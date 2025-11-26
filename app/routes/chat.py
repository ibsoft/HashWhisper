import base64
import io
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import qrcode
from flask import Blueprint, Response, current_app, flash, jsonify, render_template, request
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from ..extensions import db, limiter
from ..forms import GroupForm
from ..models import (
    Group,
    GroupMembership,
    IntegrityChain,
    MediaBlob,
    Message,
    MessageReaction,
    hash_secret,
    PresenceEvent,
    User,
)
from ..presence import get_presence_bus, sse_stream

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/")
def index():
    return render_template("auth/landing.html")


@chat_bp.route("/chat")
@login_required
def chat():
    groups = Group.query.join(GroupMembership).filter(GroupMembership.user_id == current_user.id).all()
    return render_template("chat/chat.html", groups=groups)


@chat_bp.route("/groups/create", methods=["GET", "POST"])
@login_required
def create_group():
    form = GroupForm()
    if form.validate_on_submit():
        secret = form.secret.data.strip()
        secret_hash = hash_secret(secret)
        group = Group(name=form.name.data.strip(), secret_hash=secret_hash, created_by=current_user.id)
        db.session.add(group)
        db.session.commit()
        IntegrityChain.append_event(group.id, "group_created", form.name.data.strip())
        db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
        db.session.commit()
        qr_payload = {"group": group.id, "secret": secret}
        img = qrcode.make(json.dumps(qr_payload))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_data = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        flash("Group created. Share the QR offline.", "success")
        return render_template("chat/group_created.html", group=group, qr_payload=qr_payload, qr_data=qr_data)
    return render_template("chat/create_group.html", form=form)


@chat_bp.route("/groups/join", methods=["POST"])
@login_required
def join_group():
    payload = request.get_json(silent=True) or {}
    secret = payload.get("secret", "").strip()
    group_name = payload.get("group_name", "").strip()
    if not secret or not group_name:
        return jsonify({"error": "missing"}), 400
    group = Group.query.filter_by(name=group_name).first()
    if not group:
        return jsonify({"error": "not_found"}), 404
    if hash_secret(secret) != group.secret_hash:
        return jsonify({"error": "bad_secret"}), 403
    if not GroupMembership.query.filter_by(group_id=group.id, user_id=current_user.id).first():
        db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
        IntegrityChain.append_event(group.id, "member_join", str(current_user.id))
        db.session.commit()
    return jsonify({"ok": True, "group_id": group.id})


@chat_bp.route("/api/dm/start", methods=["POST"])
@login_required
def start_dm():
    data = request.get_json(silent=True) or {}
    target_id_raw = data.get("user_id")
    secret = str(data.get("secret", "")).strip()
    try:
        target_id = int(target_id_raw)
    except (TypeError, ValueError):
        target_id = None
    if not target_id or not secret:
        return jsonify({"error": "missing"}), 400
    if target_id == current_user.id:
        return jsonify({"error": "self"}), 400
    target = User.query.get(target_id)
    if not target:
        return jsonify({"error": "not_found"}), 404
    secret_hash = hash_secret(secret)
    dm_name = f"DM:{'-'.join(sorted([current_user.username, target.username]))}"
    group = Group.query.filter_by(secret_hash=secret_hash, name=dm_name).first()
    if not group:
        group = Group(name=dm_name, secret_hash=secret_hash, created_by=current_user.id)
        db.session.add(group)
        db.session.flush()
        IntegrityChain.append_event(group.id, "dm_created", f"{current_user.id}:{target.id}")
        db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
        db.session.add(GroupMembership(user_id=target.id, group_id=group.id))
        db.session.commit()
    else:
        if not GroupMembership.query.filter_by(group_id=group.id, user_id=current_user.id).first():
            db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
        if not GroupMembership.query.filter_by(group_id=group.id, user_id=target.id).first():
            db.session.add(GroupMembership(user_id=target.id, group_id=group.id))
        db.session.commit()
    return jsonify({"group_id": group.id, "name": group.name})


@chat_bp.route("/api/users")
@login_required
@limiter.exempt
def list_users():
    group_id = request.args.get("group_id", type=int)
    if not group_id:
        return jsonify([])
    # ensure current user is in group
    if not GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first():
        return jsonify({"error": "forbidden"}), 403
    users = (
        User.query.join(GroupMembership, GroupMembership.user_id == User.id)
        .filter(GroupMembership.group_id == group_id, User.id != current_user.id)
        .all()
    )
    return jsonify([{"id": u.id, "username": u.username} for u in users])


@chat_bp.route("/api/groups/summary")
@login_required
@limiter.exempt
def groups_summary():
    results = []
    memberships = GroupMembership.query.filter_by(user_id=current_user.id).all()
    for m in memberships:
        latest_msg = (
            Message.query.filter_by(group_id=m.group_id)
            .order_by(Message.created_at.desc())
            .first()
        )
        group = Group.query.get(m.group_id)
        results.append(
            {
                "group_id": m.group_id,
                "latest": latest_msg.created_at.isoformat() if latest_msg else None,
                "name": group.name if group else "",
            }
        )
    return jsonify(results)


@chat_bp.route("/groups/<int:group_id>/delete", methods=["POST"])
@login_required
def delete_group(group_id: int):
    group = Group.query.get_or_404(group_id)
    if group.created_by != current_user.id:
        return jsonify({"error": "forbidden"}), 403

    # Delete associated messages and media securely
    messages = Message.query.filter_by(group_id=group.id).all()
    for msg in messages:
        blobs = MediaBlob.query.filter_by(message_id=msg.id).all()
        for blob in blobs:
            try:
                path = Path(blob.stored_path)
                upload_root = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
                if path.resolve().is_file() and upload_root in path.resolve().parents:
                    path.unlink()
            except OSError:
                pass
            db.session.delete(blob)
        db.session.delete(msg)

    GroupMembership.query.filter_by(group_id=group.id).delete()
    IntegrityChain.query.filter_by(group_id=group.id).delete()
    db.session.delete(group)
    db.session.commit()
    return jsonify({"ok": True})


@chat_bp.route("/api/messages", methods=["GET"])
@login_required
@limiter.exempt
def list_messages():
    group_id = request.args.get("group_id", type=int)
    before_raw = request.args.get("before")
    before_dt = None
    if before_raw:
        try:
            before_dt = datetime.fromisoformat(before_raw.replace("Z", "+00:00"))
        except ValueError:
            before_dt = None
    if not group_id:
        return jsonify([])
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    query = Message.query.filter_by(group_id=group_id)
    if before_dt:
        query = query.filter(Message.created_at < before_dt)
    messages = query.order_by(Message.created_at.desc()).limit(50).all()
    serialized = []
    for m in reversed(messages):
        reactions = MessageReaction.query.filter_by(message_id=m.id).all()
        likes = len([r for r in reactions if r.value == "like"])
        dislikes = len([r for r in reactions if r.value == "dislike"])
        like_usernames = [
            (r.user.username if r.user else str(r.user_id))
            for r in reactions
            if r.value == "like"
        ]
        dislike_usernames = [
            (r.user.username if r.user else str(r.user_id))
            for r in reactions
            if r.value == "dislike"
        ]
        serialized.append(
            {
                "id": m.id,
                "ciphertext": m.ciphertext.hex(),
                "nonce": m.nonce,
                "auth_tag": m.auth_tag,
                "meta": m.meta,
                "sender_id": m.sender_id,
                "sender_name": getattr(m.sender, "username", "user"),
                "created_at": m.created_at.replace(tzinfo=timezone.utc).isoformat(),
                "likes": likes,
                "dislikes": dislikes,
                "liked_by": like_usernames,
                "disliked_by": dislike_usernames,
            }
        )
    return jsonify(serialized)


@chat_bp.route("/api/messages", methods=["POST"])
@login_required
def post_message():
    data = request.get_json(silent=True) or {}
    group_id = data.get("group_id")
    if not group_id:
        return jsonify({"error": "missing_group"}), 400
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    ciphertext = data.get("ciphertext", "")
    nonce = data.get("nonce", "")
    auth_tag = data.get("auth_tag", "")
    meta = str(data.get("meta", "")).replace("\r", " ").replace("\n", " ")
    if not (ciphertext and nonce and auth_tag):
        return jsonify({"error": "invalid"}), 400
    try:
        blob = bytes.fromhex(ciphertext)
    except ValueError:
        return jsonify({"error": "bad_ciphertext"}), 400
    if Message.query.filter_by(group_id=group_id, sender_id=current_user.id, nonce=str(nonce)[:64]).first():
        return jsonify({"error": "replay_detected"}), 409
    message = Message(
        group_id=group_id,
        sender_id=current_user.id,
        ciphertext=blob,
        nonce=str(nonce)[:64],
        auth_tag=str(auth_tag)[:64],
        meta=meta[:255],
        expires_at=datetime.utcnow() + timedelta(days=current_app.config["MESSAGE_RETENTION_DAYS"]),
    )
    db.session.add(message)
    db.session.commit()
    bus = get_presence_bus()
    bus.publish(current_user.id, "online", typing=False, username=current_user.username, event="message", group_id=group_id, message_id=message.id, created_at=message.created_at.isoformat())
    return jsonify({
        "id": message.id,
        "created_at": message.created_at.isoformat(),
        "likes": 0,
        "dislikes": 0,
        "liked_by": [],
    })


@chat_bp.route("/api/upload", methods=["POST"])
@login_required
def upload_blob():
    group_id = request.form.get("group_id", type=int)
    nonce = request.form.get("nonce", "")
    auth_tag = request.form.get("auth_tag", "")
    raw_meta = str(request.form.get("meta", "")).replace("\r", " ").replace("\n", " ")
    if not group_id:
        return jsonify({"error": "missing_group"}), 400
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "missing_file"}), 400
    if file.mimetype not in current_app.config["ALLOWED_MIMETYPES"]:
        return jsonify({"error": "blocked_mime"}), 400
    sanitized_name = secure_filename(file.filename) or "blob"
    random_name = secrets.token_hex(16)
    base_path = Path(current_app.config["UPLOAD_FOLDER"])
    base_path.mkdir(parents=True, exist_ok=True)
    stored_path = base_path / random_name
    file.save(stored_path)
    file_size = stored_path.stat().st_size
    message = Message(
        group_id=group_id,
        sender_id=current_user.id,
        ciphertext=b"",
        nonce=str(nonce)[:64],
        auth_tag=str(auth_tag)[:64],
        meta="",
        expires_at=datetime.utcnow() + timedelta(days=current_app.config["MESSAGE_RETENTION_DAYS"]),
    )
    db.session.add(message)
    db.session.flush()
    blob = MediaBlob(
        message_id=message.id,
        stored_path=str(stored_path),
        original_name=sanitized_name,
        mime_type=file.mimetype,
        size_bytes=file_size,
    )
    db.session.add(blob)
    db.session.flush()
    try:
        meta_json = json.loads(raw_meta) if raw_meta else {}
    except ValueError:
        meta_json = {}
    # Keep meta JSON short enough for the column and always retain blob_id
    meta_json.update(
        {
            "type": "media",
            "name": (sanitized_name or "blob")[:120],
            "size": file_size,
            "mime": (file.mimetype or "application/octet-stream")[:64],
            "blob_id": blob.id,
        }
    )
    meta_str = json.dumps(meta_json)
    if len(meta_str) > 255:
        minimal = {
            "type": "media",
            "name": meta_json.get("name", "blob")[:60],
            "size": file_size,
            "mime": meta_json.get("mime", "application/octet-stream"),
            "blob_id": blob.id,
        }
        meta_json = minimal
        meta_str = json.dumps(meta_json)
    meta_json.update(
        {
            "type": "media",
            "name": sanitized_name,
            "size": stored_path.stat().st_size,
            "mime": file.mimetype,
            "blob_id": blob.id,
        }
    )
    message.meta = meta_str
    db.session.commit()
    bus = get_presence_bus()
    bus.publish(current_user.id, "online", typing=False, username=current_user.username, event="message", group_id=group_id, message_id=message.id, created_at=message.created_at.isoformat())
    return jsonify({"id": blob.id, "message_id": message.id, "meta": meta_json})


@chat_bp.route("/api/blob/<int:blob_id>")
@login_required
def download_blob(blob_id):
    blob = MediaBlob.query.get_or_404(blob_id)
    message = Message.query.get(blob.message_id)
    if not GroupMembership.query.filter_by(group_id=message.group_id, user_id=current_user.id).first():
        return jsonify({"error": "forbidden"}), 403
    file_path = Path(blob.stored_path)
    upload_root = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    if not file_path.resolve().is_file() or upload_root not in file_path.resolve().parents:
        return jsonify({"error": "invalid_path"}), 400
    return Response(
        file_path.read_bytes(),
        headers={
            "Content-Disposition": f"attachment; filename={secure_filename(blob.original_name)}",
            "Content-Type": blob.mime_type or "application/octet-stream",
        },
    )


@chat_bp.route("/api/messages/<int:message_id>/react", methods=["POST"])
@login_required
def react_message(message_id: int):
    message = Message.query.get_or_404(message_id)
    membership = GroupMembership.query.filter_by(group_id=message.group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    value = data.get("value")
    if value not in {"like", "dislike"}:
        return jsonify({"error": "invalid"}), 400
    reaction = MessageReaction.query.filter_by(message_id=message.id, user_id=current_user.id).first()
    if reaction:
        reaction.value = value
    else:
        reaction = MessageReaction(message_id=message.id, user_id=current_user.id, value=value)
        db.session.add(reaction)
    db.session.flush()
    reactions = MessageReaction.query.filter_by(message_id=message.id).all()
    likes = len([r for r in reactions if r.value == "like"])
    dislikes = len([r for r in reactions if r.value == "dislike"])
    message.likes = likes
    message.dislikes = dislikes
    db.session.commit()
    bus = get_presence_bus()
    bus.publish(
        current_user.id,
        "online",
        typing=False,
        username=current_user.username,
        event="reaction",
        group_id=message.group_id,
        message_id=message.id,
        created_at=datetime.utcnow().isoformat(),
    )
    return jsonify({
        "likes": likes,
        "dislikes": dislikes,
        "liked_by": [
            (r.user.username if r.user else str(r.user_id)) for r in reactions if r.value == "like"
        ],
        "disliked_by": [
            (r.user.username if r.user else str(r.user_id)) for r in reactions if r.value == "dislike"
        ],
    })


@chat_bp.route("/api/presence", methods=["POST"])
@login_required
def update_presence():
    data = request.get_json(silent=True) or {}
    status = data.get("status", "online")
    typing = bool(data.get("typing", False))
    bus = get_presence_bus()
    bus.publish(current_user.id, status, typing, username=current_user.username)
    PresenceEvent.touch(current_user.id, status, typing)
    return jsonify({"ok": True})


@chat_bp.route("/events/presence")
@login_required
def presence_stream():
    bus = get_presence_bus()
    return sse_stream(bus)
