import base64
import flask
import io
import json
import os
import secrets
import socket
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import qrcode
from flask import Blueprint, Response, current_app, flash, jsonify, render_template, request, url_for, redirect
from flask_login import current_user, login_required
from flask_babel import _, get_locale
from werkzeug.utils import secure_filename
from flask import send_from_directory
from werkzeug.exceptions import NotFound

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
    Favorite,
    ScheduledChat,
)
from ..presence import get_presence_bus, sse_stream
from flask import current_app

chat_bp = Blueprint("chat", __name__)


def purge_expired_scheduled():
    now = datetime.now()
    expired = ScheduledChat.query.filter(
        ScheduledChat.never_expires.is_(False),
        ScheduledChat.end_at <= now,
    ).all()
    if expired:
        current_app.logger.info(
            "Purging expired scheduled chats count=%s ids=%s now=%s",
            len(expired),
            [(sc.id, sc.group_id, sc.end_at) for sc in expired],
            now,
        )
    for sc in expired:
        gid = sc.group_id
        msg_ids = [m.id for m in Message.query.filter_by(group_id=gid).all()]
        if msg_ids:
            current_app.logger.info("Deleting messages for group %s ids=%s", gid, msg_ids)
            MediaBlob.query.filter(MediaBlob.message_id.in_(msg_ids)).delete(synchronize_session=False)
            MessageReaction.query.filter(MessageReaction.message_id.in_(msg_ids)).delete(synchronize_session=False)
            Message.query.filter(Message.id.in_(msg_ids)).delete(synchronize_session=False)
        GroupMembership.query.filter_by(group_id=gid).delete(synchronize_session=False)
        IntegrityChain.query.filter_by(group_id=gid).delete(synchronize_session=False)
        ScheduledChat.query.filter_by(id=sc.id).delete(synchronize_session=False)
        Group.query.filter_by(id=gid).delete(synchronize_session=False)
    if expired:
        db.session.commit()
        current_app.logger.info("Finished purge for expired scheduled chats.")


def delete_group_completely(group_id: int):
    current_app.logger.info("Deleting group completely group_id=%s", group_id)
    messages = Message.query.filter_by(group_id=group_id).all()
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
    GroupMembership.query.filter_by(group_id=group_id).delete(synchronize_session=False)
    IntegrityChain.query.filter_by(group_id=group_id).delete(synchronize_session=False)
    ScheduledChat.query.filter_by(group_id=group_id).delete(synchronize_session=False)
    Group.query.filter_by(id=group_id).delete(synchronize_session=False)
    current_app.logger.info("Group %s deleted.", group_id)


def ensure_not_expired(group_id: int):
    sched = ScheduledChat.query.filter_by(group_id=group_id).first()
    now = datetime.now()
    if sched and not sched.never_expires and sched.end_at and sched.end_at <= now:
        current_app.logger.info("Group %s expired at %s, deleting via ensure_not_expired.", group_id, sched.end_at)
        delete_group_completely(group_id)
        db.session.commit()
        return False
    return True


@chat_bp.route("/")
def index():
    return render_template("auth/landing.html")


@chat_bp.route("/help")
@login_required
def help_page():
    current_locale = str(get_locale())
    return render_template("help.html", locale=current_locale)


@chat_bp.route("/avatars/<path:filename>")
def avatar_file(filename: str):
    upload_dir = current_app.config.get("AVATAR_UPLOAD_FOLDER") or os.path.join("app", "storage", "avatars")
    full_dir = os.path.abspath(upload_dir)
    target = os.path.abspath(os.path.join(full_dir, filename))
    if not target.startswith(full_dir) or not os.path.isfile(target):
        raise NotFound()
    return send_from_directory(full_dir, os.path.basename(filename))


@chat_bp.route("/sw.js")
def service_worker():
    """Serve the PWA service worker from the app root for proper scope."""
    response = current_app.send_static_file("js/sw.js")
    response.headers["Content-Type"] = "application/javascript"
    response.headers["Cache-Control"] = "no-cache"
    return response


@chat_bp.route("/chat")
@login_required
def chat():
    purge_expired_scheduled()
    groups = Group.query.join(GroupMembership).filter(GroupMembership.user_id == current_user.id).all()
    default_avatar = flask.url_for("static", filename="img/user.png")
    return render_template("chat/chat.html", groups=groups, default_avatar=default_avatar)


@chat_bp.route("/groups/create", methods=["GET", "POST"])
@login_required
def create_group():
    form = GroupForm()
    if form.validate_on_submit():
        secret = form.secret.data.strip()
        secret_hash = hash_secret(secret)
        name = form.name.data.strip()
        # Enforce unique group name per app
        existing = Group.query.filter_by(name=name).first()
        if existing:
            msg = _("A group with this name already exists.")
            flash(msg, "error")
            return render_template("chat/create_group.html", form=form, duplicate_error=msg), 409
        group = Group(name=name, secret_hash=secret_hash, created_by=current_user.id)
        db.session.add(group)
        db.session.commit()
        IntegrityChain.append_event(group.id, "group_created", name)
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

@chat_bp.route("/api/groups/verify", methods=["POST"])
@login_required
def verify_group_secret():
    data = request.get_json(silent=True) or {}
    group_id = data.get("group_id")
    secret = str(data.get("secret", "")).strip()
    if not group_id or not secret:
        return jsonify({"error": "missing"}), 400
    group = Group.query.get(group_id)
    if not group:
        return jsonify({"error": "not_found"}), 404
    # Accept either the raw secret or the pre-hashed value to allow hash-only sharing.
    provided_hash = secret if secret == group.secret_hash else hash_secret(secret)
    if provided_hash != group.secret_hash:
        return jsonify({"error": "bad_secret"}), 403
    return jsonify({"ok": True})


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
    group = Group.query.filter_by(name=dm_name).first()
    if group:
        # DM already exists; enforce same secret
        if group.secret_hash != secret_hash:
            return jsonify({"error": "dm_exists_with_different_secret"}), 409
        existed = True
        if not GroupMembership.query.filter_by(group_id=group.id, user_id=current_user.id).first():
            db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
        if not GroupMembership.query.filter_by(group_id=group.id, user_id=target.id).first():
            db.session.add(GroupMembership(user_id=target.id, group_id=group.id))
        db.session.commit()
        return jsonify({"group_id": group.id, "name": group.name, "existing": True})
    else:
        group = Group(name=dm_name, secret_hash=secret_hash, created_by=current_user.id)
        db.session.add(group)
        db.session.flush()
        IntegrityChain.append_event(group.id, "dm_created", f"{current_user.id}:{target.id}")
        db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
        db.session.add(GroupMembership(user_id=target.id, group_id=group.id))
        db.session.commit()
        return jsonify({"group_id": group.id, "name": group.name, "existing": False})


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
    def avatar_url(u: User):
        if not u.avatar_path:
            return None
        return url_for("chat.avatar_file", filename=u.avatar_path, _external=False)

    return jsonify([{"id": u.id, "username": u.username, "avatar_url": avatar_url(u)} for u in users])


@chat_bp.route("/api/favorites", methods=["GET", "POST"])
@login_required
@limiter.exempt
def favorites():
    if request.method == "GET":
        favs = (
            Favorite.query.filter_by(user_id=current_user.id)
            .join(User, Favorite.favorite_user_id == User.id)
            .with_entities(User.id, User.username, User.avatar_path)
            .all()
        )
        def avatar_url(u_avatar):
            return url_for("chat.avatar_file", filename=u_avatar, _external=False) if u_avatar else None
        return jsonify(
            [
                {
                    "id": row.id,
                    "username": row.username,
                    "avatar_url": avatar_url(row.avatar_path),
                }
                for row in favs
            ]
        )
    data = request.get_json(silent=True) or {}
    target_id = data.get("target_id")
    action = (data.get("action") or "").lower()
    if not target_id or action not in {"add", "remove"}:
        return jsonify({"error": "invalid"}), 400
    if target_id == current_user.id:
        return jsonify({"error": "self"}), 400
    target = User.query.get(target_id)
    if not target:
        return jsonify({"error": "not_found"}), 404
    if action == "add":
        existing = Favorite.query.filter_by(user_id=current_user.id, favorite_user_id=target_id).first()
        if not existing:
            db.session.add(Favorite(user_id=current_user.id, favorite_user_id=target_id))
            db.session.commit()
        return jsonify({"ok": True})
    fav = Favorite.query.filter_by(user_id=current_user.id, favorite_user_id=target_id).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
    return jsonify({"ok": True})


@chat_bp.route("/api/scheduled-chats", methods=["GET", "POST", "PUT", "DELETE"])
@login_required
@limiter.exempt
def scheduled_chats():
    purge_expired_scheduled()
    if request.method == "GET":
        current_app.logger.info("Scheduled list for user %s", current_user.id)
        # Return scheduled chats where current user is host or member of the group.
        memberships = GroupMembership.query.filter_by(user_id=current_user.id).with_entities(GroupMembership.group_id)
        rows = (
            ScheduledChat.query.join(Group, ScheduledChat.group_id == Group.id)
            .filter(ScheduledChat.group_id.in_(memberships))
            .order_by(ScheduledChat.start_at.asc())
            .all()
        )
        result = []
        for sc in rows:
            share_url = url_for("chat.chat", _external=True) + f"?scheduled={sc.share_token}"
            result.append(
                {
                    "id": sc.id,
                    "name": sc.name,
                    "group_id": sc.group_id,
                    "start_at": sc.start_at.isoformat(),
                    "end_at": sc.end_at.isoformat(),
                    "host_id": sc.host_id,
                    "active": sc.is_active,
                    "public": sc.is_public,
                    "never_expires": sc.never_expires,
                    "expired": sc.is_expired,
                    "share_url": share_url,
                    "secret_hash": sc.secret_hash,
                }
            )
        return jsonify(result)
    if request.method == "PUT":
        data = request.get_json(silent=True) or {}
        sched_id = data.get("id")
        if not sched_id:
            return jsonify({"error": "missing_id"}), 400
        sched = ScheduledChat.query.get(sched_id)
        if not sched or sched.host_id != current_user.id:
            return jsonify({"error": "forbidden"}), 403
        name = (data.get("name") or sched.name).strip()
        start_at_raw = data.get("start_at") or sched.start_at.isoformat()
        end_at_raw = data.get("end_at") or sched.end_at.isoformat()
        is_public = False
        never_expires = bool(data.get("never_expires", sched.never_expires))
        try:
            start_at = datetime.fromisoformat(start_at_raw)
            end_at = datetime.fromisoformat(end_at_raw)
        except Exception:
            return jsonify({"error": "invalid_time"}), 400
        if end_at <= start_at and not never_expires:
            return jsonify({"error": "bad_range"}), 400
        sched.name = name[:128]
        sched.start_at = start_at
        sched.end_at = end_at
        sched.is_public = is_public
        sched.never_expires = never_expires
        db.session.commit()
        return jsonify({"ok": True})
    if request.method == "DELETE":
        data = request.get_json(silent=True) or {}
        sched_id = data.get("id")
        if not sched_id:
            return jsonify({"error": "missing_id"}), 400
        sched = ScheduledChat.query.get(sched_id)
        if not sched or sched.host_id != current_user.id:
            return jsonify({"error": "forbidden"}), 403
        delete_group_completely(sched.group_id)
        db.session.commit()
        return jsonify({"ok": True})
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    start_at_raw = data.get("start_at")
    end_at_raw = data.get("end_at")
    member_ids = data.get("member_ids") or []
    is_public = False
    never_expires = bool(data.get("never_expires"))
    if not name or not start_at_raw or not end_at_raw:
        return jsonify({"error": "missing"}), 400
    try:
        start_at = datetime.fromisoformat(start_at_raw)
        end_at = datetime.fromisoformat(end_at_raw)
    except Exception:
        return jsonify({"error": "invalid_time"}), 400
    if end_at <= start_at:
        return jsonify({"error": "bad_range"}), 400
    # Generate secret and group
    secret = secrets.token_urlsafe(16)
    secret_hash = hash_secret(secret)
    group = Group(name=name[:64], secret_hash=secret_hash, created_by=current_user.id)
    db.session.add(group)
    db.session.flush()
    db.session.add(GroupMembership(user_id=current_user.id, group_id=group.id))
    valid_members = (
        User.query.filter(User.id.in_(member_ids)).with_entities(User.id).all() if member_ids else []
    )
    for mid, in valid_members:
        if mid == current_user.id:
            continue
        # avoid duplicate
        if not GroupMembership.query.filter_by(user_id=mid, group_id=group.id).first():
            db.session.add(GroupMembership(user_id=mid, group_id=group.id))
    sched = ScheduledChat(
        host_id=current_user.id,
        group_id=group.id,
        name=name[:128],
        secret_hash=secret_hash,
        start_at=start_at,
        end_at=end_at,
        share_token=secrets.token_urlsafe(16),
        is_public=is_public,
        never_expires=never_expires,
    )
    db.session.add(sched)
    IntegrityChain.append_event(group.id, "scheduled_chat", name)
    db.session.commit()
    join_hint = {
        "group_id": group.id,
        "name": group.name,
        "start_at": start_at.isoformat(),
        "end_at": end_at.isoformat(),
        "share_url": url_for("chat.chat", _external=True) + f"?scheduled={sched.share_token}",
        "secret_hash": secret_hash,
    }
    return jsonify({"ok": True, "scheduled_id": sched.id, "share": join_hint})


@chat_bp.route("/api/scheduled-chats/lookup")
@login_required
@limiter.exempt
def scheduled_lookup():
    purge_expired_scheduled()
    token = request.args.get("token") or ""
    if not token:
        return jsonify({"error": "missing"}), 400
    sched = ScheduledChat.query.filter_by(share_token=token).first()
    if not sched:
        return jsonify({"error": "not_found"}), 404
    if not sched.never_expires and sched.end_at and sched.end_at < datetime.utcnow():
        return jsonify({"error": "expired"}), 410
    # Only allow host or invited members
    if not GroupMembership.query.filter_by(group_id=sched.group_id, user_id=current_user.id).first():
        return jsonify({"error": "forbidden"}), 403
    current_app.logger.info("Scheduled lookup user=%s token=%s group=%s end_at=%s", current_user.id, token, sched.group_id, sched.end_at)
    return jsonify(
        {
            "group_id": sched.group_id,
            "name": sched.name,
            "start_at": sched.start_at.isoformat(),
            "end_at": sched.end_at.isoformat(),
        }
    )


@chat_bp.route("/api/scheduled-chats/purge", methods=["POST"])
@login_required
@limiter.exempt
def purge_specific_scheduled():
    data = request.get_json(silent=True) or {}
    group_id = data.get("group_id")
    if not group_id:
        return jsonify({"error": "missing_group"}), 400
    sched = ScheduledChat.query.filter_by(group_id=group_id).first()
    if not sched:
        current_app.logger.info("Purge requested for group %s but no scheduled chat found", group_id)
        return jsonify({"ok": True, "deleted": False})
    if sched.never_expires or not sched.end_at:
        current_app.logger.info("Purge requested for group %s but never_expires=%s end_at=%s", group_id, sched.never_expires, sched.end_at)
        return jsonify({"ok": True, "deleted": False})
    now = datetime.now()
    if sched.end_at > now:
        current_app.logger.info("Purge requested for group %s but end_at in future %s now=%s", group_id, sched.end_at, now)
        return jsonify({"ok": True, "deleted": False})
    delete_group_completely(group_id)
    db.session.commit()
    current_app.logger.info("Purged expired scheduled chat via API group_id=%s", group_id)
    return jsonify({"ok": True, "deleted": True})

@chat_bp.route("/api/groups/summary")
@login_required
@limiter.exempt
def groups_summary():
    current_app.logger.info("Building groups summary for user %s", current_user.id)
    purge_expired_scheduled()
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
                "created_by": group.created_by if group else None,
            }
        )
    return jsonify(results)


@chat_bp.route("/groups/<int:group_id>/delete", methods=["POST"])
@login_required
def delete_group(group_id: int):
    group = Group.query.get_or_404(group_id)
    if group.created_by != current_user.id:
        return jsonify({"error": "forbidden"}), 403

    delete_group_completely(group.id)
    db.session.commit()
    return jsonify({"ok": True})


@chat_bp.route("/api/messages", methods=["GET"])
@login_required
@limiter.exempt
def list_messages():
    purge_expired_scheduled()
    group_id = request.args.get("group_id", type=int)
    current_app.logger.info("List messages user=%s group_id=%s", current_user.id, group_id)
    before_raw = request.args.get("before")
    before_dt = None
    if before_raw:
        try:
            before_dt = datetime.fromisoformat(before_raw.replace("Z", "+00:00"))
        except ValueError:
            before_dt = None
    if not group_id:
        return jsonify([])
    if not ensure_not_expired(group_id):
        current_app.logger.info("Group %s expired during message fetch", group_id)
        return jsonify({"error": "expired"}), 410
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


@chat_bp.route("/api/messages/count")
@login_required
@limiter.exempt
def message_count():
    purge_expired_scheduled()
    group_id = request.args.get("group_id", type=int)
    if not group_id:
        return jsonify({"error": "missing_group"}), 400
    if not ensure_not_expired(group_id):
        return jsonify({"error": "expired"}), 410
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    total = Message.query.filter_by(group_id=group_id).count()
    return jsonify({"count": total})


@chat_bp.route("/api/messages/latest")
@login_required
@limiter.exempt
def latest_message():
    purge_expired_scheduled()
    group_id = request.args.get("group_id", type=int)
    after_raw = request.args.get("after")
    after_dt = None
    if after_raw:
        try:
            after_dt = datetime.fromisoformat(after_raw.replace("Z", "+00:00"))
        except ValueError:
            after_dt = None
    if not group_id:
        return jsonify({})
    if not ensure_not_expired(group_id):
        current_app.logger.info("Group %s expired during latest fetch", group_id)
        return jsonify({"error": "expired"}), 410
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    query = Message.query.filter_by(group_id=group_id)
    if after_dt:
        query = query.filter(Message.created_at > after_dt)
    msg = query.order_by(Message.created_at.desc()).first()
    if not msg:
        return jsonify({})
    reactions = MessageReaction.query.filter_by(message_id=msg.id).all()
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
    return jsonify(
        {
            "id": msg.id,
            "ciphertext": msg.ciphertext.hex(),
            "nonce": msg.nonce,
            "auth_tag": msg.auth_tag,
            "meta": msg.meta,
            "sender_id": msg.sender_id,
            "sender_name": getattr(msg.sender, "username", "user"),
            "created_at": msg.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "likes": likes,
            "dislikes": dislikes,
            "liked_by": like_usernames,
            "disliked_by": dislike_usernames,
        }
    )


@chat_bp.route("/api/messages", methods=["POST"])
@login_required
def post_message():
    data = request.get_json(silent=True) or {}
    group_id = data.get("group_id")
    current_app.logger.info("Post message user=%s group_id=%s", current_user.id, group_id)
    if not group_id:
        return jsonify({"error": "missing_group"}), 400
    if not ensure_not_expired(group_id):
        return jsonify({"error": "expired"}), 410
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
    current_app.logger.info("Upload blob user=%s group_id=%s", current_user.id, group_id)
    nonce = request.form.get("nonce", "")
    auth_tag = request.form.get("auth_tag", "")
    raw_meta = str(request.form.get("meta", "")).replace("\r", " ").replace("\n", " ")
    if not group_id:
        return jsonify({"error": "missing_group"}), 400
    if not ensure_not_expired(group_id):
        current_app.logger.info("Group %s expired during upload", group_id)
        return jsonify({"error": "expired"}), 410
    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "forbidden"}), 403
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "missing_file"}), 400
    if file.mimetype not in current_app.config["ALLOWED_MIMETYPES"]:
        return jsonify({"error": "blocked_mime", "reason": "Unsupported file type"}), 400
    display_name = (file.filename or "blob").strip()
    # truncate display name to fit VARCHAR(64) while preserving extension if present
    base, ext = os.path.splitext(display_name)
    max_len = 60  # leave room for multibyte chars and db limit
    if len(ext) > max_len - 1:
        ext = ext[: max_len // 2]
    trimmed_base = base[: max_len - len(ext)]
    display_name = f"{trimmed_base}{ext}" if ext else trimmed_base
    mime_type = (file.mimetype or "application/octet-stream")[:60]
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
        original_name=display_name,
        mime_type=mime_type,
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
            "name": (display_name or "blob")[:120],
            "size": file_size,
            "mime": mime_type,
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
            "name": display_name,
            "size": stored_path.stat().st_size,
            "mime": mime_type,
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
    file_size = file_path.stat().st_size
    return Response(
        file_path.read_bytes(),
        headers={
            "Content-Disposition": f"attachment; filename={secure_filename(blob.original_name)}",
            "Content-Type": blob.mime_type or "application/octet-stream",
            "Content-Length": str(file_size),
            "Cache-Control": "private, max-age=0, no-store",
            "Pragma": "no-cache",
            "Expires": "0",
            "Accept-Ranges": "none",
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
        likes=likes,
        dislikes=dislikes,
        liked_by=[
            (r.user.username if r.user else str(r.user_id)) for r in reactions if r.value == "like"
        ],
        disliked_by=[
            (r.user.username if r.user else str(r.user_id)) for r in reactions if r.value == "dislike"
        ],
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


def _delete_message_core(message_id: int):
    cfg = current_app.config
    if not cfg.get("ALLOW_MESSAGE_DELETE", False):
        return jsonify({"error": "disabled", "message": "Message deletion is disabled"}), 403
    message = Message.query.get_or_404(message_id)
    membership = GroupMembership.query.filter_by(group_id=message.group_id, user_id=current_user.id).first()
    group = Group.query.get(message.group_id)
    is_group_owner = group and group.created_by == current_user.id
    if not membership:
        return jsonify({"error": "forbidden", "message": "You are not a member of this group"}), 403
    if not (message.sender_id == current_user.id or is_group_owner):
        return jsonify({"error": "forbidden", "message": "Only the sender or group owner can delete this message"}), 403
    upload_root = Path(cfg["UPLOAD_FOLDER"]).resolve()
    blobs = MediaBlob.query.filter_by(message_id=message.id).all()
    for blob in blobs:
        try:
            path = Path(blob.stored_path)
            if path.resolve().is_file() and upload_root in path.resolve().parents:
                path.unlink()
        except OSError:
            pass
        db.session.delete(blob)
    MessageReaction.query.filter_by(message_id=message.id).delete()
    group_id = message.group_id
    db.session.delete(message)
    db.session.commit()
    bus = get_presence_bus()
    bus.publish(
        current_user.id,
        "online",
        typing=False,
        username=current_user.username,
        event="delete",
        group_id=group_id,
        message_id=message_id,
        created_at=datetime.utcnow().isoformat(),
    )
    return jsonify({"ok": True, "id": message_id, "group_id": group_id})


@chat_bp.route("/api/messages/<int:message_id>", methods=["DELETE"])
@login_required
def delete_message(message_id: int):
    return _delete_message_core(message_id)


@chat_bp.route("/api/messages/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message_via_post(message_id: int):
    # Some environments may block DELETE; provide a POST fallback.
    return _delete_message_core(message_id)


@chat_bp.route("/api/ai/ask", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config.get("AI_RATELIMIT", "5 per minute"))
def ask_ai():
    cfg = current_app.config
    if not cfg.get("AI_ENABLED"):
        return jsonify({"error": "disabled", "meta": {"enabled": False}}), 403
    api_key = cfg.get("AI_API_KEY")
    model = cfg.get("AI_MODEL", "gpt-4o-mini")
    system_prompt = cfg.get("AI_SYSTEM_PROMPT", "")
    timeout = int(cfg.get("AI_TIMEOUT", 20))
    if not api_key:
        return jsonify({"error": "missing_key", "meta": {"enabled": True, "has_key": False}}), 503
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "missing_question"}), 400

    try:
        payload = json.dumps(
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question},
                ],
                "temperature": 0.4,
            }
        ).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            parsed = json.loads(raw)
            answer = (
                parsed.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )
            return jsonify({"answer": answer or "I could not find an answer right now."})
    except urllib.error.HTTPError as err:
        status = getattr(err, "code", 502) or 502
        try:
            body = err.read().decode()
        except Exception:
            body = ""
        detail = body or str(err)
        return jsonify({"error": "upstream_error", "detail": detail, "meta": {"enabled": True, "has_key": True}}), status
    except (urllib.error.URLError, socket.timeout) as err:
        return jsonify({"error": "timeout", "detail": str(err), "meta": {"enabled": True, "has_key": True}}), 504
    except Exception as err:
        return jsonify({"error": "unknown", "detail": str(err), "meta": {"enabled": True, "has_key": True}}), 500


@chat_bp.route("/api/ai/status", methods=["GET"])
@login_required
def ai_status():
    cfg = current_app.config
    return jsonify(
        {
            "enabled": bool(cfg.get("AI_ENABLED")),
            "has_key": bool(cfg.get("AI_API_KEY")),
            "model": cfg.get("AI_MODEL"),
        }
    )


@chat_bp.route("/api/presence", methods=["POST"])
@login_required
def update_presence():
    data = request.get_json(silent=True) or {}
    status = data.get("status", "online")
    typing = bool(data.get("typing", False))
    group_id_raw = data.get("group_id")
    try:
        group_id = int(group_id_raw) if group_id_raw is not None else None
    except (TypeError, ValueError):
        group_id = None
    bus = get_presence_bus()
    bus.publish(current_user.id, status, typing, username=current_user.username, group_id=group_id)
    PresenceEvent.touch(current_user.id, status, typing)
    return jsonify({"ok": True})


@chat_bp.route("/events/presence")
@login_required
def presence_stream():
    bus = get_presence_bus()
    return sse_stream(bus)
