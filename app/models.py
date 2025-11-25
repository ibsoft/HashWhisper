import secrets
import hashlib
from datetime import datetime, timedelta
from flask_login import UserMixin
from sqlalchemy import func
from werkzeug.security import check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .extensions import db, login_manager


ph = PasswordHasher()


def hash_secret(secret: str) -> str:
    return hashlib.blake2b(secret.encode(), digest_size=32).hexdigest()


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=False)
    totp_confirmed = db.Column(db.Boolean, default=False)
    preferred_theme = db.Column(db.String(16), default="system")
    language = db.Column(db.String(8), default="en")
    notifications_enabled = db.Column(db.Boolean, default=True)
    timezone = db.Column(db.String(64), default="UTC")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, password: str) -> None:
        self.password_hash = ph.hash(password)

    def check_password(self, password: str) -> bool:
        if self.locked_until and self.locked_until > datetime.utcnow():
            return False
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False

    def mark_failed_login(self) -> None:
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=5)

    def reset_failures(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


class Group(db.Model):
    __tablename__ = "chat_groups"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    secret_hash = db.Column(db.String(64), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    memberships = db.relationship("GroupMembership", backref="group", cascade="all,delete")


class GroupMembership(db.Model):
    __tablename__ = "group_memberships"
    __table_args__ = (db.UniqueConstraint("user_id", "group_id", name="uq_group_membership"),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("chat_groups.id"), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)


class IntegrityChain(db.Model):
    __tablename__ = "integrity_chain"
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("chat_groups.id"), nullable=False)
    event_type = db.Column(db.String(32), nullable=False)
    payload_hash = db.Column(db.String(64), nullable=False)
    prev_hash = db.Column(db.String(64))
    chain_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def append_event(group_id: int, event_type: str, payload: str) -> "IntegrityChain":
        prev = IntegrityChain.query.filter_by(group_id=group_id).order_by(IntegrityChain.id.desc()).first()
        prev_hash = prev.chain_hash if prev else None
        material = (prev_hash or "0") + event_type + payload
        chain_hash = hashlib.sha256(material.encode()).hexdigest()
        entry = IntegrityChain(
            group_id=group_id,
            event_type=event_type,
            payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
            prev_hash=prev_hash,
            chain_hash=chain_hash,
        )
        db.session.add(entry)
        return entry


class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("chat_groups.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    auth_tag = db.Column(db.String(64), nullable=False)
    meta = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, index=True)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)

    sender = db.relationship("User", backref=db.backref("messages", lazy="dynamic"))
    group = db.relationship("Group", backref=db.backref("messages", lazy="dynamic"))


class MessageReaction(db.Model):
    __tablename__ = "message_reactions"
    __table_args__ = (db.UniqueConstraint("user_id", "message_id", name="uq_message_user_reaction"),)
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("messages.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    value = db.Column(db.String(8), nullable=False)  # like or dislike
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    message = db.relationship("Message", backref=db.backref("reactions", cascade="all, delete-orphan"))
    user = db.relationship("User")


class MediaBlob(db.Model):
    __tablename__ = "media_blobs"
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("messages.id"), nullable=False)
    stored_path = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(128))
    mime_type = db.Column(db.String(64))
    size_bytes = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PresenceEvent(db.Model):
    __tablename__ = "presence_events"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    status = db.Column(db.String(16), default="offline")
    typing = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def touch(user_id: int, status: str, typing: bool = False):
        event = PresenceEvent.query.filter_by(user_id=user_id).first()
        if not event:
            event = PresenceEvent(user_id=user_id)
            db.session.add(event)
        event.status = status
        event.typing = typing
        event.updated_at = datetime.utcnow()
        db.session.commit()
        return event
