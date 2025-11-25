from datetime import datetime
from pathlib import Path

from .extensions import db
from .models import MediaBlob, Message


def purge_expired_messages():
    now = datetime.utcnow()
    expired = Message.query.filter(Message.expires_at <= now).all()
    for msg in expired:
        blobs = MediaBlob.query.filter_by(message_id=msg.id).all()
        for blob in blobs:
            try:
                path = Path(blob.stored_path)
                if path.exists():
                    path.unlink()
            except OSError:
                pass
            db.session.delete(blob)
        db.session.delete(msg)
    db.session.commit()

