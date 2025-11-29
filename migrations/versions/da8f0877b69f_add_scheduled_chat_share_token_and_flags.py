"""Add scheduled chat share token and flags.

Revision ID: da8f0877b69f
Revises: 9b1f9f5c2c3a
Create Date: 2025-11-29 15:54:17.464733
"""
from alembic import op
import sqlalchemy as sa

revision = "da8f0877b69f"
down_revision = "9b1f9f5c2c3a"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scheduled_chats", sa.Column("share_token", sa.String(length=64), nullable=True))
    op.add_column("scheduled_chats", sa.Column("is_public", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("scheduled_chats", sa.Column("never_expires", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.execute(
        """
        UPDATE scheduled_chats
        SET share_token = md5(random()::text || clock_timestamp()::text)
        WHERE share_token IS NULL;
        """
    )
    op.alter_column("scheduled_chats", "share_token", nullable=False)
    op.create_index(op.f("ix_scheduled_chats_share_token"), "scheduled_chats", ["share_token"], unique=True)


def downgrade():
    op.drop_index(op.f("ix_scheduled_chats_share_token"), table_name="scheduled_chats")
    op.drop_column("scheduled_chats", "never_expires")
    op.drop_column("scheduled_chats", "is_public")
    op.drop_column("scheduled_chats", "share_token")
