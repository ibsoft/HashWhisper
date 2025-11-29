"""Add scheduled chat share token/public flags with backfill.

Revision ID: fix_sched_share_token
Revises: da8f0877b69f
Create Date: 2025-11-29 16:10:00
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "fix_sched_share_token"
down_revision = "da8f0877b69f"
branch_labels = None
depends_on = None


def upgrade():
    # Use conditional DDL to avoid duplicate column errors if previous migration partially applied.
    op.execute(
        """
        ALTER TABLE scheduled_chats
          ADD COLUMN IF NOT EXISTS share_token varchar(64),
          ADD COLUMN IF NOT EXISTS is_public boolean DEFAULT false,
          ADD COLUMN IF NOT EXISTS never_expires boolean DEFAULT false;
        """
    )
    # Backfill share_token for existing rows.
    op.execute(
        """
        UPDATE scheduled_chats
        SET share_token = COALESCE(share_token, md5(random()::text || clock_timestamp()::text));
        """
    )
    # Enforce NOT NULL and uniqueness (use IF NOT EXISTS to avoid duplicate index).
    op.execute("ALTER TABLE scheduled_chats ALTER COLUMN share_token SET NOT NULL;")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_scheduled_chats_share_token ON scheduled_chats (share_token);"
    )


def downgrade():
    op.drop_index(op.f("ix_scheduled_chats_share_token"), table_name="scheduled_chats")
    op.drop_column("scheduled_chats", "never_expires")
    op.drop_column("scheduled_chats", "is_public")
    op.drop_column("scheduled_chats", "share_token")
