"""Create one-time vault secrets table.

Revision ID: vault_one_time
Revises: fix_sched_share_token
Create Date: 2025-12-03 18:00:00
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "vault_one_time"
down_revision = "fix_sched_share_token"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "one_time_secrets",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("slug", sa.String(32), nullable=False),
        sa.Column("title", sa.String(128)),
        sa.Column("ciphertext", sa.Text, nullable=False),
        sa.Column("nonce", sa.String(32), nullable=False),
        sa.Column("auth_tag", sa.String(32), nullable=False),
        sa.Column("burn_after_read", sa.Boolean, nullable=False),
        sa.Column("max_views", sa.Integer, nullable=False),
        sa.Column("view_count", sa.Integer, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("burned", sa.Boolean, nullable=False),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index(op.f("ix_one_time_secrets_slug"), "one_time_secrets", ["slug"], unique=True)
    op.create_index(op.f("ix_one_time_secrets_expires_at"), "one_time_secrets", ["expires_at"])
    op.create_index(op.f("ix_one_time_secrets_burned"), "one_time_secrets", ["burned"])


def downgrade():
    op.drop_index(op.f("ix_one_time_secrets_burned"), table_name="one_time_secrets")
    op.drop_index(op.f("ix_one_time_secrets_expires_at"), table_name="one_time_secrets")
    op.drop_index(op.f("ix_one_time_secrets_slug"), table_name="one_time_secrets")
    op.drop_table("one_time_secrets")
