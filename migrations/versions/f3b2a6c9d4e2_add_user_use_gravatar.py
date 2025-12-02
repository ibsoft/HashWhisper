"""Add user gravatar preference.

Revision ID: f3b2a6c9d4e2
Revises: da8f0877b69f
Create Date: 2025-12-01 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "f3b2a6c9d4e2"
down_revision = "da8f0877b69f"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column("use_gravatar", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )


def downgrade():
    op.drop_column("users", "use_gravatar")
