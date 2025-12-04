"""Increase Vault payload column lengths.

Revision ID: vault_payload_expand
Revises: vault_one_time_rebuild
Create Date: 2025-12-04 10:00:00
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "vault_payload_expand"
down_revision = "vault_one_time_rebuild"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "one_time_secrets",
        "payload_name",
        existing_type=sa.String(255),
        type_=sa.String(512),
        existing_nullable=True,
    )
    op.alter_column(
        "one_time_secrets",
        "payload_mime",
        existing_type=sa.String(64),
        type_=sa.String(128),
        existing_nullable=True,
    )


def downgrade():
    op.alter_column(
        "one_time_secrets",
        "payload_name",
        existing_type=sa.String(512),
        type_=sa.String(255),
        existing_nullable=True,
    )
    op.alter_column(
        "one_time_secrets",
        "payload_mime",
        existing_type=sa.String(128),
        type_=sa.String(64),
        existing_nullable=True,
    )
