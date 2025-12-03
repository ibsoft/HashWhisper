"""Add payload_type column to one-time vault secrets.

Revision ID: vault_payload_type
Revises: vault_one_time
Create Date: 2025-12-04 12:00:00
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "vault_payload_type"
down_revision = "vault_one_time"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        ALTER TABLE one_time_secrets
          ADD COLUMN IF NOT EXISTS payload_type varchar(32) NOT NULL DEFAULT 'text';
        """
    )


def downgrade():
    op.execute(
        """
        ALTER TABLE one_time_secrets
          DROP COLUMN IF EXISTS payload_type;
        """
    )
