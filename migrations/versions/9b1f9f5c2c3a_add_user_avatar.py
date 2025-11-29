"""add user avatar path

Revision ID: 9b1f9f5c2c3a
Revises: 645f949f3626
Create Date: 2025-11-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '9b1f9f5c2c3a'
down_revision = '645f949f3626'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    user_columns = {col['name'] for col in inspector.get_columns('users')}
    if 'avatar_path' not in user_columns:
        op.add_column('users', sa.Column('avatar_path', sa.String(length=255), nullable=True))


def downgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    user_columns = {col['name'] for col in inspector.get_columns('users')}
    if 'avatar_path' in user_columns:
        op.drop_column('users', 'avatar_path')
