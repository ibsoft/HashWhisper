"""Generic single-database configuration.

Revision ID: 645f949f3626
Revises: 0001_initial
Create Date: 2025-11-25 14:30:20.333530

"""
from alembic import op
import sqlalchemy as sa


revision = '645f949f3626'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    user_columns = {col['name'] for col in inspector.get_columns('users')}
    if 'timezone' not in user_columns:
        op.add_column('users', sa.Column('timezone', sa.String(length=64), nullable=True))

    message_columns = {col['name'] for col in inspector.get_columns('messages')}
    if 'likes' not in message_columns:
        op.add_column('messages', sa.Column('likes', sa.Integer(), nullable=False, server_default='0'))
    if 'dislikes' not in message_columns:
        op.add_column('messages', sa.Column('dislikes', sa.Integer(), nullable=False, server_default='0'))

    if 'message_reactions' not in inspector.get_table_names():
        op.create_table(
            'message_reactions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('message_id', sa.Integer(), sa.ForeignKey('messages.id'), nullable=False),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('value', sa.String(length=8), nullable=False),
            sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
            sa.UniqueConstraint('user_id', 'message_id', name='uq_message_user_reaction'),
        )


def downgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if 'message_reactions' in inspector.get_table_names():
        op.drop_table('message_reactions')

    message_columns = {col['name'] for col in inspector.get_columns('messages')}
    if 'dislikes' in message_columns:
        op.drop_column('messages', 'dislikes')
    if 'likes' in message_columns:
        op.drop_column('messages', 'likes')

    user_columns = {col['name'] for col in inspector.get_columns('users')}
    if 'timezone' in user_columns:
        op.drop_column('users', 'timezone')
