"""initial schema

Revision ID: 0001_initial
Revises: 
Create Date: 2024-11-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.String(length=64), nullable=False, unique=True),
        sa.Column('email', sa.String(length=120), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('totp_secret', sa.String(length=32), nullable=False),
        sa.Column('totp_confirmed', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('preferred_theme', sa.String(length=16), nullable=False, server_default='system'),
        sa.Column('language', sa.String(length=8), nullable=False, server_default='en'),
        sa.Column('notifications_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('privacy_mode', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('timezone', sa.String(length=64), nullable=False, server_default='UTC'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('last_login_at', sa.DateTime()),
        sa.Column('failed_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime()),
    )

    op.create_table(
        'chat_groups',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('secret_hash', sa.String(length=64), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        'group_memberships',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('group_id', sa.Integer(), sa.ForeignKey('chat_groups.id'), nullable=False),
        sa.Column('joined_at', sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint('user_id', 'group_id', name='uq_group_membership'),
    )

    op.create_table(
        'integrity_chain',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('group_id', sa.Integer(), sa.ForeignKey('chat_groups.id'), nullable=False),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('payload_hash', sa.String(length=64), nullable=False),
        sa.Column('prev_hash', sa.String(length=64)),
        sa.Column('chain_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        'messages',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('group_id', sa.Integer(), sa.ForeignKey('chat_groups.id'), nullable=False),
        sa.Column('sender_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('auth_tag', sa.String(length=64), nullable=False),
        sa.Column('meta', sa.String(length=255)),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime()),
    )

    op.create_index('ix_messages_created_at', 'messages', ['created_at'])
    op.create_index('ix_messages_expires_at', 'messages', ['expires_at'])

    op.create_table(
        'media_blobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('message_id', sa.Integer(), sa.ForeignKey('messages.id'), nullable=False),
        sa.Column('stored_path', sa.String(length=255), nullable=False),
        sa.Column('original_name', sa.String(length=128)),
        sa.Column('mime_type', sa.String(length=64)),
        sa.Column('size_bytes', sa.Integer()),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        'presence_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='offline'),
        sa.Column('typing', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade():
    op.drop_index('ix_messages_expires_at', table_name='messages')
    op.drop_index('ix_messages_created_at', table_name='messages')
    op.drop_table('presence_events')
    op.drop_table('media_blobs')
    op.drop_table('messages')
    op.drop_table('integrity_chain')
    op.drop_table('group_memberships')
    op.drop_table('chat_groups')
    op.drop_table('users')
