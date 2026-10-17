"""Add revocable short-lived user access sessions."""
from alembic import op
import sqlalchemy as sa

revision = "0002_sessions"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("auth_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token_id"))
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_token_id", "auth_sessions", ["token_id"], unique=True)

def downgrade():
    op.drop_index("ix_auth_sessions_token_id", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
