"""Persist server-executed sandbox gateway requests."""
from alembic import op
import sqlalchemy as sa

revision = "0004_gateway"
down_revision = "0003_correlation"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "gateway_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("idempotency_key", sa.String(length=100), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("tool_name", sa.String(length=60), nullable=False),
        sa.Column("arguments", sa.Text(), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource", sa.String(length=300), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("agent_id", "idempotency_key", name="uq_gateway_agent_idempotency"),
    )
    op.create_index("ix_gateway_requests_tenant_id", "gateway_requests", ["tenant_id"])
    op.create_index("ix_gateway_requests_agent_id", "gateway_requests", ["agent_id"])
    op.create_index("ix_gateway_requests_event_id", "gateway_requests", ["event_id"])
    op.create_index("ix_gateway_requests_state", "gateway_requests", ["state"])

def downgrade():
    op.drop_table("gateway_requests")
