"""Initial tenant-aware TrustMesh schema."""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("tenants",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False), sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("slug"))
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
    op.bulk_insert(sa.table("tenants", sa.column("id", sa.Integer()), sa.column("name", sa.String()),
                            sa.column("slug", sa.String()), sa.column("active", sa.Boolean()),
                            sa.column("created_at", sa.DateTime(timezone=True))),
                   [{"id": 1, "name": "Default Workspace", "slug": "local", "active": True, "created_at": datetime.now(timezone.utc)}])
    op.create_table("users",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False), sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="developer"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email"))
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"]); op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table("agents",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False), sa.Column("role", sa.String(60), nullable=False),
        sa.Column("permissions", sa.Text(), nullable=False), sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("token_hash"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_agent_tenant_name"))
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"]); op.create_index("ix_agents_name", "agents", ["name"])
    op.create_table("events",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=True), sa.Column("agent_name", sa.String(100), nullable=False),
        sa.Column("action", sa.String(100), nullable=False), sa.Column("resource", sa.String(300), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False), sa.Column("risk", sa.Integer(), nullable=False),
        sa.Column("reasons", sa.Text(), nullable=False), sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False))
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"]); op.create_index("ix_events_agent_name", "events", ["agent_name"])
    op.create_index("ix_events_decision", "events", ["decision"]); op.create_index("ix_events_created_at", "events", ["created_at"])
    op.create_index("ix_events_event_hash", "events", ["event_hash"])
    op.create_table("approvals",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("event_id", sa.Integer(), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("decision", sa.String(10), nullable=False), sa.Column("reviewer", sa.String(100), nullable=False),
        sa.Column("audit_event_id", sa.Integer(), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False), sa.UniqueConstraint("audit_event_id"))
    op.create_index("ix_approvals_event_id", "approvals", ["event_id"], unique=True)

def downgrade():
    op.drop_index("ix_approvals_event_id", table_name="approvals"); op.drop_table("approvals")
    for index in ("ix_events_event_hash", "ix_events_created_at", "ix_events_decision", "ix_events_agent_name", "ix_events_tenant_id"):
        op.drop_index(index, table_name="events")
    op.drop_table("events")
    for index in ("ix_agents_name", "ix_agents_tenant_id"): op.drop_index(index, table_name="agents")
    op.drop_table("agents")
    for index in ("ix_users_email", "ix_users_tenant_id"): op.drop_index(index, table_name="users")
    op.drop_table("users"); op.drop_index("ix_tenants_slug", table_name="tenants"); op.drop_table("tenants")
