"""Add persisted execution outcomes and approval consumption reference."""
from alembic import op
import sqlalchemy as sa

revision = "0005_exec_audit"
down_revision = "0004_gateway"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "action_outcomes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_id", sa.Integer(), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("audit_event_id", sa.Integer(), sa.ForeignKey("events.id"), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_action_outcomes_event_id", "action_outcomes", ["event_id"], unique=True)
    with op.batch_alter_table("approvals") as batch:
        batch.add_column(sa.Column("consumed_event_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_approvals_consumed_event_id_events", "events", ["consumed_event_id"], ["id"])

def downgrade():
    with op.batch_alter_table("approvals") as batch:
        batch.drop_constraint("fk_approvals_consumed_event_id_events", type_="foreignkey")
        batch.drop_column("consumed_event_id")
    op.drop_index("ix_action_outcomes_event_id", table_name="action_outcomes")
    op.drop_table("action_outcomes")
