"""Add correlation IDs to audit evidence."""
from alembic import op
import sqlalchemy as sa

revision = "0003_correlation"
down_revision = "0002_sessions"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("events", sa.Column("correlation_id", sa.String(length=80), nullable=True))

def downgrade():
    op.drop_column("events", "correlation_id")
