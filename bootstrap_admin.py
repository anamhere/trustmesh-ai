"""Create an initial workspace administrator using environment-provided credentials."""
import os
from sqlalchemy import select
from app import Session, Tenant, User, password_digest

email = os.getenv("TRUSTMESH_BOOTSTRAP_EMAIL", "").strip().lower()
password = os.getenv("TRUSTMESH_BOOTSTRAP_PASSWORD", "")
if not email and not password:
    if os.getenv("TRUSTMESH_ENV", "dev").lower() == "production":
        raise SystemExit("Production requires TRUSTMESH_BOOTSTRAP_EMAIL and TRUSTMESH_BOOTSTRAP_PASSWORD on first setup")
    raise SystemExit(0)
if not email or len(password) < 12:
    raise SystemExit("Provide bootstrap email and a password of at least 12 characters")
with Session() as db:
    tenant = db.scalar(select(Tenant).where(Tenant.slug == "local"))
    if not tenant: raise SystemExit("Default workspace missing; run Alembic migrations first")
    if db.scalar(select(User).where(User.email == email)):
        print("Bootstrap administrator already exists; no changes made")
    else:
        db.add(User(tenant_id=tenant.id, email=email, password_hash=password_digest(password), role="admin")); db.commit()
        print("Bootstrap administrator created")
