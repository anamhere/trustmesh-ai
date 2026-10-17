# Deploy TrustMesh with Render

`render.yaml` defines a public web service, private PostgreSQL database, and private Redis-compatible Key Value service. The web service runs migrations before startup, creates the first workspace administrator from deployment secrets, and exposes `/readyz` for health checks.

## Portfolio/demo deployment

1. Put this project in a GitHub repository. Do not commit `.env`, database files, credentials, or `.venv`.
2. In Render, create a **New Blueprint Instance** and connect that repository. Render detects `render.yaml` at the repository root.
3. When prompted for `TRUSTMESH_BOOTSTRAP_EMAIL` and `TRUSTMESH_BOOTSTRAP_PASSWORD`, provide the account you will use to sign in. Use a unique password of at least 12 characters.
4. Review the Blueprint's resources and costs, then apply it. Wait for the web service health check to pass, open its `onrender.com` URL, and sign in with the bootstrap account.
5. Keep the generated `TRUSTMESH_TOKEN_SECRET` and `TRUSTMESH_DATA_KEY` stable. Changing the data key without a re-encryption migration makes encrypted gateway data unreadable.

The Blueprint uses free plans to avoid opting into paid services. Free web instances can sleep, and free data services have platform-specific storage, capacity, and retention limits. Treat this deployment as a portfolio demo with fictional data only. Before a real pilot, review current Render plan limits and costs, choose durable paid database/cache plans, configure backups and restore testing, and arrange security review and monitoring.

## Launch locally with Docker Compose

Docker Desktop must be installed and running. Copy `.env.example` to `.env`, replace all local example secrets, then run:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

The Compose stack starts PostgreSQL, Redis, and the API. The web port is bound to localhost by default. `docker compose down` stops the stack; `docker compose down -v` also removes its database/cache volumes.

## Current deployment boundary

This deployment hosts the existing engineering MVP. Tool calls still use the fixed fictional sandbox registry; policy signals are deterministic heuristics. It does not provide an external LLM/ML detection system, production tool adapters, SSO/MFA, signed off-host audit anchoring, or a security certification. Do not connect customer systems or process real sensitive data until those gaps are addressed and the service receives an independent security review.
