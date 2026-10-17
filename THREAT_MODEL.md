# TrustMesh threat model

## Objective and scope

TrustMesh is an engineering MVP for a controlled pilot and placement demo. It authenticates workspace users and agents, evaluates requests before execution, and executes only registered sandbox tools inside the server. The demo tools operate on fictional in-process fixtures; there are no customer integrations or external side effects. `POST /v1/actions/evaluate` is a policy preview only and is not an execution authorization.

## Assets

- Human sessions, agent credentials, and signing/encryption keys
- Workspace membership, agent permissions, and approval decisions
- Server-stored tool arguments/results and audit evidence
- PostgreSQL/SQLite records and Redis rate-limit state

## Trust boundaries

1. Browser or agent client to API. Authentication uses human bearer sessions or random agent bearer tokens. TLS is expected for anything beyond local development.
2. API to persistence/cache. Workspaces are scoped in application queries; PostgreSQL and shared Redis are used by Compose.
3. Gateway to tool execution. The server derives the action label from a fixed tool registry. A review stores encrypted arguments, and resume accepts only the event ID, not replacement arguments.
4. Human approval to action resume. Workspace roles gate approvals; approved requests expire and are consumed once.
5. Audit evidence to database. Events are hash-linked per workspace; execution outcomes include a digest of the encrypted-at-rest result's plaintext.

## Threats and current controls

| Threat | Current control | Remaining gap |
|---|---|---|
| Stolen human session | 15-minute HMAC token, revocable server-side session, active-user check | No OIDC/SSO, MFA, refresh/session device controls, or password reset flow |
| Stolen agent token | Random one-time credential, SHA-256 hash at rest, 90-day expiry, disable/rotate endpoints | No scoped expiry per agent, external secret manager, or rotation automation |
| Cross-workspace data access | Authenticated workspace filters for agent/event/approval reads and user disable | Application-level tenancy only; no PostgreSQL row-level security; requires broader isolation testing |
| Unauthorized tool call | Fixed server-side registry derives action/resource; permissions are hard-denied; blocked/review calls do not execute | Only fictional demo tools exist; real tool adapters must be implemented behind this gateway and separately threat-tested |
| Approval replay or argument substitution | Resume takes no arguments; stored request fingerprint, agent/workspace scope, expiry and row locks; idempotency key for execute | External side effects need transactional outbox and downstream idempotency; no durable queue/retry worker |
| Prompt injection or sensitive data | Deterministic pattern/DLP checks and hard permission denial; does not send content to an LLM | Heuristics are bypassable and may create false positives/negatives; no semantic LLM or trained ML model |
| Database disclosure | Gateway arguments, derived payload and results use AES-GCM at rest with a separate configured key | Key rotation requires re-encryption; no KMS integration, field-level retention/deletion, or backup-key lifecycle |
| Audit row/result tampering | SHA-256 predecessor chain, workspace verification, approval/outcome consistency checks, encrypted data integrity, result digest | A privileged database operator can rewrite the entire chain and recompute hashes; no signed external checkpoint or immutable storage |
| API abuse | Request size limit, route-group fixed-window rate limiting, Redis shared counter in Compose, fail-closed Redis error | No WAF, adaptive limits, abuse alerts, load tests, or SLOs |
| Browser attack | Same-origin UI, escaping of displayed text, CSP and security headers | No independent web application penetration test; local development key shortcut must never be enabled in production |

## Safe evaluation

Run the included labelled actions only as a tiny smoke evaluation. Current rule-based results are explicitly not representative attack-detection quality. Do not feed the demo real secrets or customer information. The Attack Lab and fixed tool registry are simulation fixtures.

## Before a real business deployment

Add OIDC/SSO and MFA, external KMS/secrets management, signed audit checkpoints in immutable storage, PostgreSQL row-level security or an equivalent isolation layer, encrypted backups and restore drills, retention/deletion controls, SIEM alerting, real tool adapter threat models, durable idempotent execution, load/failure testing, privacy/legal review, and an independent security assessment. No certification, customer deployment, production SLA, or penetration-test completion is claimed.
