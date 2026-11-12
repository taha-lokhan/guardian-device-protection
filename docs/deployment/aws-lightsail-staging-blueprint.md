# Guardian AWS staging blueprint (no deployment)

Status: planning only. This document does not authorize creation of AWS resources, firewall changes, DNS changes, deployment, or public exposure.

## Goals

Build a low-cost, isolated staging environment to validate Guardian across independently networked devices. Preserve the existing protocol-v2 work while preparing the application for multiple organizations and eventual paid plans.

Non-goals for this stage:
- Production deployment or customer data.
- Publicly reachable dashboard, API, or MQTT listener.
- Destructive-command testing (wipe, lock, backup, location collection).
- Billing integration or customer self-service enrollment.
- Merging the existing security PRs as a substitute for runtime validation.

## AWS choice and budget

Preferred starting point: Amazon Lightsail Linux/Unix, 2 GB RAM / 2 vCPU / 60 GB SSD / public IPv4 bundle, currently listed at USD 12/month in the standard dual-stack plan. This fits the USD 10–20 target better than a general EC2 design. AWS lists the 4 GB bundle at USD 24/month, outside the stated budget.

Pricing is regional and can change. Verify the selected region's price and data-transfer allowance in the AWS console before purchase. Taxes, optional snapshots/backups, DNS/domain registration, and any transfer overage may increase the bill. Set an AWS Budget alert before provisioning. Do not create a managed database in this budget: Lightsail managed databases are a separate charge. For staging only, PostgreSQL can run on the same VM with private/local binding and encrypted off-host backups.

Official pricing references:
- https://aws.amazon.com/lightsail/pricing/
- https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-bundles.html

## Network model (domain not owned)

Use a VPN-first, private staging model:
- Lightsail public IPv4 is used only as the WireGuard endpoint.
- Permit inbound UDP 51820 for WireGuard.
- Permit SSH only from the operator's current trusted public IP; do not leave SSH open to the world.
- Do not expose TCP 80/443, relay/API, PostgreSQL, or MQTT to the public internet in this phase.
- Dashboard and relay API are reachable only over the WireGuard interface/subnet.
- Bind PostgreSQL to loopback or a private interface; never a public interface.
- Bind Mosquitto to the WireGuard interface, not 0.0.0.0. Use authenticated clients and topic ACLs even inside the VPN.
- WireGuard encrypts the VPN path; it does not replace application authorization, device identity, MQTT ACLs, or signed command verification.
- Since there is no domain, do not promise public HTTPS/browser-trusted certificates. Use VPN-only access for staging and revisit a domain plus HTTPS before any public customer-facing dashboard.

Every test endpoint must have a unique WireGuard peer identity and unique Guardian device command-verification key. Do not reuse the server-generated phone/laptop peer keys across endpoints.

## Application layout for the staging VM

Single VM, separate services:
1. WireGuard for private network access.
2. Mosquitto for device messaging, private interface only.
3. PostgreSQL for durable application records, local/private only.
4. Guardian FastAPI relay under a dedicated unprivileged service account.
5. Nginx for static dashboard delivery on the VPN interface only.
6. systemd units, journald/log rotation, unattended security updates, host firewall, and a tested backup/restore procedure.

Keep signing private keys under a dedicated root-owned key directory. The relay service should receive only the minimum permissions needed to read signing material and write its application data. Do not run the web application as root.

## Database direction (design now, migrate deliberately)

The current relay uses Python sqlite3 directly and stores device status, locations, nuke state, command history, durable command outbox, sessions, rate-limit state, and audit records in SQLite. PostgreSQL is not integrated yet. Do not switch a connection string and assume migration is complete: SQLite-specific SQL, transaction semantics, concurrency, and startup migrations need deliberate conversion and tests.

Target PostgreSQL domain model:
- organizations (tenant boundary)
- users (login identities)
- memberships (user-to-organization role assignments)
- devices (organization-owned enrolled endpoints)
- device_keys (key IDs, public keys, active/revoked/rotated state)
- enrollments (one-time, expiring enrollment requests)
- commands (actor, target, command, approval, status, timestamps)
- device_telemetry (health/status with retention policy)
- audit_events (append-oriented administrative/security events)
- plans, subscriptions, and usage_entitlements (later billing phase)

All tenant-owned rows must carry organization_id. Enforce tenant scoping in every API query and authorization decision; consider PostgreSQL row-level security as defense in depth. Never trust organization_id supplied by a browser without deriving and checking membership server-side. Use foreign keys, unique constraints, indexes, migrations, least-privilege database roles, and parameterized queries. Keep high-volume telemetry retention separate from durable security audit records.

For the first staging pass, the existing SQLite database can remain only if the purpose is to validate VPN connectivity and service deployment. PostgreSQL integration is a separate code milestone and is a prerequisite to multi-tenant/customer data. Do not claim tenant isolation until it is implemented and tested.

## Existing repository blockers to resolve before any deployment

Inspected on `security/gdn-002-signed-commands`:
- `vps-setup/setup_vps.sh` currently creates one shared Mosquitto username/password, binds Mosquitto to 127.0.0.1:1883, and writes MQTT_TLS=false. This does not support remote agents connecting directly and is not the target device-auth model.
- The same script configures only two initial WireGuard peers, assumes the external interface is `eth0`, and runs the Guardian systemd service as root.
- The setup opens TCP 8443 in UFW without restricting it to the WireGuard subnet, despite describing the relay as VPN-only. This must be corrected before any deployment.
- The script writes a root credentials file containing multiple secrets and generated VPN private keys. Treat that output as highly sensitive; redesign provisioning so secrets are not unnecessarily duplicated or printed.
- `vps-setup/add_device.sh` interpolates the supplied device name into filesystem paths, shell commands, and WireGuard configuration without validating it. Do not run this helper with untrusted input; replace it with strict validation, safe quoting, collision checks, and atomic config updates.
- Relay persistence is SQLite via `sqlite3`; there is no PostgreSQL driver/ORM or schema migration system in `vps-setup/requirements.txt`.
- The relay has command authentication improvements, but ACK/telemetry sender authentication and per-device MQTT authorization remain unresolved. WireGuard alone does not close those application-level gaps.
- Current dashboard authentication is a shared master-password/TOTP flow, not user accounts, organizations, invitations, or role-based access control.

These are explicit deployment blockers, not cosmetic cleanup.

## Work sequence

### A. Before buying/creating resources
- Confirm AWS account access, intended region, billing alerts, and whether Lightsail is available in that region.
- Review this blueprint and approve the exact monthly cost and region.
- Do not share AWS access keys, passwords, TOTP seeds, or private keys in chat or repository files.

### B. Prepare repository (no cloud changes)
- Replace unsafe/incomplete VPS setup assumptions with an idempotent staging installer or documented manual runbook.
- Add explicit preflight checks and a dry-run mode.
- Make firewall policy deny-by-default and restrict SSH to an operator-approved CIDR; keep all application ports VPN-only.
- Use a dedicated non-root service account and explicit file permissions.
- Remove the misleading open TCP 8443 rule; API bind/firewall policy must be consistent.
- Validate WireGuard peer creation, uniqueness, and revocation safely.
- Add configuration validation that refuses insecure MQTT defaults and refuses public binds in staging mode.
- Add automated tests/static checks for generated config and firewall policy.
- Keep secrets out of logs, command-line arguments, Git, and broad-readable files.

### C. After explicit approval to provision
- Create one Lightsail instance in the approved region.
- Apply firewall rules before installing/running Guardian.
- Configure VPN and verify from one test laptop on a separate network.
- Install services without exposing dashboard/API/MQTT publicly.
- Enroll only a dedicated test endpoint and test harmless status/ping flows.
- Verify backup restoration and revoke the test peer/key.
- Do not test wipe/lock/backup/location actions during infrastructure smoke testing.

### D. Product and scale milestones
- PostgreSQL schema and migration layer.
- User identity, organizations, memberships, roles, tenant isolation tests.
- Secure enrollment and device lifecycle APIs.
- Per-device MQTT credentials/ACLs and authenticated telemetry/ACKs.
- Audit trails and command approvals.
- Billing and plan entitlements only after tenant isolation and usage accounting are proven.

## Approval gates

No AWS resource creation, deployment, DNS, security-group/firewall exposure, or public service listener is authorized by this document. Obtain explicit approval for:
1. AWS region and exact Lightsail bundle/cost.
2. Inbound network policy and the operator IP/CIDR for SSH.
3. VPN-only staging installation.
4. Any later public dashboard/API exposure.
