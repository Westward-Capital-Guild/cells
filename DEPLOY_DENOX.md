# Denox Staging Deployment

This deployment is an unofficial modified Pydio Cells Home build for the Denox customer environment. The browser uses Denox Passport OIDC. WebDAV continues to use independent Cells Personal Access Tokens.

## Fixed Inputs

- Public host: `https://files.tools.denox-corp.com`
- OIDC issuer: `https://passport.denox-corp.com`
- OIDC client: `customer-file-platform`
- OIDC callback: `https://files.tools.denox-corp.com/auth/oidc/callback`
- Runtime directory: `/opt/customer-file-platform`
- Image: `customer-file-platform-cells:oidc-poc-v0.2.0`
- Source tag: `denox-poc-v0.2.0`
- Database: `postgres:16.10-alpine`
- Storage: a dedicated encrypted Aliyun General-purpose NAS filesystem, mounted with NFSv4.0

## Secret Contract

The server-only `.env.stage` is generated from `denox-secrets/projects/customer-file-platform.stage.enc.env` and must be mode `0600`. It contains only the keys listed in `deploy/denox/.env.stage.example`. Do not generate a second copy of the OIDC client secret.

## Deploy

Build on the control machine and ship the image archive. Do not build on the staging ECS.

```bash
deploy/denox/build-image.sh
docker save customer-file-platform-cells:oidc-poc-v0.2.0 | gzip > customer-file-platform-cells.tar.gz
```

On the staging ECS, install the deployment files under `/opt/customer-file-platform`, load the image, and run:

```bash
cd /opt/customer-file-platform
./preflight.sh
docker compose --env-file .env.stage -f compose.yaml -f docker-compose.denox-ingress.yml up -d
./configure-oidc.sh
./smoke.sh
```

The NAS must already contain `.cells-storage-identity` whose exact one-line value matches `CELLS_NAS_SENTINEL`. The NFS-backed Docker volume fails container creation when the mount is unavailable; `cells-entrypoint.sh` additionally rejects a wrong filesystem or sentinel.

## Stateful Guard

Before and after a deployment, verify:

- the NAS volume reports filesystem type `nfs` and the expected sentinel;
- PostgreSQL uses `/opt/customer-file-platform/data/postgres`;
- Cells uses `/opt/customer-file-platform/data/cells` for configuration and the NFS volume for `/var/cells/data`;
- the application and database containers are healthy;
- a known synthetic file remains visible through both Cells and an independent NFS client.

## Rollback

Keep the previous image tag and deployment directory snapshot. Restore the previous compose/config revision and image, then recreate only the `cells` service. Do not delete or reinitialize PostgreSQL or the NAS. Revoking the Passport OAuth client is a separate destructive action and is not part of an application rollback.

## Acceptance Boundary

`deploy/denox/smoke.sh` proves public routing, OIDC initiation with PKCE, invalid callback rejection, and anonymous WebDAV denial. Deployment acceptance additionally requires a real Passport user login, JIT user reuse, a PAT-authenticated WebDAV write/read/delete round trip, exact source-link inspection, and state survival after container restart.
