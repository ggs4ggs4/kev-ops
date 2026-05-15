# KEV-OPS MCP Server

Exploit-first vulnerability triage MCP server for hackathon demos.

It answers one practical question:
`Out of all CVEs in my dependency graph, what should I patch first?`

## What this ships

- Streamable HTTP MCP server (`/mcp`) for remote usage
- OAuth bearer auth with JWT verification (Auth0-ready)
- Protected Resource Metadata endpoint for MCP/OAuth discovery
- Tier-aware tools/resources/prompts (`Free`, `Premium`, `Analyst`)
- Per-user hourly rate limits (`30/150/500`)
- Multi-TTL cache with stale fallback
- Queryable audit log for every tool invocation
- Cross-source triage using:
  - NVD CVE API
  - CISA KEV feed
  - FIRST EPSS API
  - OSV package vulnerability API

## Architecture at a glance

- `src/index.ts`: runtime entrypoint
- `src/http/`: Express + MCP transport routes + health/admin endpoints
- `src/auth/`: JWT verification, user tier inference, access control
- `src/services/`: upstream adapters and triage engine
- `src/store/`: cache, rate limiter, audit log, scan persistence
- `src/mcp/serverFactory.ts`: tier-filtered MCP tools/resources/prompts

Detailed notes: [docs/ARCHITECTURE.md]

## MCP tools by tier

### Free
- `get_cve_snapshot`
- `get_kev_status`
- `list_recent_kev`
- `list_my_recent_audit`

### Premium
- `get_epss_score`
- `analyze_package_version`
- `scan_node_lockfile`

### Analyst
- `triage_cve`
- `build_patch_queue`

## Resources

- `kev://catalog/summary`
- `audit://{userId}/recent`
- `scan://{scanId}/latest`

## Prompts

- `patch-standup-brief` (Premium+)
- `executive-risk-memo` (Analyst)

## Prerequisites

- Node.js 22+
- Optional: Redis
- Auth0 tenant (for production auth flow)

## 1) Environment setup

Copy `.env.example` to `.env` and fill in values:

- `AUTH0_ISSUER` (example: `https://your-tenant.us.auth0.com/`)
- `AUTH0_AUDIENCE` (your API identifier)
- `AUTH0_JWKS_URI`

Optional:
- `REDIS_URL` for distributed rate limits/cache/logs
- `NVD_API_KEY` to improve NVD API headroom

## 2) Install and run locally

```bash
npm install
npm run check
npm run dev
```

Health checks:

- `GET /health`
- `GET /health/upstream`
- `GET /admin/audit`

## 3) Auth0 setup (required for demo day)

Create an Auth0 API and configure:

1. API Identifier = `AUTH0_AUDIENCE`
2. Enable RBAC
3. Enable “Add Permissions in Access Token”

Create permissions:

- `mcp:tools`
- `tier:free`
- `tier:premium`
- `tier:analyst`

Create roles:

- `free-user` -> `mcp:tools`, `tier:free`
- `premium-user` -> `mcp:tools`, `tier:premium`
- `analyst-user` -> `mcp:tools`, `tier:analyst`

Add a Post Login Action to inject tier claim:

```js
exports.onExecutePostLogin = async (event, api) => {
  const namespace = "https://kevops.example.com";
  const perms = event.authorization?.permissions || [];
  let tier = "free";
  if (perms.includes("tier:analyst")) tier = "analyst";
  else if (perms.includes("tier:premium")) tier = "premium";

  api.accessToken.setCustomClaim(`${namespace}/tier`, tier);
  api.accessToken.setCustomClaim(`${namespace}/roles`, event.authorization?.roles || []);
};
```

Match namespace values with:

- `AUTH0_TIER_CLAIM`
- `AUTH0_ROLES_CLAIM`

## 4) Run with Docker

```bash
docker compose up --build
```

## 5) Deploy to AWS (EC2 baseline)

1. Launch EC2 (t2.micro/t3.micro)
2. Install Docker + Compose
3. Clone repo, add `.env`
4. `docker compose up -d --build`
5. Expose `PORT` in Security Group
6. Set `PUBLIC_BASE_URL` to public URL

## 5B) Deploy to AWS with Terraform (recommended)

Use the ready stack in [infra/terraform/README.md].

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars
terraform init
terraform apply
```

## 6) Demo script (suggested)

1. Connect MCP client to `https://<your-host>/mcp`
2. Authenticate via Auth0
3. Run `scan_node_lockfile` with a real Node lockfile
4. Run `build_patch_queue` and show ranked exploit-first output
5. Log in as Free user and call Analyst tool -> blocked (`403`)
6. Trigger repeated tool calls to show `429` + `Retry-After`
7. Re-run same call and show cache-influenced speed + audit rows

## Notes

- If upstream APIs fail, cached stale data is served when available.
- Lockfile scanning is capped per tier:
  - Premium: `LOCKFILE_SCAN_MAX_DEPS_PREMIUM`
  - Analyst: `LOCKFILE_SCAN_MAX_DEPS_ANALYST`

## Useful commands

```bash
npm run check
npm run build
npm run dev
npm run demo:load
```
