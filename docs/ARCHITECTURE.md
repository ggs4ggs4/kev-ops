# KEV-OPS Architecture

## Request flow

1. Client sends MCP request to `/mcp`.
2. `requireBearerAuth` validates JWT and attaches `req.auth`.
3. Pre-tool guards apply:
   - tier boundary check (`403` on insufficient scope/tier)
   - per-user rate limiting (`429` with `Retry-After`)
4. Streamable HTTP transport routes request to a tier-specific `McpServer`.
5. Tool handlers call upstream adapters (`NVD`, `KEV`, `EPSS`, `OSV`) via cache layer.
6. Audit records are persisted for every tool call.
7. Structured JSON result is returned to client.

## Stateful MCP sessions

- New session: initialize request without `mcp-session-id`
- Existing session: requests must include matching `mcp-session-id`
- Session ownership enforced by authenticated user id
- Session resources cleaned up on close

## Core components

- `Auth0JwtVerifier`: verifies JWT signature via JWKS; infers user tier
- `RateLimiter`: per-user fixed-window hourly limits
- `CacheStore`: fresh + stale TTL strategy
- `AuditStore`: queryable execution logs
- `TriageEngine`: risk score from cross-source signals

## Cross-source triage signals

- NVD: CVSS and vulnerability context
- CISA KEV: exploited-in-wild status (+ransomware flag)
- EPSS: probability of exploitation
- OSV: dependency blast radius from lockfile scan

## Scoring heuristic

Risk score (0-100) currently combines:

- CVSS contribution
- KEV listing boost
- ransomware campaign boost
- EPSS probability contribution
- impacted package count contribution

Priority bands:

- `patch_now`
- `patch_24h`
- `patch_7d`
- `monitor`

## Operational endpoints

- `GET /health`
- `GET /health/upstream`
- `GET /admin/audit`

## OAuth metadata

The server exposes MCP OAuth metadata routes through `mcpAuthMetadataRouter`, including protected resource metadata for discovery by MCP clients.
