# Sample Scenarios For Demo

These samples are meant for MCP demo runs of KEV-OPS:

- Node lockfile scan (`scan_node_lockfile`)
- Java package lookup (`analyze_package_version` with `ecosystem = Maven`)

## Node Samples

- [clean.package-lock.json](./node/clean.package-lock.json)
- [mixed.package-lock.json](./node/mixed.package-lock.json)
- [high-risk.package-lock.json](./node/high-risk.package-lock.json)

Use each file as `lockfileContent` in `scan_node_lockfile`.

Expected behavior:

- `clean.package-lock.json`: few/no findings
- `mixed.package-lock.json`: clear vulnerable findings
- `high-risk.package-lock.json`: high finding volume and strong patch queue signal

## Java Samples

The server does not provide a Java lockfile parser tool today, but Java packages can still be analyzed using `analyze_package_version` and `ecosystem = Maven`.

- [clean-coordinates.json](./java/clean-coordinates.json)
- [vulnerable-coordinates.json](./java/vulnerable-coordinates.json)

For each entry in the JSON array, call:

- `packageName` -> `analyze_package_version.packageName`
- `version` -> `analyze_package_version.version`
- `ecosystem` -> `analyze_package_version.ecosystem`

## Suggested Demo Flow

1. Run `scan_node_lockfile` with `node/clean.package-lock.json`.
2. Run `scan_node_lockfile` with `node/high-risk.package-lock.json`.
3. Run `build_patch_queue` using the high-risk scan ID.
4. Run `analyze_package_version` for each row in `java/vulnerable-coordinates.json`.
5. Run `analyze_package_version` for each row in `java/clean-coordinates.json`.

## Optional One-Command Validation

You can validate all Node and Java samples against a live deployed server:

```bash
MCP_URL=http://52-201-86-101.nip.io/mcp \
AUTH0_DOMAIN=dev-qz8e8ckjdzrqogsq.us.auth0.com \
AUTH0_CLIENT_ID=... \
AUTH0_CLIENT_SECRET=... \
AUTH0_AUDIENCE=https://kev-ops-mcp-api/mcp \
npm run demo:samples
```

As of 2026-05-19 UTC in this repo setup, one validation run produced:

- Node clean: `0` findings
- Node mixed: `7` findings
- Node high-risk: `24` findings
- Java clean sample entries: `0` findings each
- Java vulnerable sample entries: `52` and `7` findings

Counts can change over time as OSV data updates.
