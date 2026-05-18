import fs from "node:fs";

const requiredEnv = [
  "MCP_URL",
  "AUTH0_DOMAIN",
  "AUTH0_CLIENT_ID",
  "AUTH0_CLIENT_SECRET",
  "AUTH0_AUDIENCE",
];

for (const key of requiredEnv) {
  if (!process.env[key] || !process.env[key].trim()) {
    throw new Error(`Missing required env var: ${key}`);
  }
}

const mcpUrl = process.env.MCP_URL;
const auth0Domain = process.env.AUTH0_DOMAIN;
const clientId = process.env.AUTH0_CLIENT_ID;
const clientSecret = process.env.AUTH0_CLIENT_SECRET;
const audience = process.env.AUTH0_AUDIENCE;

async function getToken() {
  const res = await fetch(`https://${auth0Domain}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      audience,
      scope: "mcp:tools tier:premium tier:analyst",
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Token request failed: ${res.status} ${JSON.stringify(json)}`);
  }
  return json.access_token;
}

async function mcpPost(token, body, sessionId) {
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${token}`,
  };
  if (sessionId) {
    headers["mcp-session-id"] = sessionId;
  }
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { res, parsed };
}

async function createSession(token) {
  const init = await mcpPost(
    token,
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "samples-validator", version: "1.0.0" },
      },
    },
    undefined,
  );
  const sessionId = init.res.headers.get("mcp-session-id");
  if (!sessionId) {
    throw new Error(
      `MCP initialize failed: status=${init.res.status} body=${JSON.stringify(init.parsed)}`,
    );
  }
  await mcpPost(
    token,
    {
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    },
    sessionId,
  );
  return sessionId;
}

async function runNodeScenarios(token, sessionId) {
  const files = [
    "samples/node/clean.package-lock.json",
    "samples/node/mixed.package-lock.json",
    "samples/node/high-risk.package-lock.json",
  ];

  const results = [];
  for (const file of files) {
    const lockfileContent = fs.readFileSync(file, "utf8");
    const started = Date.now();
    const scan = await mcpPost(
      token,
      {
        jsonrpc: "2.0",
        id: `scan:${file}`,
        method: "tools/call",
        params: {
          name: "scan_node_lockfile",
          arguments: {
            lockfileContent,
            maxDependencies: 200,
          },
        },
      },
      sessionId,
    );
    const payload = scan.parsed?.result?.structuredContent;
    if (!payload) {
      results.push({
        file,
        error: scan.parsed?.error ?? scan.parsed,
      });
      continue;
    }

    let patchQueueCount = 0;
    const queue = await mcpPost(
      token,
      {
        jsonrpc: "2.0",
        id: `queue:${file}`,
        method: "tools/call",
        params: {
          name: "build_patch_queue",
          arguments: {
            scanId: payload.scanId,
          },
        },
      },
      sessionId,
    );
    const queuePayload = queue.parsed?.result?.structuredContent;
    if (Array.isArray(queuePayload?.queue)) {
      patchQueueCount = queuePayload.queue.length;
    }

    results.push({
      file,
      elapsedMs: Date.now() - started,
      dependencyCount: payload.dependencyCount,
      vulnerableDependencyCount: payload.vulnerableDependencyCount,
      totalFindings: payload.totalFindings,
      resolvedDependencyCount: payload.resolvedDependencyCount,
      unresolvedDependencyCount: payload.unresolvedDependencyCount,
      degraded: payload.degraded,
      patchQueueCount,
    });
  }
  return results;
}

async function runJavaScenarios(token, sessionId) {
  const files = [
    "samples/java/clean-coordinates.json",
    "samples/java/vulnerable-coordinates.json",
  ];

  const results = [];
  for (const file of files) {
    const entries = JSON.parse(fs.readFileSync(file, "utf8"));
    const rows = [];
    for (const entry of entries) {
      const res = await mcpPost(
        token,
        {
          jsonrpc: "2.0",
          id: `java:${entry.packageName}@${entry.version}`,
          method: "tools/call",
          params: {
            name: "analyze_package_version",
            arguments: {
              packageName: entry.packageName,
              version: entry.version,
              ecosystem: entry.ecosystem,
            },
          },
        },
        sessionId,
      );
      const payload = res.parsed?.result?.structuredContent;
      rows.push({
        packageName: entry.packageName,
        version: entry.version,
        ecosystem: entry.ecosystem,
        vulnerabilityCount: payload?.vulnerabilityCount ?? null,
        error: payload ? null : (res.parsed?.error ?? res.parsed),
      });
    }
    results.push({ file, rows });
  }
  return results;
}

async function main() {
  const token = await getToken();
  const sessionId = await createSession(token);
  const nodeResults = await runNodeScenarios(token, sessionId);
  const javaResults = await runJavaScenarios(token, sessionId);
  console.log(
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        mcpUrl,
        nodeResults,
        javaResults,
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
