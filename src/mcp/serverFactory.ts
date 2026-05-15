import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import { config } from "../config.js";
import { userContextFromAuth } from "../auth/auth0Verifier.js";
import {
  canAccessPrimitive,
  promptAccess,
  resourceAccess,
  toolAccess,
} from "../auth/accessControl.js";
import type { Tier, UserContext } from "../types/domain.js";
import type { AuditStore } from "../store/auditStore.js";
import type { ScanStore } from "../store/scanStore.js";
import { parseNodeLockfile } from "../services/lockfileParser.js";
import type { OsvClient } from "../services/osvClient.js";
import type { EpssClient } from "../services/epssClient.js";
import type { KevClient } from "../services/kevClient.js";
import type { NvdClient } from "../services/nvdClient.js";
import type { TriageEngine } from "../services/triageEngine.js";

type ToolPayload = {
  data: unknown;
  cacheSignals: string[];
};

export type McpDependencies = {
  nvdClient: NvdClient;
  kevClient: KevClient;
  epssClient: EpssClient;
  osvClient: OsvClient;
  triageEngine: TriageEngine;
  auditStore: AuditStore;
  scanStore: ScanStore;
};

function asToolResult(payload: ToolPayload): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload.data, null, 2) }],
    structuredContent: payload.data as Record<string, unknown>,
  };
}

function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function withAudit(
  deps: McpDependencies,
  toolName: string,
  minTier: Tier,
  handler: (user: UserContext, args: Record<string, unknown>) => Promise<ToolPayload>,
) {
  return async (args: Record<string, unknown>, extra: { authInfo?: unknown }): Promise<CallToolResult> => {
    const startedAt = Date.now();
    const user = userContextFromAuth(extra.authInfo as never);
    const access = canAccessPrimitive(user.tier, user.scopes, toolAccess[toolName]);
    if (!access.allowed) {
      await deps.auditStore.append({
        userId: user.userId,
        clientId: user.clientId,
        tier: user.tier,
        toolName,
        status: "blocked",
        durationMs: Date.now() - startedAt,
        cacheSignals: [],
        errorMessage: access.reason ?? `requires_${minTier}`,
      });
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Access denied for tool '${toolName}': ${access.reason ?? "insufficient_scope"}`,
          },
        ],
      };
    }

    try {
      const payload = await handler(user, args);
      await deps.auditStore.append({
        userId: user.userId,
        clientId: user.clientId,
        tier: user.tier,
        toolName,
        status: "ok",
        durationMs: Date.now() - startedAt,
        cacheSignals: payload.cacheSignals,
      });
      return asToolResult(payload);
    } catch (error) {
      await deps.auditStore.append({
        userId: user.userId,
        clientId: user.clientId,
        tier: user.tier,
        toolName,
        status: "error",
        durationMs: Date.now() - startedAt,
        cacheSignals: [],
        errorMessage: normalizeError(error),
      });
      return {
        isError: true,
        content: [{ type: "text", text: `Tool execution failed: ${normalizeError(error)}` }],
      };
    }
  };
}

export function createMcpServerForTier(
  tier: Tier,
  deps: McpDependencies,
): McpServer {
  const server = new McpServer(
    {
      name: "kev-ops-mcp",
      version: "1.0.0",
    },
    {
      instructions:
        "Use this server for exploit-first vulnerability triage. Prefer triage_cve and build_patch_queue for analyst-grade decisions. Always include cited evidence fields from outputs.",
      capabilities: {
        logging: {},
      },
    },
  );

  if (canAccessPrimitive(tier, [], toolAccess.get_cve_snapshot).allowed) {
    server.registerTool(
      "get_cve_snapshot",
      {
        title: "Get CVE Snapshot",
        description: "Fetch NVD details and KEV listing status for a CVE.",
        inputSchema: {
          cveId: z.string().min(5).max(40),
        },
      },
      withAudit(deps, "get_cve_snapshot", "free", async (_user, args) => {
        const cveId = String(args.cveId).toUpperCase();
        const [nvd, kev] = await Promise.all([
          deps.nvdClient.getCve(cveId),
          deps.kevClient.getByCve(cveId),
        ]);
        return {
          data: {
            cveId,
            nvd: nvd.data,
            kev: {
              listed: Boolean(kev.data),
              entry: kev.data,
            },
            citations: [
              `NVD:${cveId}`,
              `CISA_KEV:${kev.data ? "listed" : "not_listed"}`,
            ],
          },
          cacheSignals: [`nvd:${nvd.cacheState}`, `kev:${kev.cacheState}`],
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.get_kev_status).allowed) {
    server.registerTool(
      "get_kev_status",
      {
        title: "Get KEV Status",
        description: "Check whether a CVE is listed in the CISA Known Exploited Vulnerabilities catalog.",
        inputSchema: {
          cveId: z.string(),
        },
      },
      withAudit(deps, "get_kev_status", "free", async (_user, args) => {
        const cveId = String(args.cveId).toUpperCase();
        const kev = await deps.kevClient.getByCve(cveId);
        return {
          data: {
            cveId,
            listed: Boolean(kev.data),
            entry: kev.data,
          },
          cacheSignals: [`kev:${kev.cacheState}`],
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.list_recent_kev).allowed) {
    server.registerTool(
      "list_recent_kev",
      {
        title: "List Recent KEV Additions",
        description: "List recently added KEV vulnerabilities.",
        inputSchema: {
          limit: z.number().int().min(1).max(100).optional(),
        },
      },
      withAudit(deps, "list_recent_kev", "free", async (_user, args) => {
        const limit = typeof args.limit === "number" ? args.limit : 10;
        const kev = await deps.kevClient.listRecent(limit);
        return {
          data: {
            limit,
            items: kev.data,
          },
          cacheSignals: [`kev:${kev.cacheState}`],
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.list_my_recent_audit).allowed) {
    server.registerTool(
      "list_my_recent_audit",
      {
        title: "List My Recent Audit Entries",
        description: "Return recent audit records for the current authenticated user.",
        inputSchema: {
          limit: z.number().int().min(1).max(200).optional(),
        },
      },
      withAudit(deps, "list_my_recent_audit", "free", async (user, args) => {
        const limit = typeof args.limit === "number" ? args.limit : 20;
        const rows = await deps.auditStore.query({ userId: user.userId, limit });
        return {
          data: {
            userId: user.userId,
            count: rows.length,
            rows,
          },
          cacheSignals: [],
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.get_epss_score).allowed) {
    server.registerTool(
      "get_epss_score",
      {
        title: "Get EPSS Score",
        description: "Get EPSS probability and percentile for a CVE.",
        inputSchema: {
          cveId: z.string(),
        },
      },
      withAudit(deps, "get_epss_score", "premium", async (_user, args) => {
        const cveId = String(args.cveId).toUpperCase();
        const epss = await deps.epssClient.getScore(cveId);
        return {
          data: {
            cveId,
            epss: epss.data,
          },
          cacheSignals: [`epss:${epss.cacheState}`],
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.analyze_package_version).allowed) {
    server.registerTool(
      "analyze_package_version",
      {
        title: "Analyze Package Version",
        description: "Query OSV advisories for a specific package@version.",
        inputSchema: {
          packageName: z.string().min(1),
          version: z.string().min(1),
          ecosystem: z.string().default("npm").optional(),
        },
      },
      withAudit(deps, "analyze_package_version", "premium", async (_user, args) => {
        const packageName = String(args.packageName);
        const version = String(args.version);
        const ecosystem = args.ecosystem ? String(args.ecosystem) : "npm";
        const osv = await deps.osvClient.queryPackage({
          name: packageName,
          version,
          direct: true,
          ecosystem,
        });
        return {
          data: {
            packageName,
            version,
            vulnerabilityCount: osv.data.length,
            vulnerabilities: osv.data,
          },
          cacheSignals: [`osv:${osv.cacheState}`],
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.scan_node_lockfile).allowed) {
    server.registerTool(
      "scan_node_lockfile",
      {
        title: "Scan Node Lockfile",
        description:
          "Parse package-lock.json, pnpm-lock.yaml, or yarn.lock content and query OSV for vulnerable dependencies.",
        inputSchema: {
          lockfileContent: z.string().min(10),
          maxDependencies: z.number().int().min(1).max(1000).optional(),
        },
      },
      withAudit(deps, "scan_node_lockfile", "premium", async (user, args) => {
        const lockfileContent = String(args.lockfileContent);
        const requestedMax =
          typeof args.maxDependencies === "number" ? args.maxDependencies : undefined;
        const tierCap = config.limits.lockfileScanMaxDepsByTier[user.tier];
        const maxDependencies = Math.min(requestedMax ?? tierCap, tierCap);
        const parsed = parseNodeLockfile(lockfileContent);
        const truncated = parsed.slice(0, maxDependencies);
        const osvFindings = await deps.osvClient.queryBatch(truncated);
        const withVulns = osvFindings
          .filter((entry) => entry.vulnerabilities.length > 0)
          .map((entry) => ({
            packageName: entry.packageName,
            version: entry.version,
            direct: entry.direct,
            vulnerabilities: entry.vulnerabilities,
          }));
        const totalFindings = withVulns.reduce(
          (sum, entry) => sum + entry.vulnerabilities.length,
          0,
        );
        const saved = deps.scanStore.save({
          dependencyCount: truncated.length,
          vulnerableDependencyCount: withVulns.length,
          totalFindings,
          findings: withVulns,
        });
        return {
          data: {
            scanId: saved.scanId,
            createdAt: saved.createdAt,
            dependencyCount: saved.dependencyCount,
            vulnerableDependencyCount: saved.vulnerableDependencyCount,
            totalFindings: saved.totalFindings,
            topPackages: withVulns.slice(0, 20),
            truncatedFrom: parsed.length,
          },
          cacheSignals: osvFindings.map((entry) => `osv:${entry.cacheState}`),
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.triage_cve).allowed) {
    server.registerTool(
      "triage_cve",
      {
        title: "Triage CVE",
        description:
          "Cross-source exploit-first triage using NVD + CISA KEV + EPSS and optional dependency blast radius.",
        inputSchema: {
          cveId: z.string(),
          affectedPackagesCount: z.number().int().min(0).max(999).optional(),
        },
      },
      withAudit(deps, "triage_cve", "analyst", async (_user, args) => {
        const cveId = String(args.cveId).toUpperCase();
        const affectedPackagesCount =
          typeof args.affectedPackagesCount === "number" ? args.affectedPackagesCount : 0;
        const result = await deps.triageEngine.triageCve(cveId, affectedPackagesCount);
        return {
          data: result.verdict,
          cacheSignals: result.cacheSignals,
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], toolAccess.build_patch_queue).allowed) {
    server.registerTool(
      "build_patch_queue",
      {
        title: "Build Patch Queue",
        description:
          "Build a ranked patch queue from a previous lockfile scan with exploit-first prioritization.",
        inputSchema: {
          scanId: z.string().uuid().optional(),
        },
      },
      withAudit(deps, "build_patch_queue", "analyst", async (_user, args) => {
        const scanId = typeof args.scanId === "string" ? args.scanId : undefined;
        const scan = scanId ? deps.scanStore.get(scanId) : deps.scanStore.latest();
        if (!scan) {
          throw new Error(
            "No scan found. Run scan_node_lockfile first or pass a valid scanId.",
          );
        }
        const queue = await deps.triageEngine.buildPatchQueue(scan);
        return {
          data: {
            scanId: scan.scanId,
            consideredCveCount: queue.consideredCveCount,
            droppedCves: queue.droppedCves,
            queue: queue.queue,
          },
          cacheSignals: queue.cacheSignals,
        };
      }),
    );
  }

  if (canAccessPrimitive(tier, [], resourceAccess["kev-summary"]).allowed) {
    server.registerResource(
      "kev-summary",
      "kev://catalog/summary",
      {
        title: "KEV Catalog Summary",
        description: "High-level summary of the CISA KEV feed.",
        mimeType: "application/json",
      },
      async () => {
        const catalog = await deps.kevClient.getCatalog();
        const ransomwareKnown = catalog.data.vulnerabilities.filter(
          (item) => item.knownRansomwareCampaignUse.toLowerCase() === "known",
        ).length;
        return {
          contents: [
            {
              uri: "kev://catalog/summary",
              mimeType: "application/json",
              text: JSON.stringify(
                {
                  title: catalog.data.title,
                  catalogVersion: catalog.data.catalogVersion,
                  dateReleased: catalog.data.dateReleased,
                  count: catalog.data.count,
                  ransomwareKnownCount: ransomwareKnown,
                  cacheState: catalog.cacheState,
                },
                null,
                2,
              ),
            },
          ],
        };
      },
    );
  }

  if (canAccessPrimitive(tier, [], resourceAccess["user-audit-log"]).allowed) {
    server.registerResource(
      "user-audit-log",
      new ResourceTemplate("audit://{userId}/recent", { list: undefined }),
      {
        title: "User Audit Log",
        description: "Recent audit entries for a user.",
        mimeType: "application/json",
      },
      async (uri, variables, extra) => {
        const requester = userContextFromAuth(extra.authInfo);
        const targetUserId = String(variables.userId);
        if (requester.userId !== targetUserId && requester.tier !== "analyst") {
          throw new Error("Not allowed to read another user's audit log.");
        }
        const rows = await deps.auditStore.query({ userId: targetUserId, limit: 50 });
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "application/json",
              text: JSON.stringify(
                {
                  userId: targetUserId,
                  count: rows.length,
                  rows,
                },
                null,
                2,
              ),
            },
          ],
        };
      },
    );
  }

  if (canAccessPrimitive(tier, [], resourceAccess["scan-latest"]).allowed) {
    server.registerResource(
      "scan-latest",
      new ResourceTemplate("scan://{scanId}/latest", { list: undefined }),
      {
        title: "Scan Snapshot",
        description: "Stored lockfile scan result by scanId.",
        mimeType: "application/json",
      },
      async (uri, variables) => {
        const scanId = String(variables.scanId);
        const scan = deps.scanStore.get(scanId);
        if (!scan) {
          throw new Error(`Scan '${scanId}' not found.`);
        }
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "application/json",
              text: JSON.stringify(scan, null, 2),
            },
          ],
        };
      },
    );
  }

  if (canAccessPrimitive(tier, [], promptAccess["patch-standup-brief"]).allowed) {
    server.registerPrompt(
      "patch-standup-brief",
      {
        title: "Patch Standup Brief",
        description: "Template for a concise engineering standup update from patch queue output.",
        argsSchema: {
          scanId: z.string().describe("Scan ID used to generate build_patch_queue output"),
        },
      },
      async ({ scanId }) => ({
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Using scanId ${scanId}, produce a 5-bullet engineering standup: top risks, what will be patched today, owners, rollback risks, and verification plan.`,
            },
          },
        ],
      }),
    );
  }

  if (canAccessPrimitive(tier, [], promptAccess["executive-risk-memo"]).allowed) {
    server.registerPrompt(
      "executive-risk-memo",
      {
        title: "Executive Risk Memo",
        description: "Template for non-technical stakeholder risk memo.",
        argsSchema: {
          cveId: z.string().describe("CVE identifier"),
        },
      },
      async ({ cveId }) => ({
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Write an executive memo for ${cveId}: business impact, why now, mitigation timeline, and residual risk after patch.`,
            },
          },
        ],
      }),
    );
  }

  return server;
}
