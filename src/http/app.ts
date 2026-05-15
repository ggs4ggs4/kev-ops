import express from "express";
import cors from "cors";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { config } from "../config.js";
import { logger } from "../core/logger.js";
import { createRedisClient } from "../store/redis.js";
import { CacheStore } from "../store/cacheStore.js";
import { RateLimiter } from "../store/rateLimiter.js";
import { AuditStore } from "../store/auditStore.js";
import { ScanStore } from "../store/scanStore.js";
import { Auth0JwtVerifier } from "../auth/auth0Verifier.js";
import { NvdClient } from "../services/nvdClient.js";
import { KevClient } from "../services/kevClient.js";
import { EpssClient } from "../services/epssClient.js";
import { OsvClient } from "../services/osvClient.js";
import { TriageEngine } from "../services/triageEngine.js";
import {
  createMcpRouteHandlers,
  installAuthMetadataRoutes,
} from "./mcpRoutes.js";
import type { McpDependencies } from "../mcp/serverFactory.js";

export async function createApp() {
  const redis = await createRedisClient(config.redis.url);
  const cacheStore = new CacheStore(redis);
  const rateLimiter = new RateLimiter(redis);
  const auditStore = new AuditStore(redis);
  const scanStore = new ScanStore();

  const nvdClient = new NvdClient(cacheStore);
  const kevClient = new KevClient(cacheStore);
  const epssClient = new EpssClient(cacheStore);
  const osvClient = new OsvClient(cacheStore);
  const triageEngine = new TriageEngine(nvdClient, kevClient, epssClient);

  const deps: McpDependencies = {
    nvdClient,
    kevClient,
    epssClient,
    osvClient,
    triageEngine,
    auditStore,
    scanStore,
  };

  const app = createMcpExpressApp({
    host: config.host,
    allowedHosts: config.allowedHosts.length > 0 ? config.allowedHosts : undefined,
  });
  app.use(
    cors({
      origin: "*",
      exposedHeaders: [
        "WWW-Authenticate",
        "Mcp-Session-Id",
        "Mcp-Protocol-Version",
        "Retry-After",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
      ],
    }),
  );
  app.use(express.json({ limit: "8mb" }));

  const resourceMetadataUrl = installAuthMetadataRoutes(app);

  const verifier = new Auth0JwtVerifier();
  const mcp = createMcpRouteHandlers({
    deps,
    verifier,
    rateLimiter,
    resourceMetadataUrl,
  });
  mcp.mount(app);

  app.get("/health", async (_req, res) => {
    res.json({
      status: "ok",
      time: new Date().toISOString(),
      mcpPath: config.mcpPath,
      authRequired: config.auth.required,
      redis: Boolean(redis),
    });
  });

  app.get("/health/upstream", async (_req, res) => {
    const checks = await Promise.allSettled([
      nvdClient.getCve("CVE-2021-44228"),
      kevClient.listRecent(1),
      epssClient.getScore("CVE-2021-44228"),
      osvClient.queryPackage({
        name: "lodash",
        version: "4.17.20",
        direct: true,
        ecosystem: "npm",
      }),
    ]);

    const [nvd, kev, epss, osv] = checks.map((check) =>
      check.status === "fulfilled"
        ? { ok: true, cacheState: check.value.cacheState }
        : { ok: false, error: check.reason instanceof Error ? check.reason.message : String(check.reason) },
    );

    res.json({
      status: checks.every((check) => check.status === "fulfilled") ? "ok" : "degraded",
      checks: {
        nvd,
        kev,
        epss,
        osv,
      },
    });
  });

  app.get("/admin/audit", async (req, res) => {
    const userId = typeof req.query.userId === "string" ? req.query.userId : undefined;
    const limit =
      typeof req.query.limit === "string" ? Number.parseInt(req.query.limit, 10) : 100;
    const rows = await auditStore.query({
      userId,
      limit: Number.isFinite(limit) ? limit : 100,
    });
    res.json({
      count: rows.length,
      rows,
    });
  });

  async function shutdown(): Promise<void> {
    if (redis) {
      await redis.quit();
    }
    logger.info("Application resources closed");
  }

  return {
    app,
    shutdown,
  };
}
