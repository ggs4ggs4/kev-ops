import { randomUUID } from "node:crypto";
import type { Express, Request, Response, RequestHandler } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { config } from "../config.js";
import { logger } from "../core/logger.js";
import { toolAccess, canAccessPrimitive } from "../auth/accessControl.js";
import { userContextFromAuth, type Auth0JwtVerifier } from "../auth/auth0Verifier.js";
import type { RateLimiter } from "../store/rateLimiter.js";
import { createMcpServerForTier, type McpDependencies } from "../mcp/serverFactory.js";

type SessionState = {
  transport: StreamableHTTPServerTransport;
  server: ReturnType<typeof createMcpServerForTier>;
  userId: string;
  tier: "free" | "premium" | "analyst";
};

function jsonRpcIdOf(body: unknown): string | number | null {
  if (typeof body !== "object" || body === null) {
    return null;
  }
  const maybeId = (body as { id?: unknown }).id;
  if (
    typeof maybeId === "string" ||
    typeof maybeId === "number" ||
    maybeId === null
  ) {
    return maybeId;
  }
  return null;
}

function extractToolName(body: unknown): string | null {
  if (Array.isArray(body)) {
    for (const item of body) {
      const fromItem = extractToolName(item);
      if (fromItem) {
        return fromItem;
      }
    }
    return null;
  }
  if (typeof body !== "object" || body === null) {
    return null;
  }
  const method = (body as { method?: unknown }).method;
  if (method !== "tools/call") {
    return null;
  }
  const params = (body as { params?: unknown }).params;
  if (typeof params !== "object" || params === null) {
    return null;
  }
  const name = (params as { name?: unknown }).name;
  return typeof name === "string" ? name : null;
}

function authMetadata() {
  const issuer = config.auth.issuer.endsWith("/")
    ? config.auth.issuer.slice(0, -1)
    : config.auth.issuer;
  const scopes = [
    "mcp:tools",
    "tier:free",
    "tier:premium",
    "tier:analyst",
    ...config.auth.requiredScopes,
  ];
  const scopesSupported = [...new Set(scopes)];
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oidc/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: scopesSupported,
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  };
}

export function installAuthMetadataRoutes(
  app: Express,
): string {
  const mcpServerUrl = new URL(config.mcpPath, config.publicBaseUrl);
  const resourceServerUrl = new URL(config.auth.resource);
  const oauth = authMetadata();
  const scopesSupported = [
    "mcp:tools",
    "tier:free",
    "tier:premium",
    "tier:analyst",
  ];
  const canonicalResourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(mcpServerUrl);
  const configuredResourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);
  const protectedResourceMetadata = {
    resource: resourceServerUrl.href,
    authorization_servers: [oauth.issuer],
    scopes_supported: scopesSupported,
    resource_name: "KEV-OPS MCP Server",
  };
  app.use(
    mcpAuthMetadataRouter({
      oauthMetadata: oauth,
      resourceServerUrl,
      scopesSupported,
      resourceName: "KEV-OPS MCP Server",
    }),
  );

  const canonicalResourceMetadataPath = new URL(canonicalResourceMetadataUrl).pathname;
  const rootResourceMetadataPath = "/.well-known/oauth-protected-resource";

  // Always provide canonical path metadata explicitly for client compatibility.
  app.get(canonicalResourceMetadataPath, (_req, res) => {
    res.json(protectedResourceMetadata);
  });

  // Compatibility alias: some clients probe the root well-known path first.
  if (canonicalResourceMetadataPath !== rootResourceMetadataPath) {
    app.get(rootResourceMetadataPath, (_req, res) => {
      res.json(protectedResourceMetadata);
    });
  }

  // Some clients probe this path-specific fallback; serve the same metadata for compatibility.
  const pathSpecificAuthServerMetadataPath = `/.well-known/oauth-authorization-server${
    mcpServerUrl.pathname === "/" ? "" : mcpServerUrl.pathname
  }`;
  if (pathSpecificAuthServerMetadataPath !== "/.well-known/oauth-authorization-server") {
    app.get(pathSpecificAuthServerMetadataPath, (_req, res) => {
      res.json(oauth);
    });
  }

  return canonicalResourceMetadataUrl;
}

export function createMcpRouteHandlers(options: {
  deps: McpDependencies;
  verifier: Auth0JwtVerifier;
  rateLimiter: RateLimiter;
  resourceMetadataUrl: string;
}) {
  const sessions = new Map<string, SessionState>();
  const mcpPath = config.mcpPath;

  const authMiddleware: RequestHandler = config.auth.required
    ? requireBearerAuth({
        verifier: options.verifier,
        requiredScopes: config.auth.requiredScopes,
        resourceMetadataUrl: options.resourceMetadataUrl,
      })
    : (_req, _res, next) => next();

  async function enforceToolBoundary(req: Request, res: Response): Promise<boolean> {
    const toolName = extractToolName(req.body);
    if (!toolName) {
      return true;
    }
    const user = userContextFromAuth(req.auth);
    const access = canAccessPrimitive(user.tier, user.scopes, toolAccess[toolName]);
    if (!access.allowed) {
      res.setHeader(
        "WWW-Authenticate",
        `Bearer error="insufficient_scope", error_description="Tool '${toolName}' requires higher tier or scope", resource_metadata="${options.resourceMetadataUrl}"`,
      );
      res.status(403).json({
        jsonrpc: "2.0",
        error: {
          code: -32003,
          message: "insufficient_scope",
          data: {
            toolName,
            reason: access.reason ?? "insufficient_scope",
          },
        },
        id: jsonRpcIdOf(req.body),
      });
      return false;
    }

    const decision = await options.rateLimiter.check(user.userId, user.tier);
    res.setHeader("X-RateLimit-Limit", String(decision.limit));
    res.setHeader("X-RateLimit-Remaining", String(decision.remaining));
    res.setHeader("X-RateLimit-Reset", String(decision.resetAtEpochSec));
    if (!decision.allowed) {
      res.setHeader("Retry-After", String(decision.retryAfterSec));
      res.status(429).json({
        jsonrpc: "2.0",
        error: {
          code: -32029,
          message: "Too Many Requests",
          data: {
            retryAfterSec: decision.retryAfterSec,
          },
        },
        id: jsonRpcIdOf(req.body),
      });
      return false;
    }
    return true;
  }

  const postHandler: RequestHandler = async (req, res) => {
    const allowed = await enforceToolBoundary(req, res);
    if (!allowed) {
      return;
    }

    const sessionId = req.headers["mcp-session-id"];
    const user = userContextFromAuth(req.auth);
    try {
      let session: SessionState | undefined;
      if (typeof sessionId === "string" && sessionId.length > 0) {
        session = sessions.get(sessionId);
        if (!session) {
          res.status(404).json({
            jsonrpc: "2.0",
            error: {
              code: -32004,
              message: "Unknown session",
            },
            id: jsonRpcIdOf(req.body),
          });
          return;
        }
        if (session.userId !== user.userId) {
          res.status(403).json({
            jsonrpc: "2.0",
            error: {
              code: -32003,
              message: "Session ownership mismatch",
            },
            id: jsonRpcIdOf(req.body),
          });
          return;
        }
      } else if (isInitializeRequest(req.body)) {
        let initializedSession: SessionState | null = null;
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized: (initializedSessionId) => {
            if (initializedSession) {
              sessions.set(initializedSessionId, initializedSession);
            }
          },
        });
        const server = createMcpServerForTier(user.tier, options.deps);
        session = {
          transport,
          server,
          userId: user.userId,
          tier: user.tier,
        };
        initializedSession = session;

        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid) {
            sessions.delete(sid);
          }
          void server.close().catch((error) => {
            logger.warn({ error }, "error during server close");
          });
        };

        transport.onerror = (error) => {
          logger.error({ err: error }, "mcp transport error");
        };

        transport.onmessage = () => {};

        await server.connect(transport);
      } else {
        res.status(400).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Bad Request: missing valid MCP session ID or initialize payload",
          },
          id: jsonRpcIdOf(req.body),
        });
        return;
      }

      await session.transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error({ err: error }, "failed to handle MCP POST");
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: "Internal server error",
          },
          id: jsonRpcIdOf(req.body),
        });
      }
    }
  };

  const getHandler: RequestHandler = async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    if (typeof sessionId !== "string") {
      res.status(400).send("Missing mcp-session-id header");
      return;
    }
    const session = sessions.get(sessionId);
    if (!session) {
      res.status(404).send("Unknown session");
      return;
    }
    const user = userContextFromAuth(req.auth);
    if (session.userId !== user.userId) {
      res.status(403).send("Session ownership mismatch");
      return;
    }
    try {
      await session.transport.handleRequest(req, res);
    } catch (error) {
      logger.error({ err: error }, "failed to handle MCP GET");
      if (!res.headersSent) {
        res.status(500).send("Internal server error");
      }
    }
  };

  const deleteHandler: RequestHandler = async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    if (typeof sessionId !== "string") {
      res.status(400).send("Missing mcp-session-id header");
      return;
    }
    const session = sessions.get(sessionId);
    if (!session) {
      res.status(404).send("Unknown session");
      return;
    }
    const user = userContextFromAuth(req.auth);
    if (session.userId !== user.userId) {
      res.status(403).send("Session ownership mismatch");
      return;
    }
    try {
      await session.transport.handleRequest(req, res);
      sessions.delete(sessionId);
      await session.server.close();
    } catch (error) {
      logger.error({ err: error }, "failed to handle MCP DELETE");
      if (!res.headersSent) {
        res.status(500).send("Internal server error");
      }
    }
  };

  const mount = (app: Express) => {
    app.post(mcpPath, authMiddleware, postHandler);
    app.get(mcpPath, authMiddleware, getHandler);
    app.delete(mcpPath, authMiddleware, deleteHandler);
  };

  return {
    mount,
  };
}
