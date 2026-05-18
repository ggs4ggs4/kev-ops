import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { config } from "../config.js";
import { isTier } from "./accessControl.js";
import type { Tier, UserContext } from "../types/domain.js";

const jwks = createRemoteJWKSet(new URL(config.auth.jwksUri));

function toStringArray(value: unknown): string[] {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  if (typeof value === "string") {
    return value.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean);
  }
  return [];
}

function inferTier(payload: JWTPayload, scopes: string[]): Tier {
  const explicitTier = payload[config.auth.tierClaim];
  if (typeof explicitTier === "string" && isTier(explicitTier)) {
    return explicitTier;
  }

  const roles = [
    ...toStringArray(payload[config.auth.rolesClaim]),
    ...toStringArray(payload["roles"]),
    ...toStringArray(payload["permissions"]),
  ].map((value) => value.toLowerCase());

  if (roles.some((role) => role.includes("analyst"))) {
    return "analyst";
  }
  if (roles.some((role) => role.includes("premium"))) {
    return "premium";
  }
  if (roles.some((role) => role.includes("free"))) {
    return "free";
  }

  const normalizedScopes = scopes.map((scope) => scope.toLowerCase());
  if (normalizedScopes.includes("tier:analyst")) {
    return "analyst";
  }
  if (normalizedScopes.includes("tier:premium")) {
    return "premium";
  }
  if (normalizedScopes.includes("tier:free")) {
    return "free";
  }

  return config.auth.defaultTier;
}

export class Auth0JwtVerifier implements OAuthTokenVerifier {
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: config.auth.issuer,
      audience: [...config.auth.acceptedAudiences],
    });

    const scopes = [
      ...toStringArray(payload.scope),
      ...toStringArray(payload.permissions),
    ];
    const uniqueScopes = [...new Set(scopes)];
    const tier = inferTier(payload, uniqueScopes);
    const subject = typeof payload.sub === "string" ? payload.sub : "anonymous";
    const clientId =
      (typeof payload.azp === "string" && payload.azp) ||
      (typeof payload.client_id === "string" && payload.client_id) ||
      "unknown-client";

    return {
      token,
      clientId,
      scopes: uniqueScopes,
      expiresAt: typeof payload.exp === "number" ? payload.exp : undefined,
      extra: {
        userId: subject,
        tier,
        permissions: toStringArray(payload.permissions),
      },
    };
  }
}

export function userContextFromAuth(authInfo: AuthInfo | undefined): UserContext {
  if (!authInfo) {
    return {
      userId: "anonymous",
      clientId: "unknown-client",
      tier: config.auth.defaultTier,
      scopes: [],
      authInfo: {
        token: "",
        clientId: "unknown-client",
        scopes: [],
        extra: {
          userId: "anonymous",
          tier: config.auth.defaultTier,
        },
      },
    };
  }

  const extraTier = authInfo.extra?.tier;
  const tier = typeof extraTier === "string" && isTier(extraTier) ? extraTier : config.auth.defaultTier;
  const userId =
    typeof authInfo.extra?.userId === "string" && authInfo.extra.userId.length > 0
      ? authInfo.extra.userId
      : authInfo.clientId;

  return {
    userId,
    clientId: authInfo.clientId,
    tier,
    scopes: authInfo.scopes,
    authInfo,
  };
}
