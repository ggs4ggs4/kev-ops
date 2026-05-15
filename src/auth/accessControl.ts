import { TIERS, type Tier } from "../types/domain.js";

type PrimitiveAccess = {
  minTier: Tier;
  scopesAnyOf?: string[];
};

const tierRank: Record<Tier, number> = {
  free: 0,
  premium: 1,
  analyst: 2,
};

export const toolAccess: Record<string, PrimitiveAccess> = {
  get_cve_snapshot: { minTier: "free" },
  get_kev_status: { minTier: "free" },
  list_recent_kev: { minTier: "free" },
  list_my_recent_audit: { minTier: "free" },

  get_epss_score: { minTier: "premium" },
  analyze_package_version: { minTier: "premium" },
  scan_node_lockfile: { minTier: "premium" },

  triage_cve: { minTier: "analyst" },
  build_patch_queue: { minTier: "analyst" },
};

export const resourceAccess: Record<string, PrimitiveAccess> = {
  "kev-summary": { minTier: "free" },
  "user-audit-log": { minTier: "free" },
  "scan-latest": { minTier: "premium" },
};

export const promptAccess: Record<string, PrimitiveAccess> = {
  "patch-standup-brief": { minTier: "premium" },
  "executive-risk-memo": { minTier: "analyst" },
};

export function isTier(value: string): value is Tier {
  return (TIERS as readonly string[]).includes(value);
}

export function canAccessTier(userTier: Tier, requiredTier: Tier): boolean {
  return tierRank[userTier] >= tierRank[requiredTier];
}

export function canAccessPrimitive(
  userTier: Tier,
  userScopes: string[],
  access: PrimitiveAccess | undefined,
): { allowed: boolean; reason?: string } {
  if (!access) {
    return { allowed: false, reason: "unknown_primitive" };
  }

  if (!canAccessTier(userTier, access.minTier)) {
    return { allowed: false, reason: `requires_${access.minTier}` };
  }

  if (access.scopesAnyOf && access.scopesAnyOf.length > 0) {
    const hasScope = access.scopesAnyOf.some((scope) => userScopes.includes(scope));
    if (!hasScope) {
      return { allowed: false, reason: "insufficient_scope" };
    }
  }

  return { allowed: true };
}

export function listAllowedTools(tier: Tier): string[] {
  return Object.entries(toolAccess)
    .filter(([, access]) => canAccessTier(tier, access.minTier))
    .map(([name]) => name);
}

export function listAllowedResources(tier: Tier): string[] {
  return Object.entries(resourceAccess)
    .filter(([, access]) => canAccessTier(tier, access.minTier))
    .map(([name]) => name);
}

export function listAllowedPrompts(tier: Tier): string[] {
  return Object.entries(promptAccess)
    .filter(([, access]) => canAccessTier(tier, access.minTier))
    .map(([name]) => name);
}
