import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export const TIERS = ["free", "premium", "analyst"] as const;
export type Tier = (typeof TIERS)[number];

export type CacheState = "fresh" | "stale" | "miss";

export interface UserContext {
  userId: string;
  clientId: string;
  tier: Tier;
  scopes: string[];
  authInfo: AuthInfo;
}

export interface SourceCitation {
  source: string;
  key: string;
  detail: string;
}

export interface NvdSnapshot {
  cveId: string;
  description: string;
  published: string;
  lastModified: string;
  cvssBaseScore: number | null;
  cvssSeverity: string | null;
  attackVector: string | null;
  references: string[];
}

export interface KevEntry {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  shortDescription: string;
  requiredAction: string;
  notes: string;
}

export interface EpssSnapshot {
  cveId: string;
  epss: number | null;
  percentile: number | null;
  date: string | null;
}

export interface PackageFinding {
  packageName: string;
  version: string;
  direct: boolean;
  vulnerabilities: Array<{
    osvId: string;
    aliases: string[];
    summary: string;
    severity: string | null;
  }>;
}

export interface LockfileScanResult {
  scanId: string;
  createdAt: string;
  dependencyCount: number;
  vulnerableDependencyCount: number;
  totalFindings: number;
  findings: PackageFinding[];
  unresolvedDependencyCount?: number;
  unresolvedDependencies?: Array<{
    packageName: string;
    version: string;
    direct: boolean;
    reason: string;
  }>;
}

export interface TriageVerdict {
  cveId: string;
  riskScore: number;
  priority: "patch_now" | "patch_24h" | "patch_7d" | "monitor";
  summary: string;
  confirmations: string[];
  contradictions: string[];
  recommendedActions: string[];
  citations: SourceCitation[];
  signals: {
    cvssBaseScore: number | null;
    kevListed: boolean;
    kevRansomwareKnown: boolean;
    epss: number | null;
    affectedPackagesCount: number;
  };
}

export interface AuditRecord {
  id: string;
  timestamp: string;
  userId: string;
  clientId: string;
  tier: Tier;
  toolName: string;
  status: "ok" | "error" | "blocked";
  durationMs: number;
  cacheSignals: string[];
  errorMessage?: string;
}
