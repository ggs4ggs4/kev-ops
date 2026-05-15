import { config } from "../config.js";
import type { CacheStore } from "../store/cacheStore.js";
import { cacheKey } from "../store/cacheStore.js";
import { fetchJson } from "./http.js";
import type { ServiceResult } from "./types.js";

export type PackageCoordinate = {
  name: string;
  version: string;
  direct: boolean;
  ecosystem?: string;
};

export type OsvVulnerabilitySummary = {
  osvId: string;
  aliases: string[];
  summary: string;
  severity: string | null;
};

type OsvQueryBatchRequest = {
  queries: Array<{
    package: { name: string; ecosystem: string };
    version: string;
  }>;
};

type OsvQueryBatchResponse = {
  results: Array<{
    vulns?: Array<{
      id?: string;
      aliases?: string[];
      summary?: string;
      details?: string;
      severity?: Array<{ type?: string; score?: string }>;
      database_specific?: { severity?: string };
    }>;
  }>;
};

function normalizeSeverity(vuln: {
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
}): string | null {
  if (vuln.database_specific?.severity) {
    return vuln.database_specific.severity;
  }
  const first = vuln.severity?.[0];
  if (first?.score) {
    return first.score;
  }
  return null;
}

function normalizeVulns(vulns: OsvQueryBatchResponse["results"][number]["vulns"]): OsvVulnerabilitySummary[] {
  if (!vulns) {
    return [];
  }
  return vulns
    .map((item) => ({
      osvId: item.id ?? "unknown",
      aliases: (item.aliases ?? []).filter((alias): alias is string => typeof alias === "string"),
      summary: item.summary?.trim() || item.details?.slice(0, 240) || "No summary provided",
      severity: normalizeSeverity(item),
    }))
    .filter((item) => item.osvId !== "unknown");
}

export class OsvClient {
  constructor(private readonly cache: CacheStore) {}

  async queryPackage(pkg: PackageCoordinate): Promise<ServiceResult<OsvVulnerabilitySummary[]>> {
    const normalized = {
      ...pkg,
      ecosystem: pkg.ecosystem ?? "npm",
      name: pkg.name.trim(),
      version: pkg.version.trim(),
    };
    const key = cacheKey(["osv", normalized.ecosystem, normalized.name, normalized.version]);
    const cached = await this.cache.get<OsvVulnerabilitySummary[]>(key);
    if (cached && cached.state === "fresh") {
      return { data: cached.value, cacheState: "fresh" };
    }

    try {
      const payload = await fetchJson<OsvQueryBatchResponse>(config.upstream.osvQueryBatchUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": "kev-ops-mcp/1.0",
        },
        body: JSON.stringify({
          queries: [
            {
              package: {
                name: normalized.name,
                ecosystem: normalized.ecosystem,
              },
              version: normalized.version,
            },
          ],
        } satisfies OsvQueryBatchRequest),
        timeoutMs: 20000,
      });
      const vulns = normalizeVulns(payload.results?.[0]?.vulns);
      await this.cache.set(
        key,
        vulns,
        config.cacheTtls.osv.freshSec,
        config.cacheTtls.osv.staleSec,
      );
      return { data: vulns, cacheState: "fresh" };
    } catch (error) {
      if (cached) {
        return { data: cached.value, cacheState: "stale" };
      }
      throw error;
    }
  }

  async queryBatch(packages: PackageCoordinate[]): Promise<
    Array<{
      packageName: string;
      version: string;
      direct: boolean;
      vulnerabilities: OsvVulnerabilitySummary[];
      cacheState: "fresh" | "stale";
    }>
  > {
    const results: Array<{
      packageName: string;
      version: string;
      direct: boolean;
      vulnerabilities: OsvVulnerabilitySummary[];
      cacheState: "fresh" | "stale";
    }> = [];

    for (const pkg of packages) {
      const response = await this.queryPackage(pkg);
      results.push({
        packageName: pkg.name,
        version: pkg.version,
        direct: pkg.direct,
        vulnerabilities: response.data,
        cacheState: response.cacheState === "miss" ? "fresh" : response.cacheState,
      });
    }
    return results;
  }
}
