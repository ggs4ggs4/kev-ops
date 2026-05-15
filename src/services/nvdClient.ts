import { config } from "../config.js";
import type { NvdSnapshot } from "../types/domain.js";
import type { CacheStore } from "../store/cacheStore.js";
import { cacheKey } from "../store/cacheStore.js";
import { fetchJson } from "./http.js";
import type { ServiceResult } from "./types.js";

type NvdApiResponse = {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      published?: string;
      lastModified?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      references?: Array<{ url?: string }>;
      metrics?: Record<string, Array<{ cvssData?: Record<string, unknown> }>>;
    };
  }>;
};

function firstDescription(descriptions: Array<{ lang?: string; value?: string }> | undefined): string {
  if (!descriptions || descriptions.length === 0) {
    return "No description available.";
  }
  const english = descriptions.find((item) => item.lang === "en" && item.value);
  return (english?.value ?? descriptions[0]?.value ?? "No description available.").trim();
}

function pickCvss(metrics: Record<string, Array<{ cvssData?: Record<string, unknown> }>> | undefined): {
  score: number | null;
  severity: string | null;
  attackVector: string | null;
} {
  if (!metrics) {
    return { score: null, severity: null, attackVector: null };
  }

  const orderedMetricKeys = [
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
  ];
  for (const key of orderedMetricKeys) {
    const metric = metrics[key];
    if (!metric || metric.length === 0) {
      continue;
    }
    const cvssData = metric[0]?.cvssData ?? {};
    const score = typeof cvssData.baseScore === "number" ? cvssData.baseScore : null;
    const severity =
      typeof cvssData.baseSeverity === "string" ? cvssData.baseSeverity : null;
    const attackVector =
      typeof cvssData.attackVector === "string" ? cvssData.attackVector : null;
    return { score, severity, attackVector };
  }

  return { score: null, severity: null, attackVector: null };
}

export class NvdClient {
  constructor(private readonly cache: CacheStore) {}

  async getCve(cveId: string): Promise<ServiceResult<NvdSnapshot | null>> {
    const normalized = cveId.toUpperCase();
    const key = cacheKey(["nvd", "cve", normalized]);
    const cached = await this.cache.get<NvdSnapshot | null>(key);
    if (cached && cached.state === "fresh") {
      return { data: cached.value, cacheState: "fresh" };
    }

    try {
      const url = new URL(config.upstream.nvdApiBase);
      url.searchParams.set("cveId", normalized);

      const headers: Record<string, string> = {
        Accept: "application/json",
        "User-Agent": "kev-ops-mcp/1.0",
      };
      if (config.upstream.nvdApiKey) {
        headers.apiKey = config.upstream.nvdApiKey;
      }

      const payload = await fetchJson<NvdApiResponse>(url.toString(), {
        headers,
        timeoutMs: 20000,
      });

      const cve = payload.vulnerabilities?.[0]?.cve;
      if (!cve?.id) {
        await this.cache.set(
          key,
          null,
          config.cacheTtls.nvd.freshSec,
          config.cacheTtls.nvd.staleSec,
        );
        return { data: null, cacheState: "fresh" };
      }

      const cvss = pickCvss(cve.metrics);
      const snapshot: NvdSnapshot = {
        cveId: cve.id,
        description: firstDescription(cve.descriptions),
        published: cve.published ?? "",
        lastModified: cve.lastModified ?? "",
        cvssBaseScore: cvss.score,
        cvssSeverity: cvss.severity,
        attackVector: cvss.attackVector,
        references: (cve.references ?? [])
          .map((reference) => reference.url)
          .filter((url): url is string => Boolean(url))
          .slice(0, 15),
      };

      await this.cache.set(
        key,
        snapshot,
        config.cacheTtls.nvd.freshSec,
        config.cacheTtls.nvd.staleSec,
      );
      return { data: snapshot, cacheState: "fresh" };
    } catch (error) {
      if (cached) {
        return { data: cached.value, cacheState: "stale" };
      }
      throw error;
    }
  }
}
