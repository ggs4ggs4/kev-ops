import { config } from "../config.js";
import type { EpssSnapshot } from "../types/domain.js";
import type { CacheStore } from "../store/cacheStore.js";
import { cacheKey } from "../store/cacheStore.js";
import { fetchJson } from "./http.js";
import type { ServiceResult } from "./types.js";

type EpssApiResponse = {
  data?: Array<{
    cve?: string;
    epss?: string;
    percentile?: string;
    date?: string;
  }>;
};

export class EpssClient {
  constructor(private readonly cache: CacheStore) {}

  async getScore(cveId: string): Promise<ServiceResult<EpssSnapshot>> {
    const normalized = cveId.toUpperCase();
    const key = cacheKey(["epss", "cve", normalized]);
    const cached = await this.cache.get<EpssSnapshot>(key);
    if (cached && cached.state === "fresh") {
      return { data: cached.value, cacheState: "fresh" };
    }

    try {
      const url = new URL(config.upstream.epssApiBase);
      url.searchParams.set("cve", normalized);
      const payload = await fetchJson<EpssApiResponse>(url.toString(), {
        headers: {
          Accept: "application/json",
          "User-Agent": "kev-ops-mcp/1.0",
        },
        timeoutMs: 15000,
      });

      const row = payload.data?.[0];
      const snapshot: EpssSnapshot = {
        cveId: normalized,
        epss: row?.epss ? Number.parseFloat(row.epss) : null,
        percentile: row?.percentile ? Number.parseFloat(row.percentile) : null,
        date: row?.date ?? null,
      };
      await this.cache.set(
        key,
        snapshot,
        config.cacheTtls.epss.freshSec,
        config.cacheTtls.epss.staleSec,
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
