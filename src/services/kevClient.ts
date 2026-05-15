import { config } from "../config.js";
import type { KevEntry } from "../types/domain.js";
import type { CacheStore } from "../store/cacheStore.js";
import { cacheKey } from "../store/cacheStore.js";
import { fetchJson } from "./http.js";
import type { ServiceResult } from "./types.js";

type KevFeedPayload = {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
    notes: string;
  }>;
};

type KevCatalog = {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
};

export class KevClient {
  constructor(private readonly cache: CacheStore) {}

  async getCatalog(): Promise<ServiceResult<KevCatalog>> {
    const key = cacheKey(["kev", "catalog"]);
    const cached = await this.cache.get<KevCatalog>(key);
    if (cached && cached.state === "fresh") {
      return { data: cached.value, cacheState: "fresh" };
    }

    try {
      const payload = await fetchJson<KevFeedPayload>(config.upstream.kevFeedUrl, {
        headers: {
          "User-Agent": "kev-ops-mcp/1.0",
          Accept: "application/json",
        },
        timeoutMs: 15000,
      });

      const catalog: KevCatalog = {
        title: payload.title,
        catalogVersion: payload.catalogVersion,
        dateReleased: payload.dateReleased,
        count: payload.count,
        vulnerabilities: payload.vulnerabilities.map((item) => ({
          cveId: item.cveID,
          vendorProject: item.vendorProject,
          product: item.product,
          vulnerabilityName: item.vulnerabilityName,
          dateAdded: item.dateAdded,
          shortDescription: item.shortDescription,
          requiredAction: item.requiredAction,
          dueDate: item.dueDate,
          knownRansomwareCampaignUse: item.knownRansomwareCampaignUse,
          notes: item.notes,
        })),
      };

      await this.cache.set(
        key,
        catalog,
        config.cacheTtls.kev.freshSec,
        config.cacheTtls.kev.staleSec,
      );
      return { data: catalog, cacheState: "fresh" };
    } catch (error) {
      if (cached) {
        return { data: cached.value, cacheState: "stale" };
      }
      throw error;
    }
  }

  async getByCve(cveId: string): Promise<ServiceResult<KevEntry | null>> {
    const catalog = await this.getCatalog();
    const found = catalog.data.vulnerabilities.find(
      (entry) => entry.cveId.toUpperCase() === cveId.toUpperCase(),
    );
    return { data: found ?? null, cacheState: catalog.cacheState };
  }

  async listRecent(limit = 10): Promise<ServiceResult<KevEntry[]>> {
    const catalog = await this.getCatalog();
    const sorted = [...catalog.data.vulnerabilities].sort((a, b) =>
      b.dateAdded.localeCompare(a.dateAdded),
    );
    return {
      data: sorted.slice(0, Math.max(1, Math.min(limit, 100))),
      cacheState: catalog.cacheState,
    };
  }
}
