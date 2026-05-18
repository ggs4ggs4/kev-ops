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

export type OsvBatchDependencyResult = {
  packageName: string;
  version: string;
  direct: boolean;
  vulnerabilities: OsvVulnerabilitySummary[];
  cacheState: "fresh" | "stale";
};

export type OsvBatchUnresolved = {
  packageName: string;
  version: string;
  direct: boolean;
  reason: string;
};

export type OsvBatchLookupResult = {
  results: OsvBatchDependencyResult[];
  unresolved: OsvBatchUnresolved[];
};

type NormalizedPackageCoordinate = {
  name: string;
  version: string;
  direct: boolean;
  ecosystem: string;
};

type OsvQueryRequest = {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
};

type OsvVulnerabilityRecord = {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
};

type OsvQueryResponse = {
  vulns?: OsvVulnerabilityRecord[];
  next_page_token?: string;
};

type OsvQueryBatchRequest = {
  queries: OsvQueryRequest[];
};

type OsvQueryBatchResponse = {
  results?: OsvQueryResponse[];
};

type BatchPageItem = {
  pkg: NormalizedPackageCoordinate;
  pageToken?: string;
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

function normalizeVulns(vulns: OsvVulnerabilityRecord[] | undefined): OsvVulnerabilitySummary[] {
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

function dedupeVulns(vulns: OsvVulnerabilitySummary[]): OsvVulnerabilitySummary[] {
  const byId = new Map<string, OsvVulnerabilitySummary>();
  for (const vuln of vulns) {
    const existing = byId.get(vuln.osvId);
    if (!existing) {
      byId.set(vuln.osvId, vuln);
      continue;
    }
    const aliasSet = new Set([...existing.aliases, ...vuln.aliases]);
    byId.set(vuln.osvId, {
      osvId: vuln.osvId,
      aliases: [...aliasSet],
      summary:
        existing.summary !== "No summary provided" ? existing.summary : vuln.summary,
      severity: existing.severity ?? vuln.severity,
    });
  }
  return [...byId.values()];
}

function toCacheKey(pkg: NormalizedPackageCoordinate): string {
  return cacheKey(["osv", pkg.ecosystem, pkg.name, pkg.version]);
}

function normalizeCoordinate(pkg: PackageCoordinate): NormalizedPackageCoordinate | null {
  const name = pkg.name.trim();
  const version = pkg.version.trim();
  const ecosystem = (pkg.ecosystem ?? "npm").trim() || "npm";
  if (!name || !version) {
    return null;
  }
  return {
    name,
    version,
    ecosystem,
    direct: pkg.direct,
  };
}

function dedupeCoordinates(packages: PackageCoordinate[]): NormalizedPackageCoordinate[] {
  const byKey = new Map<string, NormalizedPackageCoordinate>();
  for (const item of packages) {
    const normalized = normalizeCoordinate(item);
    if (!normalized) {
      continue;
    }
    const key = toCacheKey(normalized);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, normalized);
      continue;
    }
    if (normalized.direct && !existing.direct) {
      byKey.set(key, normalized);
    }
  }
  return [...byKey.values()];
}

function chunkArray<T>(items: T[], size: number): T[][] {
  const chunkSize = Math.max(1, size);
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += chunkSize) {
    chunks.push(items.slice(index, index + chunkSize));
  }
  return chunks;
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }
  const results = new Array<R>(items.length);
  const maxWorkers = Math.min(Math.max(1, concurrency), items.length);
  let nextIndex = 0;

  const runWorker = async (): Promise<void> => {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      if (currentIndex >= items.length) {
        return;
      }
      results[currentIndex] = await worker(items[currentIndex], currentIndex);
    }
  };

  await Promise.all(Array.from({ length: maxWorkers }, () => runWorker()));
  return results;
}

export class OsvClient {
  constructor(private readonly cache: CacheStore) {}

  async queryPackage(pkg: PackageCoordinate): Promise<ServiceResult<OsvVulnerabilitySummary[]>> {
    const normalized = normalizeCoordinate(pkg);
    if (!normalized) {
      return { data: [], cacheState: "fresh" };
    }

    const key = toCacheKey(normalized);
    const cached = await this.cache.get<OsvVulnerabilitySummary[]>(key);
    if (cached && cached.state === "fresh") {
      return { data: cached.value, cacheState: "fresh" };
    }

    try {
      const vulns = await this.fetchFullPackageVulnerabilities(normalized);
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

  async queryBatchDetailed(packages: PackageCoordinate[]): Promise<OsvBatchLookupResult> {
    const normalized = dedupeCoordinates(packages);
    if (normalized.length === 0) {
      return { results: [], unresolved: [] };
    }

    const resolvedByKey = new Map<string, OsvBatchDependencyResult>();
    const unresolved: OsvBatchUnresolved[] = [];
    const cacheChecks = await Promise.all(
      normalized.map(async (pkg) => ({
        pkg,
        key: toCacheKey(pkg),
        cached: await this.cache.get<OsvVulnerabilitySummary[]>(toCacheKey(pkg)),
      })),
    );

    const cacheMisses: NormalizedPackageCoordinate[] = [];
    for (const entry of cacheChecks) {
      if (entry.cached) {
        resolvedByKey.set(entry.key, {
          packageName: entry.pkg.name,
          version: entry.pkg.version,
          direct: entry.pkg.direct,
          vulnerabilities: entry.cached.value,
          cacheState: entry.cached.state === "fresh" ? "fresh" : "stale",
        });
        continue;
      }
      cacheMisses.push(entry.pkg);
    }

    const fromUpstream = await this.queryMissingPackages(cacheMisses);
    for (const result of fromUpstream.results) {
      const matchingSource =
        normalized.find(
          (item) =>
            item.name === result.packageName &&
            item.version === result.version &&
            item.direct === result.direct,
        ) ??
        normalized.find(
          (item) =>
            item.name === result.packageName &&
            item.version === result.version,
        );
      const normalizedKey = matchingSource
        ? toCacheKey(matchingSource)
        : cacheKey(["osv", "npm", result.packageName, result.version]);
      resolvedByKey.set(normalizedKey, result);
    }
    unresolved.push(...fromUpstream.unresolved);

    const orderedResults = normalized
      .map((pkg) => resolvedByKey.get(toCacheKey(pkg)))
      .filter((item): item is OsvBatchDependencyResult => Boolean(item));

    return {
      results: orderedResults,
      unresolved,
    };
  }

  async queryBatch(packages: PackageCoordinate[]): Promise<OsvBatchDependencyResult[]> {
    const detailed = await this.queryBatchDetailed(packages);
    return detailed.results;
  }

  private async queryMissingPackages(
    packages: NormalizedPackageCoordinate[],
  ): Promise<OsvBatchLookupResult> {
    if (packages.length === 0) {
      return { results: [], unresolved: [] };
    }

    const chunks = chunkArray(packages, config.upstream.osvBatchChunkSize);
    const chunkResults = await mapWithConcurrency(
      chunks,
      config.upstream.osvBatchConcurrency,
      async (chunk) => this.queryChunkWithFallback(chunk),
    );

    return {
      results: chunkResults.flatMap((entry) => entry.results),
      unresolved: chunkResults.flatMap((entry) => entry.unresolved),
    };
  }

  private async queryChunkWithFallback(
    chunk: NormalizedPackageCoordinate[],
  ): Promise<OsvBatchLookupResult> {
    try {
      return await this.queryChunkByBatchThenHydrate(chunk);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return this.queryChunkBySingleQueries(chunk, `batch_failed:${reason}`);
    }
  }

  private async queryChunkByBatchThenHydrate(
    chunk: NormalizedPackageCoordinate[],
  ): Promise<OsvBatchLookupResult> {
    const vulnerabilityIdsByKey = new Map<string, string[]>();
    const batchMissingResultKeys = new Set<string>();
    const unresolved: OsvBatchUnresolved[] = [];

    let pending: BatchPageItem[] = chunk.map((pkg) => ({ pkg }));
    for (let page = 0; pending.length > 0; page += 1) {
      if (page >= config.upstream.osvMaxPagesPerQuery) {
        for (const item of pending) {
          unresolved.push({
            packageName: item.pkg.name,
            version: item.pkg.version,
            direct: item.pkg.direct,
            reason: "batch_pagination_limit_reached",
          });
        }
        break;
      }

      const response = await fetchJson<OsvQueryBatchResponse>(
        config.upstream.osvQueryBatchUrl,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            "User-Agent": "kev-ops-mcp/1.0",
          },
          body: JSON.stringify({
            queries: pending.map((entry) => ({
              package: {
                name: entry.pkg.name,
                ecosystem: entry.pkg.ecosystem,
              },
              version: entry.pkg.version,
              ...(entry.pageToken ? { page_token: entry.pageToken } : {}),
            })),
          } satisfies OsvQueryBatchRequest),
          timeoutMs: config.upstream.osvQueryBatchTimeoutMs,
        },
      );

      const nextPending: BatchPageItem[] = [];
      for (let index = 0; index < pending.length; index += 1) {
        const requestItem = pending[index];
        const result = response.results?.[index];
        if (!result) {
          batchMissingResultKeys.add(toCacheKey(requestItem.pkg));
          continue;
        }

        const collectedIds =
          vulnerabilityIdsByKey.get(toCacheKey(requestItem.pkg)) ?? [];
        for (const vuln of result.vulns ?? []) {
          if (typeof vuln.id === "string" && vuln.id.trim()) {
            collectedIds.push(vuln.id);
          }
        }
        vulnerabilityIdsByKey.set(toCacheKey(requestItem.pkg), collectedIds);

        if (result.next_page_token) {
          nextPending.push({ pkg: requestItem.pkg, pageToken: result.next_page_token });
        }
      }
      pending = nextPending;
    }

    const needsDetails = chunk.filter((pkg) => {
      const ids = vulnerabilityIdsByKey.get(toCacheKey(pkg)) ?? [];
      return ids.length > 0;
    });
    const detailResults = new Map<string, OsvVulnerabilitySummary[]>();
    const detailUnresolved = new Map<string, string>();

    await mapWithConcurrency(
      needsDetails,
      config.upstream.osvBatchFallbackConcurrency,
      async (pkg) => {
        try {
          const vulnerabilities = await this.fetchFullPackageVulnerabilities(pkg);
          detailResults.set(toCacheKey(pkg), vulnerabilities);
        } catch (error) {
          detailUnresolved.set(
            toCacheKey(pkg),
            error instanceof Error ? error.message : String(error),
          );
        }
      },
    );

    const results: OsvBatchDependencyResult[] = [];
    await Promise.all(
      chunk.map(async (pkg) => {
        const key = toCacheKey(pkg);
        if (batchMissingResultKeys.has(key)) {
          return;
        }
        if (detailUnresolved.has(key)) {
          const fallbackIds = [...new Set(vulnerabilityIdsByKey.get(key) ?? [])];
          results.push({
            packageName: pkg.name,
            version: pkg.version,
            direct: pkg.direct,
            vulnerabilities: fallbackIds.map((id) => ({
              osvId: id,
              aliases: [],
              summary: "Partial finding from OSV batch response; detail fetch failed.",
              severity: null,
            })),
            cacheState: "stale",
          });
          unresolved.push({
            packageName: pkg.name,
            version: pkg.version,
            direct: pkg.direct,
            reason: `detail_lookup_failed:${detailUnresolved.get(key)}`,
          });
          return;
        }

        const vulnerabilities = detailResults.get(key) ?? [];
        await this.cache.set(
          key,
          vulnerabilities,
          config.cacheTtls.osv.freshSec,
          config.cacheTtls.osv.staleSec,
        );
        results.push({
          packageName: pkg.name,
          version: pkg.version,
          direct: pkg.direct,
          vulnerabilities,
          cacheState: "fresh",
        });
      }),
    );

    const missingBatchItems = chunk.filter((pkg) =>
      batchMissingResultKeys.has(toCacheKey(pkg)),
    );
    const fallbackForMissing = await this.queryChunkBySingleQueries(
      missingBatchItems,
      "batch_missing_result",
    );
    results.push(...fallbackForMissing.results);
    unresolved.push(...fallbackForMissing.unresolved);

    return { results, unresolved };
  }

  private async queryChunkBySingleQueries(
    chunk: NormalizedPackageCoordinate[],
    reasonPrefix: string,
  ): Promise<OsvBatchLookupResult> {
    const singleResults = await mapWithConcurrency(
      chunk,
      config.upstream.osvBatchFallbackConcurrency,
      async (pkg) => {
        try {
          const response = await this.queryPackage(pkg);
          return {
            result: {
              packageName: pkg.name,
              version: pkg.version,
              direct: pkg.direct,
              vulnerabilities: response.data,
              cacheState:
                response.cacheState === "fresh" ? "fresh" : "stale",
            } satisfies OsvBatchDependencyResult,
            unresolved: null,
          };
        } catch (error) {
          return {
            result: null,
            unresolved: {
              packageName: pkg.name,
              version: pkg.version,
              direct: pkg.direct,
              reason: `${reasonPrefix};single_failed:${error instanceof Error ? error.message : String(error)}`,
            } satisfies OsvBatchUnresolved,
          };
        }
      },
    );

    return {
      results: singleResults
        .map((item) => item.result)
        .filter((item): item is OsvBatchDependencyResult => Boolean(item)),
      unresolved: singleResults
        .map((item) => item.unresolved)
        .filter((item): item is OsvBatchUnresolved => Boolean(item)),
    };
  }

  private async fetchFullPackageVulnerabilities(
    pkg: NormalizedPackageCoordinate,
  ): Promise<OsvVulnerabilitySummary[]> {
    const all: OsvVulnerabilitySummary[] = [];
    let pageToken: string | undefined;

    for (let page = 0; page < config.upstream.osvMaxPagesPerQuery; page += 1) {
      const payload = await fetchJson<OsvQueryResponse>(config.upstream.osvQueryUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": "kev-ops-mcp/1.0",
        },
        body: JSON.stringify({
          package: {
            name: pkg.name,
            ecosystem: pkg.ecosystem,
          },
          version: pkg.version,
          ...(pageToken ? { page_token: pageToken } : {}),
        } satisfies OsvQueryRequest),
        timeoutMs: config.upstream.osvQueryTimeoutMs,
      });

      all.push(...normalizeVulns(payload.vulns));
      if (!payload.next_page_token) {
        return dedupeVulns(all);
      }
      pageToken = payload.next_page_token;
    }

    throw new Error("query_pagination_limit_reached");
  }
}
