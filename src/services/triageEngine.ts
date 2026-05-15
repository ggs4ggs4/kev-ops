import { config } from "../config.js";
import type {
  LockfileScanResult,
  SourceCitation,
  TriageVerdict,
} from "../types/domain.js";
import { EpssClient } from "./epssClient.js";
import { KevClient } from "./kevClient.js";
import { NvdClient } from "./nvdClient.js";

export interface TriageResultWithMeta {
  verdict: TriageVerdict;
  cacheSignals: string[];
}

function riskPriority(score: number): TriageVerdict["priority"] {
  if (score >= 80) {
    return "patch_now";
  }
  if (score >= 60) {
    return "patch_24h";
  }
  if (score >= 40) {
    return "patch_7d";
  }
  return "monitor";
}

function summarizePriority(priority: TriageVerdict["priority"]): string {
  switch (priority) {
    case "patch_now":
      return "Immediate patch is recommended.";
    case "patch_24h":
      return "Patch within 24 hours is recommended.";
    case "patch_7d":
      return "Patch within the next 7 days is recommended.";
    default:
      return "Monitor and plan patching in a routine cycle.";
  }
}

function clamp(min: number, value: number, max: number): number {
  return Math.max(min, Math.min(value, max));
}

export class TriageEngine {
  constructor(
    private readonly nvdClient: NvdClient,
    private readonly kevClient: KevClient,
    private readonly epssClient: EpssClient,
  ) {}

  async triageCve(
    cveId: string,
    affectedPackagesCount: number,
  ): Promise<TriageResultWithMeta> {
    const [nvd, kev, epss] = await Promise.all([
      this.nvdClient.getCve(cveId),
      this.kevClient.getByCve(cveId),
      this.epssClient.getScore(cveId),
    ]);
    const cacheSignals = [
      `nvd:${nvd.cacheState}`,
      `kev:${kev.cacheState}`,
      `epss:${epss.cacheState}`,
    ];

    const cvss = nvd.data?.cvssBaseScore ?? 0;
    const kevListed = Boolean(kev.data);
    const kevRansomwareKnown =
      kev.data?.knownRansomwareCampaignUse?.toLowerCase() === "known";
    const epssScore = epss.data.epss ?? 0;

    const score = clamp(
      0,
      Math.round(
        cvss * 5 +
          (kevListed ? 30 : 0) +
          (kevRansomwareKnown ? 20 : 0) +
          epssScore * 20 +
          Math.min(affectedPackagesCount * 2, 20),
      ),
      100,
    );

    const confirmations: string[] = [];
    const contradictions: string[] = [];
    if (kevListed && cvss >= 9) {
      confirmations.push("KEV-listed and high CVSS indicate active severe risk.");
    }
    if (kevListed && epssScore >= 0.7) {
      confirmations.push("KEV and high EPSS both indicate near-term exploitation likelihood.");
    }
    if (!kevListed && cvss >= 9 && epssScore < 0.2) {
      contradictions.push("High CVSS but low exploit probability and no KEV listing.");
    }
    if ((cvss < 7 || !nvd.data) && (kevListed || epssScore >= 0.8)) {
      contradictions.push("Moderate technical severity but strong real-world exploitation signals.");
    }

    const citations: SourceCitation[] = [];
    if (nvd.data) {
      citations.push({
        source: "NVD",
        key: nvd.data.cveId,
        detail: `CVSS=${nvd.data.cvssBaseScore ?? "n/a"} severity=${nvd.data.cvssSeverity ?? "n/a"}`,
      });
    } else {
      citations.push({
        source: "NVD",
        key: cveId.toUpperCase(),
        detail: "No NVD entry returned for this identifier.",
      });
    }
    if (kev.data) {
      citations.push({
        source: "CISA_KEV",
        key: kev.data.cveId,
        detail: `dateAdded=${kev.data.dateAdded} ransomware=${kev.data.knownRansomwareCampaignUse}`,
      });
    } else {
      citations.push({
        source: "CISA_KEV",
        key: cveId.toUpperCase(),
        detail: "Not listed in KEV catalog.",
      });
    }
    citations.push({
      source: "FIRST_EPSS",
      key: cveId.toUpperCase(),
      detail: `epss=${epss.data.epss ?? "n/a"} percentile=${epss.data.percentile ?? "n/a"} date=${epss.data.date ?? "n/a"}`,
    });

    const priority = riskPriority(score);
    const verdict: TriageVerdict = {
      cveId: cveId.toUpperCase(),
      riskScore: score,
      priority,
      summary: summarizePriority(priority),
      confirmations,
      contradictions,
      recommendedActions: [
        priority === "patch_now"
          ? "Patch immediately and add temporary mitigation until rollout completes."
          : "Schedule patch according to the priority window and verify deployment coverage.",
        kevListed
          ? "Treat as exploited in the wild and prioritize internet-facing assets first."
          : "Validate exploitability in your environment before escalating.",
        affectedPackagesCount > 0
          ? `Review ${affectedPackagesCount} impacted dependency occurrence(s) from lockfile scan.`
          : "Map affected packages in your dependency graph if package context is available.",
      ],
      citations,
      signals: {
        cvssBaseScore: nvd.data?.cvssBaseScore ?? null,
        kevListed,
        kevRansomwareKnown,
        epss: epss.data.epss,
        affectedPackagesCount,
      },
    };
    return { verdict, cacheSignals };
  }

  async buildPatchQueue(scan: LockfileScanResult): Promise<{
    queue: TriageVerdict[];
    droppedCves: string[];
    consideredCveCount: number;
    cacheSignals: string[];
  }> {
    const cveFrequency = new Map<string, number>();
    for (const finding of scan.findings) {
      for (const vuln of finding.vulnerabilities) {
        for (const alias of vuln.aliases) {
          if (!alias.toUpperCase().startsWith("CVE-")) {
            continue;
          }
          const normalized = alias.toUpperCase();
          cveFrequency.set(normalized, (cveFrequency.get(normalized) ?? 0) + 1);
        }
      }
    }

    const allCves = [...cveFrequency.keys()];
    const capped = allCves.slice(0, config.limits.patchQueueMaxCves);
    const droppedCves = allCves.slice(config.limits.patchQueueMaxCves);
    const triaged = await Promise.all(
      capped.map((cve) => this.triageCve(cve, cveFrequency.get(cve) ?? 0)),
    );
    const queue = triaged
      .map((item) => item.verdict)
      .sort((a, b) => b.riskScore - a.riskScore);
    return {
      queue,
      droppedCves,
      consideredCveCount: capped.length,
      cacheSignals: triaged.flatMap((item) => item.cacheSignals),
    };
  }
}
