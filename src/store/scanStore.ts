import { randomUUID } from "node:crypto";
import type { LockfileScanResult } from "../types/domain.js";

export class ScanStore {
  private readonly byId = new Map<string, LockfileScanResult>();
  private readonly orderedIds: string[] = [];
  private readonly maxRecords = 200;

  save(result: Omit<LockfileScanResult, "scanId" | "createdAt">): LockfileScanResult {
    const scan: LockfileScanResult = {
      scanId: randomUUID(),
      createdAt: new Date().toISOString(),
      ...result,
    };
    this.byId.set(scan.scanId, scan);
    this.orderedIds.unshift(scan.scanId);
    if (this.orderedIds.length > this.maxRecords) {
      const dropped = this.orderedIds.pop();
      if (dropped) {
        this.byId.delete(dropped);
      }
    }
    return scan;
  }

  get(scanId: string): LockfileScanResult | null {
    return this.byId.get(scanId) ?? null;
  }

  latest(): LockfileScanResult | null {
    const first = this.orderedIds[0];
    if (!first) {
      return null;
    }
    return this.byId.get(first) ?? null;
  }
}
