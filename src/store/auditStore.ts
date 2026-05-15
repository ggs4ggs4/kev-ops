import type { Redis } from "ioredis";
import { randomUUID } from "node:crypto";
import { config } from "../config.js";
import type { AuditRecord } from "../types/domain.js";

type AuditFilter = {
  userId?: string;
  toolName?: string;
  limit?: number;
};

export class AuditStore {
  private readonly memoryRecords: AuditRecord[] = [];

  constructor(private readonly redis: Redis | null) {}

  async append(record: Omit<AuditRecord, "id" | "timestamp">): Promise<AuditRecord> {
    const finalRecord: AuditRecord = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...record,
    };
    const listKey = this.listKey();

    if (this.redis) {
      await this.redis.pipeline().lpush(listKey, JSON.stringify(finalRecord)).ltrim(listKey, 0, config.audit.maxRecords - 1).exec();
      return finalRecord;
    }

    this.memoryRecords.unshift(finalRecord);
    if (this.memoryRecords.length > config.audit.maxRecords) {
      this.memoryRecords.splice(config.audit.maxRecords);
    }
    return finalRecord;
  }

  async query(filter: AuditFilter = {}): Promise<AuditRecord[]> {
    const limit = Math.max(1, Math.min(filter.limit ?? 50, 500));
    let records: AuditRecord[] = [];
    if (this.redis) {
      const rows = await this.redis.lrange(this.listKey(), 0, Math.max(limit * 4, 200));
      records = rows
        .map((row: string) => {
          try {
            return JSON.parse(row) as AuditRecord;
          } catch {
            return null;
          }
        })
        .filter((item: AuditRecord | null): item is AuditRecord => item !== null);
    } else {
      records = [...this.memoryRecords];
    }

    const filtered = records.filter((record) => {
      if (filter.userId && record.userId !== filter.userId) {
        return false;
      }
      if (filter.toolName && record.toolName !== filter.toolName) {
        return false;
      }
      return true;
    });

    return filtered.slice(0, limit);
  }

  private listKey(): string {
    return `${config.redis.prefix}:audit:records`;
  }
}
