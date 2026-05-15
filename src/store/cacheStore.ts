import type { Redis } from "ioredis";
import type { CacheState } from "../types/domain.js";
import { config } from "../config.js";

interface CacheEnvelope<T> {
  value: T;
  cachedAtMs: number;
  freshUntilMs: number;
  staleUntilMs: number;
}

export interface CacheGetResult<T> {
  value: T;
  state: CacheState;
  cachedAtMs: number;
  freshUntilMs: number;
  staleUntilMs: number;
}

export class CacheStore {
  private readonly memory = new Map<string, CacheEnvelope<unknown>>();

  constructor(private readonly redis: Redis | null) {}

  async get<T>(key: string): Promise<CacheGetResult<T> | null> {
    const now = Date.now();
    const namespacedKey = this.withPrefix(key);

    let envelope: CacheEnvelope<T> | null = null;
    if (this.redis) {
      const raw = await this.redis.get(namespacedKey);
      if (!raw) {
        return null;
      }
      envelope = JSON.parse(raw) as CacheEnvelope<T>;
    } else {
      const fromMemory = this.memory.get(namespacedKey);
      if (!fromMemory) {
        return null;
      }
      envelope = fromMemory as CacheEnvelope<T>;
    }

    if (now > envelope.staleUntilMs) {
      if (!this.redis) {
        this.memory.delete(namespacedKey);
      }
      return null;
    }

    const state: CacheState = now <= envelope.freshUntilMs ? "fresh" : "stale";
    return {
      value: envelope.value,
      state,
      cachedAtMs: envelope.cachedAtMs,
      freshUntilMs: envelope.freshUntilMs,
      staleUntilMs: envelope.staleUntilMs,
    };
  }

  async set<T>(key: string, value: T, freshTtlSec: number, staleTtlSec: number): Promise<void> {
    const now = Date.now();
    const envelope: CacheEnvelope<T> = {
      value,
      cachedAtMs: now,
      freshUntilMs: now + freshTtlSec * 1000,
      staleUntilMs: now + staleTtlSec * 1000,
    };
    const namespacedKey = this.withPrefix(key);

    if (this.redis) {
      await this.redis.set(namespacedKey, JSON.stringify(envelope), "EX", staleTtlSec);
      return;
    }
    this.memory.set(namespacedKey, envelope as CacheEnvelope<unknown>);
  }

  private withPrefix(key: string): string {
    return `${config.redis.prefix}:cache:${key}`;
  }
}

export function cacheKey(parts: Array<string | number>): string {
  return parts
    .map((part) => String(part).trim().toLowerCase())
    .filter(Boolean)
    .join(":");
}
