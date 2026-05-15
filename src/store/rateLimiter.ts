import type { Redis } from "ioredis";
import { config } from "../config.js";
import type { Tier } from "../types/domain.js";

const WINDOW_SEC = 3600;

const INCR_WITH_EXPIRE_LUA = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("TTL", KEYS[1])
return {current, ttl}
`;

type MemoryCounter = {
  count: number;
  expiresAtMs: number;
};

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSec: number;
  resetAtEpochSec: number;
  currentCount: number;
}

export class RateLimiter {
  private readonly memoryCounters = new Map<string, MemoryCounter>();

  constructor(private readonly redis: Redis | null) {}

  async check(userId: string, tier: Tier): Promise<RateLimitDecision> {
    const limit = config.limits.hourlyByTier[tier];
    const key = this.keyForUser(userId);
    if (this.redis) {
      const result = (await this.redis.eval(
        INCR_WITH_EXPIRE_LUA,
        1,
        key,
        WINDOW_SEC.toString(),
      )) as [number, number];
      const currentCount = Number(result[0] ?? 0);
      const ttl = Math.max(0, Number(result[1] ?? 0));
      const remaining = Math.max(0, limit - currentCount);
      const allowed = currentCount <= limit;
      return {
        allowed,
        limit,
        remaining,
        retryAfterSec: allowed ? 0 : ttl,
        resetAtEpochSec: Math.floor(Date.now() / 1000) + ttl,
        currentCount,
      };
    }

    const now = Date.now();
    const existing = this.memoryCounters.get(key);
    if (!existing || now > existing.expiresAtMs) {
      const expiresAtMs = now + WINDOW_SEC * 1000;
      this.memoryCounters.set(key, { count: 1, expiresAtMs });
      return {
        allowed: true,
        limit,
        remaining: Math.max(0, limit - 1),
        retryAfterSec: 0,
        resetAtEpochSec: Math.floor(expiresAtMs / 1000),
        currentCount: 1,
      };
    }

    existing.count += 1;
    const remaining = Math.max(0, limit - existing.count);
    const allowed = existing.count <= limit;
    const retryAfterSec = allowed ? 0 : Math.ceil((existing.expiresAtMs - now) / 1000);
    return {
      allowed,
      limit,
      remaining,
      retryAfterSec,
      resetAtEpochSec: Math.floor(existing.expiresAtMs / 1000),
      currentCount: existing.count,
    };
  }

  private keyForUser(userId: string): string {
    const windowBucket = Math.floor(Date.now() / 1000 / WINDOW_SEC);
    return `${config.redis.prefix}:rate:${userId}:${windowBucket}`;
  }
}
