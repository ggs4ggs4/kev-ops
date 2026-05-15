import { Redis } from "ioredis";
import { logger } from "../core/logger.js";

export async function createRedisClient(redisUrl: string | undefined): Promise<Redis | null> {
  if (!redisUrl) {
    logger.info("REDIS_URL not set, using in-memory stores");
    return null;
  }

  const client = new Redis(redisUrl, {
    maxRetriesPerRequest: 2,
    enableReadyCheck: true,
    lazyConnect: true,
  });

  try {
    await client.connect();
    await client.ping();
    logger.info("Connected to Redis");
    return client;
  } catch (error) {
    logger.warn({ err: error }, "Failed to connect to Redis, falling back to in-memory stores");
    try {
      await client.quit();
    } catch {
      // noop
    }
    return null;
  }
}
