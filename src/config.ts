import "dotenv/config";
import { z } from "zod";
import type { Tier } from "./types/domain.js";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  MCP_PATH: z.string().default("/mcp"),
  PUBLIC_BASE_URL: z.string().url().optional(),
  ALLOWED_HOSTS: z.string().optional(),

  AUTH_REQUIRED: z
    .string()
    .default("true")
    .transform((value) => value.toLowerCase() !== "false"),
  AUTH0_ISSUER: z.string().url(),
  AUTH0_AUDIENCE: z.string().url(),
  AUTH0_AUDIENCE_ALIASES: z.string().default(""),
  AUTH0_RESOURCE: z.string().url().optional(),
  AUTH0_JWKS_URI: z.string().url().optional(),
  AUTH0_TIER_CLAIM: z.string().default("https://kevops.example.com/tier"),
  AUTH0_ROLES_CLAIM: z.string().default("https://kevops.example.com/roles"),
  AUTH0_DEFAULT_TIER: z.enum(["free", "premium", "analyst"]).default("free"),
  AUTH_REQUIRED_SCOPES: z.string().default(""),

  REDIS_URL: z.string().url().optional(),
  REDIS_PREFIX: z.string().default("kevops"),

  RATE_LIMIT_FREE_HOURLY: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_PREMIUM_HOURLY: z.coerce.number().int().positive().default(150),
  RATE_LIMIT_ANALYST_HOURLY: z.coerce.number().int().positive().default(500),

  CACHE_NVD_TTL_SEC: z.coerce.number().int().positive().default(3600),
  CACHE_NVD_STALE_SEC: z.coerce.number().int().positive().default(86400),
  CACHE_KEV_TTL_SEC: z.coerce.number().int().positive().default(1800),
  CACHE_KEV_STALE_SEC: z.coerce.number().int().positive().default(86400),
  CACHE_EPSS_TTL_SEC: z.coerce.number().int().positive().default(86400),
  CACHE_EPSS_STALE_SEC: z.coerce.number().int().positive().default(604800),
  CACHE_OSV_TTL_SEC: z.coerce.number().int().positive().default(43200),
  CACHE_OSV_STALE_SEC: z.coerce.number().int().positive().default(259200),

  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"])
    .default("info"),

  NVD_API_BASE: z.string().url().default("https://services.nvd.nist.gov/rest/json/cves/2.0"),
  NVD_API_KEY: z.string().optional(),
  KEV_FEED_URL: z
    .string()
    .url()
    .default("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
  EPSS_API_BASE: z.string().url().default("https://api.first.org/data/v1/epss"),
  OSV_QUERY_URL: z.string().url().default("https://api.osv.dev/v1/query"),
  OSV_QUERY_BATCH_URL: z.string().url().default("https://api.osv.dev/v1/querybatch"),
  OSV_QUERY_TIMEOUT_MS: z.coerce.number().int().positive().default(20000),
  OSV_QUERY_BATCH_TIMEOUT_MS: z.coerce.number().int().positive().default(30000),
  OSV_BATCH_CHUNK_SIZE: z.coerce.number().int().positive().default(40),
  OSV_BATCH_CONCURRENCY: z.coerce.number().int().positive().default(4),
  OSV_BATCH_FALLBACK_CONCURRENCY: z.coerce.number().int().positive().default(6),
  OSV_MAX_PAGES_PER_QUERY: z.coerce.number().int().positive().default(4),

  LOCKFILE_SCAN_MAX_DEPS_PREMIUM: z.coerce.number().int().positive().default(80),
  LOCKFILE_SCAN_MAX_DEPS_ANALYST: z.coerce.number().int().positive().default(300),
  PATCH_QUEUE_MAX_CVES: z.coerce.number().int().positive().default(40),

  AUDIT_LOG_MAX_RECORDS: z.coerce.number().int().positive().default(5000),
});

const parsed = envSchema.parse(process.env);

const authRequiredScopes = parsed.AUTH_REQUIRED_SCOPES.split(",")
  .map((scope) => scope.trim())
  .filter(Boolean);
const authAudienceAliases = parsed.AUTH0_AUDIENCE_ALIASES.split(",")
  .map((audience) => audience.trim())
  .filter(Boolean);

const publicBaseUrl = parsed.PUBLIC_BASE_URL ?? `http://localhost:${parsed.PORT}`;
const allowedHosts = parsed.ALLOWED_HOSTS
  ? parsed.ALLOWED_HOSTS.split(",").map((value) => value.trim()).filter(Boolean)
  : [];

export const config = {
  env: parsed.NODE_ENV,
  host: parsed.HOST,
  port: parsed.PORT,
  mcpPath: parsed.MCP_PATH,
  publicBaseUrl,
  allowedHosts,
  auth: {
    required: parsed.AUTH_REQUIRED,
    issuer: parsed.AUTH0_ISSUER,
    audience: parsed.AUTH0_AUDIENCE,
    acceptedAudiences: [parsed.AUTH0_AUDIENCE, ...authAudienceAliases],
    resource: parsed.AUTH0_RESOURCE ?? parsed.AUTH0_AUDIENCE,
    jwksUri: parsed.AUTH0_JWKS_URI ?? new URL(".well-known/jwks.json", parsed.AUTH0_ISSUER).href,
    tierClaim: parsed.AUTH0_TIER_CLAIM,
    rolesClaim: parsed.AUTH0_ROLES_CLAIM,
    defaultTier: parsed.AUTH0_DEFAULT_TIER as Tier,
    requiredScopes: authRequiredScopes,
  },
  redis: {
    url: parsed.REDIS_URL,
    prefix: parsed.REDIS_PREFIX,
  },
  limits: {
    hourlyByTier: {
      free: parsed.RATE_LIMIT_FREE_HOURLY,
      premium: parsed.RATE_LIMIT_PREMIUM_HOURLY,
      analyst: parsed.RATE_LIMIT_ANALYST_HOURLY,
    } satisfies Record<Tier, number>,
    lockfileScanMaxDepsByTier: {
      free: 0,
      premium: parsed.LOCKFILE_SCAN_MAX_DEPS_PREMIUM,
      analyst: parsed.LOCKFILE_SCAN_MAX_DEPS_ANALYST,
    } satisfies Record<Tier, number>,
    patchQueueMaxCves: parsed.PATCH_QUEUE_MAX_CVES,
  },
  cacheTtls: {
    nvd: { freshSec: parsed.CACHE_NVD_TTL_SEC, staleSec: parsed.CACHE_NVD_STALE_SEC },
    kev: { freshSec: parsed.CACHE_KEV_TTL_SEC, staleSec: parsed.CACHE_KEV_STALE_SEC },
    epss: { freshSec: parsed.CACHE_EPSS_TTL_SEC, staleSec: parsed.CACHE_EPSS_STALE_SEC },
    osv: { freshSec: parsed.CACHE_OSV_TTL_SEC, staleSec: parsed.CACHE_OSV_STALE_SEC },
  },
  logLevel: parsed.LOG_LEVEL,
  upstream: {
    nvdApiBase: parsed.NVD_API_BASE,
    nvdApiKey: parsed.NVD_API_KEY,
    kevFeedUrl: parsed.KEV_FEED_URL,
    epssApiBase: parsed.EPSS_API_BASE,
    osvQueryUrl: parsed.OSV_QUERY_URL,
    osvQueryBatchUrl: parsed.OSV_QUERY_BATCH_URL,
    osvQueryTimeoutMs: parsed.OSV_QUERY_TIMEOUT_MS,
    osvQueryBatchTimeoutMs: parsed.OSV_QUERY_BATCH_TIMEOUT_MS,
    osvBatchChunkSize: parsed.OSV_BATCH_CHUNK_SIZE,
    osvBatchConcurrency: parsed.OSV_BATCH_CONCURRENCY,
    osvBatchFallbackConcurrency: parsed.OSV_BATCH_FALLBACK_CONCURRENCY,
    osvMaxPagesPerQuery: parsed.OSV_MAX_PAGES_PER_QUERY,
  },
  audit: {
    maxRecords: parsed.AUDIT_LOG_MAX_RECORDS,
  },
} as const;

export type AppConfig = typeof config;
