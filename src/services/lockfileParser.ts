import yaml from "js-yaml";
import type { PackageCoordinate } from "./osvClient.js";

type SupportedLockfile = "package-lock" | "pnpm-lock" | "yarn-lock";

function detectLockfileType(content: string): SupportedLockfile {
  const trimmed = content.trimStart();
  if (trimmed.startsWith("{")) {
    return "package-lock";
  }
  if (trimmed.includes("lockfileVersion:") && trimmed.includes("importers:")) {
    return "pnpm-lock";
  }
  return "yarn-lock";
}

function addDependency(
  target: Map<string, PackageCoordinate>,
  item: PackageCoordinate,
): void {
  const key = `${item.name}@${item.version}`;
  const existing = target.get(key);
  if (!existing) {
    target.set(key, item);
    return;
  }
  if (item.direct && !existing.direct) {
    target.set(key, item);
  }
}

function parsePackageLock(content: string): PackageCoordinate[] {
  const parsed = JSON.parse(content) as {
    packages?: Record<string, { version?: string }>;
    dependencies?: Record<string, unknown>;
    lockfileVersion?: number;
  };

  const directNames = new Set(Object.keys(parsed.dependencies ?? {}));
  const deps = new Map<string, PackageCoordinate>();

  if (parsed.packages && typeof parsed.packages === "object") {
    for (const [packagePath, value] of Object.entries(parsed.packages)) {
      if (!packagePath.includes("node_modules/")) {
        continue;
      }
      const match = packagePath.match(/node_modules\/(.+)$/);
      if (!match) {
        continue;
      }
      const name = match[1];
      const version = value?.version;
      if (!name || !version) {
        continue;
      }
      addDependency(deps, {
        name,
        version,
        direct: directNames.has(name),
        ecosystem: "npm",
      });
    }
    return [...deps.values()];
  }

  const walkLegacy = (
    tree: Record<string, unknown> | undefined,
    isDirectLevel: boolean,
  ): void => {
    if (!tree) {
      return;
    }
    for (const [name, rawNode] of Object.entries(tree)) {
      const node = rawNode as {
        version?: string;
        dependencies?: Record<string, unknown>;
      };
      if (node.version) {
        addDependency(deps, {
          name,
          version: node.version,
          direct: isDirectLevel,
          ecosystem: "npm",
        });
      }
      walkLegacy(node.dependencies, false);
    }
  };
  walkLegacy(parsed.dependencies, true);
  return [...deps.values()];
}

function parsePnpmLock(content: string): PackageCoordinate[] {
  const parsed = yaml.load(content) as {
    packages?: Record<string, { version?: string }>;
    importers?: Record<
      string,
      {
        dependencies?: Record<string, unknown>;
        devDependencies?: Record<string, unknown>;
        optionalDependencies?: Record<string, unknown>;
      }
    >;
  };
  const directNames = new Set<string>();
  const rootImporter = parsed.importers?.["."];
  const directSources = [
    rootImporter?.dependencies,
    rootImporter?.devDependencies,
    rootImporter?.optionalDependencies,
  ];
  for (const source of directSources) {
    for (const name of Object.keys(source ?? {})) {
      directNames.add(name);
    }
  }

  const deps = new Map<string, PackageCoordinate>();
  for (const [rawKey, value] of Object.entries(parsed.packages ?? {})) {
    const clean = rawKey.startsWith("/") ? rawKey.slice(1) : rawKey;
    const atIndex = clean.lastIndexOf("@");
    if (atIndex <= 0) {
      continue;
    }
    const name = clean.slice(0, atIndex);
    const rawVersionFromKey = clean.slice(atIndex + 1).split("(")[0];
    const version = value?.version?.split("(")[0] ?? rawVersionFromKey;
    if (!name || !version) {
      continue;
    }
    addDependency(deps, {
      name,
      version,
      direct: directNames.has(name),
      ecosystem: "npm",
    });
  }
  return [...deps.values()];
}

function parseYarnLock(content: string): PackageCoordinate[] {
  const deps = new Map<string, PackageCoordinate>();
  const lines = content.split(/\r?\n/);
  let currentNames: string[] = [];
  let currentVersion: string | null = null;

  const flush = (): void => {
    if (!currentVersion || currentNames.length === 0) {
      return;
    }
    for (const specifier of currentNames) {
      const normalized = specifier.replace(/^"|"$/g, "");
      const at = normalized.lastIndexOf("@");
      if (at <= 0) {
        continue;
      }
      const name = normalized.slice(0, at);
      addDependency(deps, {
        name,
        version: currentVersion,
        direct: false,
        ecosystem: "npm",
      });
    }
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line.trim()) {
      continue;
    }
    if (!line.startsWith(" ") && line.endsWith(":")) {
      flush();
      currentVersion = null;
      currentNames = line
        .slice(0, -1)
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);
      continue;
    }
    const versionMatch = line.match(/^\s+version\s+"([^"]+)"/);
    if (versionMatch) {
      currentVersion = versionMatch[1];
    }
  }
  flush();

  return [...deps.values()];
}

export function parseNodeLockfile(content: string): PackageCoordinate[] {
  const type = detectLockfileType(content);
  if (type === "package-lock") {
    return parsePackageLock(content);
  }
  if (type === "pnpm-lock") {
    return parsePnpmLock(content);
  }
  return parseYarnLock(content);
}
