import { posix } from "node:path";
import { parse as parseJsonc, type ParseError } from "jsonc-parser";

import {
  logicalPathEscapesRoot,
  normalizeJoinedLogicalPath,
} from "../artifactIdentity.js";
import type { JavaScriptArtifactFile } from "./javascriptArtifactFiles.js";

export interface ParsedTsconfigPaths {
  readonly configPath: string;
  readonly baseUrl: string | null;
  readonly paths: ReadonlyMap<string, readonly string[]>;
  readonly rootDir: string | null;
  readonly outDir: string | null;
  readonly references: readonly string[];
}

const MAX_EXTENDS_DEPTH = 8;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const resolveRelativeArtifactPath = (
  baseDir: string,
  target: string,
): string | null => {
  const normalizedTarget = target.replaceAll("\\", "/");
  const joined =
    baseDir === "." || baseDir === ""
      ? normalizedTarget
      : posix.join(baseDir, normalizedTarget);
  const normalized = normalizeJoinedLogicalPath(joined);
  if (normalized === "" || logicalPathEscapesRoot(normalized)) return null;
  return normalized;
};

const parseRawTsconfig = (
  text: string,
): Record<string, unknown> | null => {
  const errors: ParseError[] = [];
  const parsed: unknown = parseJsonc(text, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  if (errors.length > 0 || !isRecord(parsed)) return null;
  return parsed;
};

const lookupTsconfigFile = (
  files: ReadonlyMap<string, JavaScriptArtifactFile>,
  path: string,
): JavaScriptArtifactFile | undefined =>
  files.get(path) ?? (path.endsWith(".json") ? undefined : files.get(`${path}.json`));

/**
 * Parse an inventoried tsconfig.json and follow artifact-confined `extends`
 * chains so `compilerOptions.paths` and `baseUrl` inherit accurately.
 */
export const loadTsconfigFromArtifact = (
  configPath: string,
  files: ReadonlyMap<string, JavaScriptArtifactFile>,
): ParsedTsconfigPaths | null => {
  const visited = new Set<string>();
  const chain: { readonly path: string; readonly dir: string; readonly data: Record<string, unknown> }[] = [];

  let currentPath: string | null = configPath;
  while (currentPath !== null && chain.length < MAX_EXTENDS_DEPTH) {
    if (visited.has(currentPath)) break;
    visited.add(currentPath);
    const file = lookupTsconfigFile(files, currentPath);
    if (file === undefined || !file.text.included) break;
    const data = parseRawTsconfig(file.text.value);
    if (data === null) {
      if (chain.length === 0) return null;
      break;
    }
    const dir = posix.dirname(file.path);
    chain.push({ path: file.path, dir, data });
    const ext = data.extends;
    if (typeof ext === "string" && (ext.startsWith("./") || ext.startsWith("../"))) {
      currentPath = resolveRelativeArtifactPath(dir, ext);
    } else {
      currentPath = null;
    }
  }

  if (chain.length === 0) return null;

  let baseUrl: string | null = null;
  let rootDir: string | null = null;
  let outDir: string | null = null;
  const mergedPaths = new Map<string, readonly string[]>();
  const references: string[] = [];

  // Apply base configs first, child configs override.
  for (let i = chain.length - 1; i >= 0; i -= 1) {
    const { dir, data } = chain[i]!;
    const compilerOptions = isRecord(data.compilerOptions)
      ? data.compilerOptions
      : null;
    if (compilerOptions !== null) {
      if (typeof compilerOptions.baseUrl === "string" && compilerOptions.baseUrl.trim() !== "") {
        baseUrl =
          resolveRelativeArtifactPath(dir, compilerOptions.baseUrl.trim()) ?? baseUrl;
      }
      if (typeof compilerOptions.rootDir === "string" && compilerOptions.rootDir.trim() !== "") {
        rootDir =
          resolveRelativeArtifactPath(dir, compilerOptions.rootDir.trim()) ?? rootDir;
      }
      if (typeof compilerOptions.outDir === "string" && compilerOptions.outDir.trim() !== "") {
        outDir =
          resolveRelativeArtifactPath(dir, compilerOptions.outDir.trim()) ?? outDir;
      }
      if (isRecord(compilerOptions.paths)) {
        const pathsBase = baseUrl ?? (dir === "." ? "" : dir);
        for (const [pattern, targets] of Object.entries(compilerOptions.paths)) {
          if (!Array.isArray(targets)) continue;
          const resolvedTargets: string[] = [];
          for (const rawTarget of targets) {
            if (typeof rawTarget !== "string" || rawTarget.trim() === "") continue;
            const resolved = resolveRelativeArtifactPath(pathsBase, rawTarget.trim());
            if (resolved !== null) resolvedTargets.push(resolved);
          }
          if (resolvedTargets.length > 0) mergedPaths.set(pattern, resolvedTargets);
        }
      }
    }
    if (i === 0 && Array.isArray(data.references)) {
      for (const ref of data.references) {
        if (isRecord(ref) && typeof ref.path === "string" && ref.path.trim() !== "") {
          const resolved = resolveRelativeArtifactPath(dir, ref.path.trim());
          if (resolved !== null) references.push(resolved);
        }
      }
    }
  }

  return {
    configPath: chain[0]!.path,
    baseUrl,
    paths: mergedPaths,
    rootDir,
    outDir,
    references,
  };
};

/** Find the nearest enclosing tsconfig.json for a source path (stopping at node_modules). */
export const findEnclosingTsconfig = (
  sourcePath: string,
  files: ReadonlyMap<string, JavaScriptArtifactFile>,
): ParsedTsconfigPaths | null => {
  let directory = posix.dirname(sourcePath);
  while (posix.basename(directory) !== "node_modules") {
    const candidate =
      directory === "." || directory === ""
        ? "tsconfig.json"
        : `${directory}/tsconfig.json`;
    if (files.has(candidate)) {
      const loaded = loadTsconfigFromArtifact(candidate, files);
      if (loaded !== null) return loaded;
    }
    if (directory === "." || directory === "") break;
    directory = posix.dirname(directory);
  }
  return null;
};

/**
 * Expand a bare specifier against tsconfig `paths` (longest non-wildcard prefix
 * first, matching TypeScript's module resolution) and `baseUrl`.
 */
export const expandTsconfigAliasCandidates = (
  specifier: string,
  tsconfig: ParsedTsconfigPaths,
): string[] => {
  const candidates: string[] = [];
  const exact = tsconfig.paths.get(specifier);
  if (exact !== undefined) candidates.push(...exact);

  // Match wildcard patterns (`prefix*suffix`), ordered by longest prefix.
  const wildcardMatches: { readonly prefixLen: number; readonly expanded: string[] }[] = [];
  for (const [pattern, targets] of tsconfig.paths.entries()) {
    const star = pattern.indexOf("*");
    if (star === -1 || pattern.indexOf("*", star + 1) !== -1) continue;
    const prefix = pattern.slice(0, star);
    const suffix = pattern.slice(star + 1);
    if (
      specifier.length >= prefix.length + suffix.length &&
      specifier.startsWith(prefix) &&
      specifier.endsWith(suffix)
    ) {
      const captured = specifier.slice(
        prefix.length,
        specifier.length - suffix.length,
      );
      const expanded: string[] = [];
      for (const target of targets) {
        const replaced = target.includes("*")
          ? target.replace("*", captured)
          : target;
        const normalized = normalizeJoinedLogicalPath(replaced);
        if (normalized !== "" && !logicalPathEscapesRoot(normalized))
          expanded.push(normalized);
      }
      if (expanded.length > 0)
        wildcardMatches.push({ prefixLen: prefix.length, expanded });
    }
  }
  wildcardMatches.sort((a, b) => b.prefixLen - a.prefixLen);
  for (const match of wildcardMatches) candidates.push(...match.expanded);

  if (tsconfig.baseUrl !== null) {
    const baseCandidate = resolveRelativeArtifactPath(tsconfig.baseUrl, specifier);
    if (baseCandidate !== null) candidates.push(baseCandidate);
  }

  return [...new Set(candidates)];
};
