import type {
  NpmManifest,
  NpmMemberRole,
  NpmPackage,
} from "../../domain/javascript/npmPackage.js";
import { redactRecordedTransportUrl } from "../../domain/recordedTransportUrl.js";
import { isRecord } from "../../kernel/isRecord.js";
import {
  readNpmTarGz,
  type ReadTarGzOptions,
  type TarEntryRecord,
} from "./TarGzReader.js";

const LIFECYCLE_SCRIPT_NAMES = new Set([
  "preinstall",
  "install",
  "postinstall",
  "preuninstall",
  "uninstall",
  "postuninstall",
  "prepare",
  "prepack",
  "postpack",
  "prepublish",
  "prepublishOnly",
  "publish",
  "postpublish",
]);

const redactUrl = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "") return null;
  return redactRecordedTransportUrl(trimmed).url;
};

const stringOrNull = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

const stringArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const recordToPairs = (
  value: unknown,
): { readonly name: string; readonly value: string }[] => {
  if (!isRecord(value)) return [];
  const out: { name: string; value: string }[] = [];
  for (const [k, v] of Object.entries(value)) {
    if (k !== "" && typeof v === "string") out.push({ name: k, value: v });
  }
  return out;
};

const parseBin = (
  rawBin: unknown,
  pkgName: string | null,
): { readonly command: string; readonly target: string }[] => {
  if (typeof rawBin === "string" && rawBin.trim() !== "") {
    const fallbackName =
      pkgName !== null ? pkgName.replace(/^@[^/]+\//, "") : "bin";
    return [{ command: fallbackName || "bin", target: rawBin }];
  }
  if (!isRecord(rawBin)) return [];
  const out: { command: string; target: string }[] = [];
  for (const [command, target] of Object.entries(rawBin)) {
    if (command !== "" && typeof target === "string") {
      out.push({ command, target });
    }
  }
  return out;
};

const parseRepository = (
  raw: unknown,
): NpmManifest["repository"] => {
  if (typeof raw === "string") {
    return { type: null, url: redactUrl(raw), directory: null };
  }
  if (!isRecord(raw)) return null;
  return {
    type: stringOrNull(raw.type),
    url: redactUrl(raw.url),
    directory: stringOrNull(raw.directory),
  };
};

const parseBugsUrl = (raw: unknown): string | null => {
  if (typeof raw === "string") return redactUrl(raw);
  if (isRecord(raw)) return redactUrl(raw.url);
  return null;
};

const parseExportsKeys = (raw: unknown): string[] => {
  if (typeof raw === "string") return ["."];
  if (isRecord(raw)) return Object.keys(raw);
  return [];
};

const parsePackageJson = (
  manifestPath: string,
  rawBytes: Buffer,
  limitations: string[],
): NpmManifest | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBytes.toString("utf8"));
  } catch {
    limitations.push(
      `Manifest ${manifestPath} is not valid JSON; package.json fields omitted.`,
    );
    return null;
  }
  if (!isRecord(parsed)) {
    limitations.push(
      `Manifest ${manifestPath} did not decode to a JSON object; package.json fields omitted.`,
    );
    return null;
  }

  const name = stringOrNull(parsed.name);
  const rawType = parsed.type;
  const pkgType =
    rawType === "module" || rawType === "commonjs" ? rawType : null;
  const scripts = recordToPairs(parsed.scripts);
  const lifecycleScripts = scripts.filter((s) =>
    LIFECYCLE_SCRIPT_NAMES.has(s.name),
  );
  const rawLicense = parsed.license;
  const license =
    typeof rawLicense === "string"
      ? rawLicense
      : isRecord(rawLicense)
        ? stringOrNull(rawLicense.type)
        : null;

  return {
    path: manifestPath,
    bytes: rawBytes.length,
    name,
    version: stringOrNull(parsed.version),
    description: stringOrNull(parsed.description),
    license,
    private: typeof parsed.private === "boolean" ? parsed.private : null,
    type: pkgType,
    main: stringOrNull(parsed.main),
    module: stringOrNull(parsed.module),
    browser: typeof parsed.browser === "string" ? parsed.browser : null,
    types: stringOrNull(parsed.types) ?? stringOrNull(parsed.typings),
    exports_keys: parseExportsKeys(parsed.exports),
    imports_keys: isRecord(parsed.imports) ? Object.keys(parsed.imports) : [],
    bin: parseBin(parsed.bin, name),
    files: stringArray(parsed.files),
    engines: recordToPairs(parsed.engines),
    os: stringArray(parsed.os),
    cpu: stringArray(parsed.cpu),
    repository: parseRepository(parsed.repository),
    homepage: redactUrl(parsed.homepage),
    bugs_url: parseBugsUrl(parsed.bugs),
    dependencies: recordToPairs(parsed.dependencies),
    dev_dependencies: recordToPairs(parsed.devDependencies),
    peer_dependencies: recordToPairs(parsed.peerDependencies),
    optional_dependencies: recordToPairs(parsed.optionalDependencies),
    lifecycle_scripts: lifecycleScripts,
    scripts,
  };
};

const normalizeBinTargets = (manifest: NpmManifest | null): Set<string> => {
  const targets = new Set<string>();
  if (manifest === null) return targets;
  const manifestDir = manifest.path.includes("/")
    ? manifest.path.slice(0, manifest.path.lastIndexOf("/") + 1)
    : "";
  for (const entry of manifest.bin) {
    const rel = entry.target.replace(/^\.\//, "");
    targets.add(rel);
    if (manifestDir !== "") targets.add(`${manifestDir}${rel}`);
  }
  return targets;
};

const classifyMemberRole = (
  entry: TarEntryRecord,
  manifestPath: string | null,
  binTargets: ReadonlySet<string>,
): NpmMemberRole => {
  const p = entry.path.replace(/^\.\//, "");
  const lower = p.toLowerCase();
  if (manifestPath !== null && entry.path === manifestPath) return "manifest";
  if (binTargets.has(p)) return "bin";
  if (/\.(?:d\.ts|d\.mts|d\.cts)$/i.test(lower)) return "typescript-declaration";
  if (/\.map$/i.test(lower)) return "source-map";
  if (
    /\.node$/i.test(lower) ||
    /(?:^|\/)(?:binding\.gyp|cmakelists\.txt)$/i.test(lower) ||
    /(?:^|\/)prebuilds\//i.test(lower)
  ) {
    return "native-addon";
  }
  if (/\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(lower)) return "javascript";
  if (
    /(?:^|\/)(?:readme|license|licence|changelog|history|notice|security)(?:\.[^/]*)?$/i.test(
      lower,
    ) ||
    /\.md$/i.test(lower)
  ) {
    return "docs";
  }
  if (/\.(?:json|wasm|css|scss|svg|png|jpg|jpeg|webp|woff2?|ttf)$/i.test(lower)) {
    return "asset";
  }
  return "other";
};

const detectSuspiciousReason = (
  entry: TarEntryRecord,
): "path-traversal" | "absolute-path" | "symlink" | "hardlink" | null => {
  const normalized = entry.path.replace(/\\/g, "/");
  if (normalized.startsWith("/")) return "absolute-path";
  if (normalized.split("/").some((segment) => segment === "..")) {
    return "path-traversal";
  }
  if (entry.typeFlag === "symlink") return "symlink";
  if (entry.typeFlag === "hardlink") return "hardlink";
  return null;
};

export interface ParseNpmPackageOptions extends ReadTarGzOptions {
  readonly artifact: {
    readonly path: string;
    readonly sha256: string;
    readonly bytes: number;
  };
}

/** Parse a local npm package `.tgz` tarball into a normalized read-only inventory. */
export const parseNpmPackage = async (
  compressed: Buffer,
  options: ParseNpmPackageOptions,
): Promise<NpmPackage> => {
  const tarResult = await readNpmTarGz(compressed, options);
  const limitations: string[] = [
    "Static offline npm tarball inspection: lifecycle scripts are not executed, dependencies are not resolved, and npm registry signatures are not verified.",
  ];

  let packageJson: NpmManifest | null = null;
  let manifestBytesCount = 0;

  if (tarResult.manifestPath === null) {
    limitations.push("No top-level package.json manifest was found in the tarball.");
  } else if (tarResult.manifestOversizeBytes !== null) {
    manifestBytesCount = tarResult.manifestOversizeBytes;
    limitations.push(
      `Manifest ${tarResult.manifestPath} (${String(tarResult.manifestOversizeBytes)} bytes) exceeds max_manifest_bytes (${String(options.maxManifestBytes)}); package.json fields omitted.`,
    );
  } else if (tarResult.manifestBytes !== null) {
    manifestBytesCount = tarResult.manifestBytes.length;
    packageJson = parsePackageJson(
      tarResult.manifestPath,
      tarResult.manifestBytes,
      limitations,
    );
  }

  const binTargets = normalizeBinTargets(packageJson);
  const typeDeclarations: string[] = [];
  const sourceMaps: string[] = [];
  const nativeAddons: string[] = [];
  const suspiciousEntries: NpmPackage["suspicious_entries"] = [];
  const contents: NpmPackage["contents"] = [];

  for (const entry of tarResult.entries) {
    const role = classifyMemberRole(entry, tarResult.manifestPath, binTargets);
    if (entry.typeFlag === "file") {
      if (role === "typescript-declaration") typeDeclarations.push(entry.path);
      else if (role === "source-map") sourceMaps.push(entry.path);
      else if (role === "native-addon") nativeAddons.push(entry.path);
    }
    const reason = detectSuspiciousReason(entry);
    if (reason !== null) {
      suspiciousEntries.push({
        path: entry.path,
        reason,
        link_target: entry.linkTarget,
      });
    }
    contents.push({
      path: entry.path,
      size: entry.size,
      type_flag: entry.typeFlag,
      role,
      link_target: entry.linkTarget,
    });
  }

  return {
    artifact: options.artifact,
    package_json: packageJson,
    type_declarations: typeDeclarations,
    source_maps: sourceMaps,
    native_addons: nativeAddons,
    suspicious_entries: suspiciousEntries,
    contents,
    coverage: {
      entries: contents.length,
      uncompressed_bytes: tarResult.uncompressedBytes,
      manifest_bytes: manifestBytesCount,
      lifecycle_script_count: packageJson?.lifecycle_scripts.length ?? 0,
      native_addon_count: nativeAddons.length,
      type_declaration_count: typeDeclarations.length,
      source_map_count: sourceMaps.length,
      suspicious_entry_count: suspiciousEntries.length,
    },
    limitations,
  };
};
