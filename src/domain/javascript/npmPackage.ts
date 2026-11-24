import { z } from "zod";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

const nonEmptyTextSchema = z.string().min(1);

const artifactFileIdentitySchema = z.strictObject({
  path: nonEmptyTextSchema,
  sha256: digestSchema,
  bytes: z.int().nonnegative(),
});

/** Format identifier for offline npm package tarball parse failures. */
export const NPM_PACKAGE_FORMAT = "npm-package" as const;

/** Default and hard ceilings for offline npm `.tgz` tarball inspection. */
export const NPM_PACKAGE_LIMIT_DEFAULTS = {
  max_file_bytes: 64 * 1024 * 1024,
  max_entries: 8_192,
  max_uncompressed_bytes: 128 * 1024 * 1024,
  max_manifest_bytes: 1024 * 1024,
} as const;

export const NPM_PACKAGE_LIMIT_MAXIMA = {
  max_file_bytes: 512 * 1024 * 1024,
  max_entries: 65_536,
  max_uncompressed_bytes: 512 * 1024 * 1024,
  max_manifest_bytes: 8 * 1024 * 1024,
} as const;

const boundedLimit = (
  key: keyof typeof NPM_PACKAGE_LIMIT_DEFAULTS,
  description: string,
) =>
  z
    .int()
    .positive()
    .max(NPM_PACKAGE_LIMIT_MAXIMA[key])
    .default(NPM_PACKAGE_LIMIT_DEFAULTS[key])
    .describe(description);

export const npmPackageLimitsSchema = z.strictObject({
  max_file_bytes: boundedLimit(
    "max_file_bytes",
    "Maximum compressed .tgz file size in bytes",
  ),
  max_entries: boundedLimit(
    "max_entries",
    "Maximum tar archive member entries inspected",
  ),
  max_uncompressed_bytes: boundedLimit(
    "max_uncompressed_bytes",
    "Maximum total decompressed tar bytes streamed (anti-gzip-bomb ceiling)",
  ),
  max_manifest_bytes: boundedLimit(
    "max_manifest_bytes",
    "Maximum package.json manifest size in bytes",
  ),
});

export const inspectNpmPackageInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local npm package tarball (.tgz)",
  ),
  ...npmPackageLimitsSchema.shape,
});

export type InspectNpmPackageInput = z.infer<typeof inspectNpmPackageInputSchema>;

export const npmKeyValueSchema = z.strictObject({
  name: nonEmptyTextSchema,
  value: z.string(),
});

export const npmBinEntrySchema = z.strictObject({
  command: nonEmptyTextSchema,
  target: z.string(),
});

export const npmRepositorySchema = z.strictObject({
  type: z.string().nullable(),
  url: z.string().nullable(),
  directory: z.string().nullable(),
});

export const npmManifestSchema = z.strictObject({
  path: nonEmptyTextSchema,
  bytes: z.int().nonnegative(),
  name: z.string().nullable(),
  version: z.string().nullable(),
  description: z.string().nullable(),
  license: z.string().nullable(),
  private: z.boolean().nullable(),
  type: z.enum(["module", "commonjs"]).nullable(),
  main: z.string().nullable(),
  module: z.string().nullable(),
  browser: z.string().nullable(),
  types: z.string().nullable(),
  exports_keys: z.array(z.string()),
  imports_keys: z.array(z.string()),
  bin: z.array(npmBinEntrySchema),
  files: z.array(z.string()),
  engines: z.array(npmKeyValueSchema),
  os: z.array(z.string()),
  cpu: z.array(z.string()),
  repository: npmRepositorySchema.nullable(),
  homepage: z.string().nullable(),
  bugs_url: z.string().nullable(),
  dependencies: z.array(npmKeyValueSchema),
  dev_dependencies: z.array(npmKeyValueSchema),
  peer_dependencies: z.array(npmKeyValueSchema),
  optional_dependencies: z.array(npmKeyValueSchema),
  lifecycle_scripts: z.array(npmKeyValueSchema),
  scripts: z.array(npmKeyValueSchema),
});

export type NpmManifest = z.infer<typeof npmManifestSchema>;

export const npmTarTypeFlagSchema = z.enum([
  "file",
  "directory",
  "symlink",
  "hardlink",
  "other",
]);

export const npmMemberRoleSchema = z.enum([
  "manifest",
  "javascript",
  "typescript-declaration",
  "source-map",
  "native-addon",
  "bin",
  "docs",
  "asset",
  "other",
]);

export type NpmMemberRole = z.infer<typeof npmMemberRoleSchema>;

export const npmSuspiciousReasonSchema = z.enum([
  "path-traversal",
  "absolute-path",
  "symlink",
  "hardlink",
]);

export const npmSuspiciousEntrySchema = z.strictObject({
  path: z.string(),
  reason: npmSuspiciousReasonSchema,
  link_target: z.string().nullable(),
});

export const npmContentEntrySchema = z.strictObject({
  path: z.string(),
  size: z.int().nonnegative(),
  type_flag: npmTarTypeFlagSchema,
  role: npmMemberRoleSchema,
  link_target: z.string().nullable(),
});

export const npmPackageCoverageSchema = z.strictObject({
  entries: z.int().nonnegative(),
  uncompressed_bytes: z.int().nonnegative(),
  manifest_bytes: z.int().nonnegative(),
  lifecycle_script_count: z.int().nonnegative(),
  native_addon_count: z.int().nonnegative(),
  type_declaration_count: z.int().nonnegative(),
  source_map_count: z.int().nonnegative(),
  suspicious_entry_count: z.int().nonnegative(),
});

export const npmPackageSchema = z.strictObject({
  artifact: artifactFileIdentitySchema,
  package_json: npmManifestSchema.nullable(),
  type_declarations: z.array(z.string()),
  source_maps: z.array(z.string()),
  native_addons: z.array(z.string()),
  suspicious_entries: z.array(npmSuspiciousEntrySchema),
  contents: z.array(npmContentEntrySchema),
  coverage: npmPackageCoverageSchema,
  limitations: z.array(nonEmptyTextSchema),
});

export type NpmPackage = z.infer<typeof npmPackageSchema>;
