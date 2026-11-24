import { z } from "zod";

import { coverageStatusSchema } from "../coverage.js";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Format identity for typed Python wheel parse failures. */
export const PYTHON_WHEEL_FORMAT = "python-wheel";

const uint = z.number().int().min(0).max(0xffffffff);

/** Hard ceiling on the caller-selected input read budget. */
export const MAX_INSPECT_PYTHON_WHEEL_FILE_BYTES = 536870912;
/** Hard ceiling on ZIP members inventoried in one wheel. */
export const MAX_INSPECT_PYTHON_WHEEL_ENTRIES = 65536;
/** Hard ceiling on decoded *.dist-info metadata bytes. */
export const MAX_INSPECT_PYTHON_WHEEL_METADATA_BYTES = 16 * 1024 * 1024;
/** Hard ceiling on total uncompressed bytes hashed for RECORD verification. */
export const MAX_INSPECT_PYTHON_WHEEL_RECORD_VERIFY_BYTES = 536870912;

export const PYTHON_WHEEL_LIMIT_MAXIMA = {
  max_file_bytes: MAX_INSPECT_PYTHON_WHEEL_FILE_BYTES,
  max_entries: MAX_INSPECT_PYTHON_WHEEL_ENTRIES,
  max_metadata_bytes: MAX_INSPECT_PYTHON_WHEEL_METADATA_BYTES,
  max_record_verify_bytes: MAX_INSPECT_PYTHON_WHEEL_RECORD_VERIFY_BYTES,
} as const;

/** Path-derived wheel member roles; import-time execution is not observed. */
export const PYTHON_WHEEL_ENTRY_ROLES = [
  "dist-info",
  "data",
  "python-source",
  "python-bytecode",
  "python-stub",
  "native-extension",
  "resource",
] as const;
export type PythonWheelEntryRole = (typeof PYTHON_WHEEL_ENTRY_ROLES)[number];

/** Logical ZIP path with unified separators and without a leading `./`. */
export const pythonWheelLogicalPath = (name: string): string =>
  name.replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "");

/** Classify a wheel member by its normalized archive path. */
export const pythonWheelEntryRole = (name: string): PythonWheelEntryRole => {
  const logical = pythonWheelLogicalPath(name);
  const lower = logical.toLowerCase();
  const slash = lower.indexOf("/");
  const head = slash === -1 ? lower : lower.slice(0, slash);
  if (head.endsWith(".dist-info")) return "dist-info";
  if (head.endsWith(".data")) return "data";
  if (lower.endsWith(".py")) return "python-source";
  if (lower.endsWith(".pyc") || lower.endsWith(".pyo")) return "python-bytecode";
  if (lower.endsWith(".pyi") || lower.endsWith("/py.typed") || lower === "py.typed")
    return "python-stub";
  if (
    lower.endsWith(".so") ||
    lower.endsWith(".pyd") ||
    lower.endsWith(".dylib") ||
    lower.endsWith(".dll") ||
    lower.endsWith(".sl") ||
    /\.so\.[0-9]+(?:\.[0-9]+)*$/u.test(lower)
  )
    return "native-extension";
  return "resource";
};

/** Bounded inspection input for one Python .whl distribution. */
export const inspectPythonWheelInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute filesystem path to a Python .whl distribution",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(16)
    .max(MAX_INSPECT_PYTHON_WHEEL_FILE_BYTES)
    .default(67108864)
    .describe("Maximum stable artifact bytes to read (default 64 MiB)"),
  max_entries: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_PYTHON_WHEEL_ENTRIES)
    .default(4096)
    .describe(
      "Maximum ZIP entries to inventory; exceeding the budget fails without partial success",
    ),
  max_metadata_bytes: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_PYTHON_WHEEL_METADATA_BYTES)
    .default(2097152)
    .describe(
      "Maximum expanded bytes to decode across *.dist-info metadata files (default 2 MiB)",
    ),
  verify_record: z
    .boolean()
    .default(true)
    .describe(
      "Verify RECORD-listed member sizes and SHA-256/384/512 digests against ZIP bytes (default true)",
    ),
  max_record_verify_bytes: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_PYTHON_WHEEL_RECORD_VERIFY_BYTES)
    .default(67108864)
    .describe(
      "Maximum cumulative uncompressed bytes hashed during RECORD verification (default 64 MiB)",
    ),
});

const nullableText = z.string().min(1).nullable();

const wheelProjectUrlSchema = z.strictObject({
  label: z.string().min(1),
  url: z.string().min(1),
  url_credentials_redacted: z.boolean(),
});

const wheelTagSchema = z.strictObject({
  raw: z.string().min(1),
  python_tag: nullableText,
  abi_tag: nullableText,
  platform_tag: nullableText,
});

const wheelEntryPointSchema = z.strictObject({
  group: z.string().min(1),
  name: z.string().min(1),
  value: z.string().min(1),
});

export const PYTHON_WHEEL_RECORD_ANOMALY_KINDS = [
  "hash-mismatch",
  "size-mismatch",
  "missing-in-archive",
  "unrecorded-in-record",
  "duplicate-record-entry",
  "unsupported-algorithm",
  "encrypted-member",
  "malformed-row",
  "budget-exceeded",
] as const;

const wheelRecordAnomalySchema = z.strictObject({
  path: z.string().min(1),
  kind: z.enum(PYTHON_WHEEL_RECORD_ANOMALY_KINDS),
  algorithm: nullableText.optional(),
  declared_hash: nullableText.optional(),
  observed_hash: nullableText.optional(),
  declared_size: z.number().int().nonnegative().nullable().optional(),
  observed_size: z.number().int().nonnegative().nullable().optional(),
  detail: z.string().min(1),
});

const wheelContentSchema = z.strictObject({
  /** ZIP member name as stored in the archive. */
  name: z.string().min(1),
  /** Name with separators normalized and leading `./` removed; drives role and lookup. */
  path: z.string().min(1),
  uncompressed_size: z.number().int().nonnegative().nullable(),
  compressed_size: z.number().int().nonnegative().nullable(),
  role: z.enum(PYTHON_WHEEL_ENTRY_ROLES),
  encrypted: z.boolean(),
});

/** Observed .whl metadata, tags, entry points, RECORD integrity, and ZIP inventory. */
export const pythonWheelSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  dist_info: z
    .strictObject({
      directory: z.string().min(1),
      metadata_path: nullableText,
      wheel_path: nullableText,
      record_path: nullableText,
      entry_points_path: nullableText,
      top_level_path: nullableText,
      direct_url_path: nullableText,
    })
    .nullable(),
  metadata: z
    .strictObject({
      metadata_version: nullableText,
      name: nullableText,
      version: nullableText,
      summary: nullableText,
      author: nullableText,
      author_email: nullableText,
      maintainer: nullableText,
      license: nullableText,
      license_expression: nullableText,
      requires_python: nullableText,
      requires_dist: z.array(z.string().min(1)),
      provides_extra: z.array(z.string().min(1)),
      classifiers: z.array(z.string().min(1)),
      project_urls: z.array(wheelProjectUrlSchema),
      home_page: nullableText,
      home_page_credentials_redacted: z.boolean(),
    })
    .nullable(),
  wheel: z
    .strictObject({
      wheel_version: nullableText,
      generator: nullableText,
      root_is_purelib: z.boolean().nullable(),
      tags: z.array(wheelTagSchema),
      build: nullableText,
    })
    .nullable(),
  entry_points: z.array(wheelEntryPointSchema),
  top_level: z.array(z.string().min(1)),
  direct_url: z
    .strictObject({
      url: nullableText,
      url_credentials_redacted: z.boolean(),
      vcs: nullableText,
      commit_id: nullableText,
      editable: z.boolean().nullable(),
    })
    .nullable(),
  record: z.strictObject({
    present: z.boolean(),
    entry_count: uint,
    verified_count: uint,
    mismatched_count: uint,
    missing_from_archive_count: uint,
    unrecorded_archive_count: uint,
    unsupported_algorithm_count: uint,
    unhashed_count: uint,
    skipped_budget_count: uint,
    verification_status: z.enum([
      "verified",
      "mismatched",
      "partial",
      "skipped",
      "unavailable",
    ]),
    anomalies: z.array(wheelRecordAnomalySchema),
  }),
  native_extensions: z.array(z.string().min(1)),
  contents: z.array(wheelContentSchema),
  coverage: z.strictObject({
    status: coverageStatusSchema,
    entries: uint,
    examined_metadata_bytes: uint,
    verified_record_bytes: uint,
  }),
  limitations: z.array(z.string().min(1)).min(1),
});

export type PythonWheel = z.infer<typeof pythonWheelSchema>;
export type InspectPythonWheelInput = z.infer<
  typeof inspectPythonWheelInputSchema
>;
