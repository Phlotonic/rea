import { z } from "zod";

import { coverageStatusSchema } from "../coverage.js";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Format identity for typed PyTorch/pickle checkpoint parse failures. */
export const PYTORCH_PICKLE_FORMAT = "pytorch-pickle";

const uint = z.number().int().min(0).max(0xffffffff);

export const MAX_INSPECT_PYTORCH_FILE_BYTES = 2147483647;
export const MAX_INSPECT_PYTORCH_ENTRIES = 65536;
export const MAX_INSPECT_PYTORCH_PICKLE_BYTES = 64 * 1024 * 1024;
export const MAX_INSPECT_PYTORCH_OPCODES = 2_000_000;

export const PYTORCH_PICKLE_LIMIT_MAXIMA = {
  max_file_bytes: MAX_INSPECT_PYTORCH_FILE_BYTES,
  max_entries: MAX_INSPECT_PYTORCH_ENTRIES,
  max_pickle_bytes: MAX_INSPECT_PYTORCH_PICKLE_BYTES,
  max_opcodes: MAX_INSPECT_PYTORCH_OPCODES,
} as const;

export const inspectPytorchCheckpointInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute filesystem path to a PyTorch checkpoint (.pt/.pth/.ckpt/.bin ZIP) or raw Python pickle (.pkl/.pickle)",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(2)
    .max(MAX_INSPECT_PYTORCH_FILE_BYTES)
    .default(268435456)
    .describe("Maximum stable artifact bytes to read (default 256 MiB)"),
  max_entries: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_PYTORCH_ENTRIES)
    .default(8192)
    .describe("Maximum ZIP entries to inventory for ZIP-based PyTorch checkpoints (default 8192)"),
  max_pickle_bytes: z
    .number()
    .int()
    .min(2)
    .max(MAX_INSPECT_PYTORCH_PICKLE_BYTES)
    .default(16 * 1024 * 1024)
    .describe("Maximum pickle stream bytes decoded from data.pkl or a raw pickle file (default 16 MiB)"),
  max_opcodes: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_PYTORCH_OPCODES)
    .default(200000)
    .describe("Maximum pickle VM opcodes stepped before stopping with partial coverage (default 200000)"),
});

const nullableText = z.string().min(1).nullable();

export const PICKLE_GLOBAL_RISK_LEVELS = ["critical", "high", "review"] as const;

const pickleGlobalRefSchema = z.strictObject({
  module: z.string(),
  name: z.string(),
  opcode: z.enum(["GLOBAL", "STACK_GLOBAL", "INST", "EXT"]),
  offset: uint,
});

const pickleFlaggedGlobalSchema = z.strictObject({
  module: z.string(),
  name: z.string(),
  opcode: z.enum(["GLOBAL", "STACK_GLOBAL", "INST", "EXT"]),
  offset: uint,
  severity: z.enum(PICKLE_GLOBAL_RISK_LEVELS),
  reason: z.string().min(1),
});

const pytorchTensorSchema = z.strictObject({
  name: nullableText,
  rebuilder: z.string().min(1),
  dtype: nullableText,
  storage_type: nullableText,
  storage_key: nullableText,
  storage_location: nullableText,
  storage_numel: z.number().int().nonnegative().nullable(),
  storage_offset: z.number().int().nonnegative().nullable(),
  shape: z.array(z.number().int().nonnegative()),
  stride: z.array(z.number().int().nonnegative()),
  requires_grad: z.boolean().nullable(),
  archive_member: nullableText,
  archive_bytes: z.number().int().nonnegative().nullable(),
});

const pytorchStorageSchema = z.strictObject({
  key: z.string().min(1),
  archive_member: z.string().min(1),
  uncompressed_size: z.number().int().nonnegative().nullable(),
  compressed_size: z.number().int().nonnegative().nullable(),
});

export const pytorchCheckpointSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  container_format: z.enum(["pytorch-zip", "raw-pickle"]),
  archive: z
    .strictObject({
      prefix: nullableText,
      pickle_member: nullableText,
      version: nullableText,
      byteorder: nullableText,
      entry_count: uint,
      storages: z.array(pytorchStorageSchema),
    })
    .nullable(),
  pickle: z.strictObject({
    protocol: z.number().int().min(0).max(5).nullable(),
    bytes: uint,
    opcodes_decoded: uint,
    truncated: z.boolean(),
    terminated_with_stop: z.boolean(),
    reduce_count: uint,
    build_count: uint,
    newobj_count: uint,
    persistent_load_count: uint,
    globals: z.array(pickleGlobalRefSchema),
    flagged_globals: z.array(pickleFlaggedGlobalSchema),
    top_level_keys: z.array(z.string()),
  }),
  tensors: z.array(pytorchTensorSchema),
  coverage: z.strictObject({
    status: coverageStatusSchema,
    entries: uint,
    examined_pickle_bytes: uint,
    opcodes_decoded: uint,
  }),
  limitations: z.array(z.string().min(1)).min(1),
});

export type PytorchCheckpoint = z.infer<typeof pytorchCheckpointSchema>;
export type InspectPytorchCheckpointInput = z.infer<
  typeof inspectPytorchCheckpointInputSchema
>;
