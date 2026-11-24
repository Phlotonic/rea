import { z } from "zod";

import { coverageStatusSchema } from "../coverage.js";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Format identity for typed TypeScript declaration parse failures. */
export const TYPESCRIPT_DECLARATIONS_FORMAT = "typescript-declarations";

const uint = z.number().int().min(0).max(0xffffffff);

export const MAX_INSPECT_TS_DECL_FILE_BYTES = 32 * 1024 * 1024;
export const MAX_INSPECT_TS_DECL_ENTRIES = 16384;

export const TYPESCRIPT_DECL_LIMIT_MAXIMA = {
  max_file_bytes: MAX_INSPECT_TS_DECL_FILE_BYTES,
  max_declarations: MAX_INSPECT_TS_DECL_ENTRIES,
} as const;

export const inspectTypeScriptDeclarationsInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute filesystem path to a TypeScript declaration file (.d.ts, .d.mts, .d.cts)",
  ),
  declaration_map_path: absoluteLocalPathStringSchema
    .optional()
    .describe(
      "Optional explicit absolute path to a companion .d.ts.map declaration source map",
    ),
  max_file_bytes: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_TS_DECL_FILE_BYTES)
    .default(4 * 1024 * 1024)
    .describe("Maximum stable declaration file bytes to read (default 4 MiB)"),
  max_declarations: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_TS_DECL_ENTRIES)
    .default(4096)
    .describe("Maximum top-level/ambient declarations returned before truncating with partial coverage (default 4096)"),
});

const nullableText = z.string().min(1).nullable();

export const TS_DECLARATION_KINDS = [
  "function",
  "class",
  "interface",
  "type-alias",
  "enum",
  "const-enum",
  "variable",
  "namespace",
  "module-augmentation",
  "re-export",
  "export-all",
  "export-default",
] as const;

export const TS_MEMBER_KINDS = [
  "method",
  "property",
  "constructor",
  "getter",
  "setter",
  "index-signature",
  "call-signature",
  "enum-member",
] as const;

const tsMemberSchema = z.strictObject({
  name: z.string().min(1),
  kind: z.enum(TS_MEMBER_KINDS),
  optional: z.boolean(),
  readonly: z.boolean(),
  static: z.boolean(),
});

const tsDeclarationSchema = z.strictObject({
  kind: z.enum(TS_DECLARATION_KINDS),
  name: z.string().min(1),
  exported: z.boolean(),
  ambient: z.boolean(),
  line: uint,
  source_specifier: nullableText,
  type_parameters: z.array(z.string().min(1)),
  extends: z.array(z.string().min(1)),
  implements: z.array(z.string().min(1)),
  members: z.array(tsMemberSchema),
});

const tsImportSchema = z.strictObject({
  specifier: z.string().min(1),
  type_only: z.boolean(),
  names: z.array(z.string().min(1)),
  line: uint,
});

const tsTripleSlashSchema = z.strictObject({
  kind: z.enum(["path", "types", "lib", "no-default-lib"]),
  value: z.string().min(1),
  line: uint,
});

export const typescriptDeclarationsSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  source_mapping_url: nullableText,
  declaration_map: z
    .strictObject({
      path: z.string().min(1),
      sha256: digestSchema,
      version: z.number().int().nullable(),
      source_root: nullableText,
      sources: z.array(z.string()),
      has_mappings: z.boolean(),
    })
    .nullable(),
  triple_slash_references: z.array(tsTripleSlashSchema),
  imports: z.array(tsImportSchema),
  declarations: z.array(tsDeclarationSchema),
  coverage: z.strictObject({
    status: coverageStatusSchema,
    declarations: uint,
    parse_errors: uint,
  }),
  limitations: z.array(z.string().min(1)).min(1),
});

export type TypeScriptDeclarations = z.infer<
  typeof typescriptDeclarationsSchema
>;
export type InspectTypeScriptDeclarationsInput = z.infer<
  typeof inspectTypeScriptDeclarationsInputSchema
>;
