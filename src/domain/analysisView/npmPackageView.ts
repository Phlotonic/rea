import { z } from "zod";
import {
  npmBinEntrySchema,
  npmKeyValueSchema,
  npmPackageSchema,
  npmRepositorySchema,
} from "../javascript/npmPackage.js";
import { err, ok } from "../result.js";
import type { AnalysisViewParent } from "./analysisViewParent.js";
import {
  ownedView,
  type AdmittedView,
  type SummaryAnalysisView,
} from "./analysisViewShape.js";
import { analysisViewInputError } from "./analysisViewErrors.js";
import { createAnalysisViewResultReader } from "./analysisViewParent.js";
import {
  boundedViewMessages,
  completeWithinViewCoverage,
} from "./analysisViewCoverage.js";

/** Compact npm tarball summary; full member inventory stays in the complete parent. */
export const npmPackageSummarySchema = npmPackageSchema
  .pick({
    artifact: true,
    coverage: true,
  })
  .extend({
    name: z.string().nullable(),
    version: z.string().nullable(),
    license: z.string().nullable(),
    type: z.enum(["module", "commonjs"]).nullable(),
    main: z.string().nullable(),
    types: z.string().nullable(),
    exports_keys: z.array(z.string()),
    bin: z.array(npmBinEntrySchema),
    repository: npmRepositorySchema.nullable(),
    lifecycle_scripts: z.array(npmKeyValueSchema),
    dependency_count: z.int().nonnegative(),
    dev_dependency_count: z.int().nonnegative(),
    peer_dependency_count: z.int().nonnegative(),
    optional_dependency_count: z.int().nonnegative(),
    limitation_count: z.int().nonnegative(),
  });

const readReport = createAnalysisViewResultReader(npmPackageSchema);

/** Summarize retained npm package facts without reopening the .tgz tarball. */
export const projectNpmPackageView = (
  parent: AnalysisViewParent,
  admitted: AdmittedView,
) => {
  const view = ownedView<SummaryAnalysisView>(admitted, "summary");
  if (view === undefined)
    return err(
      analysisViewInputError([
        {
          path: ["view"],
          reason: "invalid_value",
          message: "npm package Evidence supports the summary view.",
        },
      ]),
    );
  const parsed = readReport(parent);
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  const pkg = report.package_json;
  return ok({
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_npm_package" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact: {
      path: report.artifact.path,
      sha256: report.artifact.sha256,
    },
    limitations: boundedViewMessages(
      [...parent.limitations, ...report.limitations],
      parent.evidenceId,
      "limitations",
    ),
    unknowns: [],
    kind: "summary" as const,
    view,
    summary: {
      artifact: report.artifact,
      coverage: report.coverage,
      name: pkg?.name ?? null,
      version: pkg?.version ?? null,
      license: pkg?.license ?? null,
      type: pkg?.type ?? null,
      main: pkg?.main ?? null,
      types: pkg?.types ?? null,
      exports_keys: pkg?.exports_keys ?? [],
      bin: pkg?.bin ?? [],
      repository: pkg?.repository ?? null,
      lifecycle_scripts: pkg?.lifecycle_scripts ?? [],
      dependency_count: pkg?.dependencies.length ?? 0,
      dev_dependency_count: pkg?.dev_dependencies.length ?? 0,
      peer_dependency_count: pkg?.peer_dependencies.length ?? 0,
      optional_dependency_count: pkg?.optional_dependencies.length ?? 0,
      limitation_count: report.limitations.length,
    },
    coverage: completeWithinViewCoverage(report.contents.length),
  });
};
