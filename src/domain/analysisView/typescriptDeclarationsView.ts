import { z } from "zod";

import { typescriptDeclarationsSchema } from "../javascript/typescriptDeclarations.js";
import { err, ok } from "../result.js";
import {
  boundedViewMessages,
  completeWithinViewCoverage,
} from "./analysisViewCoverage.js";
import { analysisViewInputError } from "./analysisViewErrors.js";
import {
  createAnalysisViewResultReader,
  type AnalysisViewParent,
} from "./analysisViewParent.js";
import {
  ownedView,
  type AdmittedView,
  type SummaryAnalysisView,
} from "./analysisViewShape.js";

/** Compact declaration surface summary; full members stay in parent Evidence. */
export const typescriptDeclarationsSummarySchema = typescriptDeclarationsSchema
  .pick({
    artifact: true,
    source_mapping_url: true,
    declaration_map: true,
    coverage: true,
  })
  .extend({
    triple_slash_count: z.int().nonnegative(),
    import_count: z.int().nonnegative(),
    declaration_count: z.int().nonnegative(),
    exported_count: z.int().nonnegative(),
    limitation_count: z.int().nonnegative(),
  });

const readReport = createAnalysisViewResultReader(typescriptDeclarationsSchema);

/** Summarize retained TypeScript declaration facts without reopening the .d.ts. */
export const projectTypeScriptDeclarationsView = (
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
          message: "TypeScript declarations Evidence supports the summary view.",
        },
      ]),
    );
  const parsed = readReport(parent);
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  return ok({
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_typescript_declarations" as const,
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
      source_mapping_url: report.source_mapping_url,
      declaration_map: report.declaration_map,
      coverage: report.coverage,
      triple_slash_count: report.triple_slash_references.length,
      import_count: report.imports.length,
      declaration_count: report.declarations.length,
      exported_count: report.declarations.filter((d) => d.exported).length,
      limitation_count: report.limitations.length,
    },
    coverage: completeWithinViewCoverage(report.declarations.length),
  });
};
