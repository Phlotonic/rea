import { z } from "zod";

import { pytorchCheckpointSchema } from "../python/pytorchPickle.js";
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

/** Compact checkpoint/pickle summary; full global and tensor rows stay in parent. */
export const pytorchPickleSummarySchema = pytorchCheckpointSchema
  .pick({
    artifact: true,
    container_format: true,
    coverage: true,
  })
  .extend({
    archive_version: z.string().min(1).nullable(),
    archive_byteorder: z.string().min(1).nullable(),
    storage_count: z.int().nonnegative(),
    pickle_protocol: z.number().int().min(0).max(5).nullable(),
    global_count: z.int().nonnegative(),
    flagged_global_count: z.int().nonnegative(),
    tensor_count: z.int().nonnegative(),
    top_level_key_count: z.int().nonnegative(),
    limitation_count: z.int().nonnegative(),
  });

const readReport = createAnalysisViewResultReader(pytorchCheckpointSchema);

/** Summarize retained PyTorch/pickle Evidence without reopening the file. */
export const projectPytorchPickleView = (
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
          message: "PyTorch/pickle Evidence supports the summary view.",
        },
      ]),
    );
  const parsed = readReport(parent);
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  return ok({
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_pytorch_checkpoint" as const,
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
      container_format: report.container_format,
      coverage: report.coverage,
      archive_version: report.archive?.version ?? null,
      archive_byteorder: report.archive?.byteorder ?? null,
      storage_count: report.archive?.storages.length ?? 0,
      pickle_protocol: report.pickle.protocol,
      global_count: report.pickle.globals.length,
      flagged_global_count: report.pickle.flagged_globals.length,
      tensor_count: report.tensors.length,
      top_level_key_count: report.pickle.top_level_keys.length,
      limitation_count: report.limitations.length,
    },
    coverage: completeWithinViewCoverage(report.coverage.opcodes_decoded),
  });
};
