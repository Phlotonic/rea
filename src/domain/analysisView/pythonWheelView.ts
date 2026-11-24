import { z } from "zod";

import { pythonWheelSchema } from "../python/pythonWheel.js";
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

/** Wheel identity, tags, RECORD verification summary and counts; full rows stay in parent. */
export const pythonWheelSummarySchema = pythonWheelSchema
  .pick({
    artifact: true,
    dist_info: true,
    wheel: true,
    direct_url: true,
    coverage: true,
  })
  .extend({
    metadata_name: z.string().min(1).nullable(),
    metadata_version: z.string().min(1).nullable(),
    requires_python: z.string().min(1).nullable(),
    requires_dist_count: z.int().nonnegative(),
    entry_point_count: z.int().nonnegative(),
    native_extension_count: z.int().nonnegative(),
    record_verification_status:
      pythonWheelSchema.shape.record.shape.verification_status,
    record_anomaly_count: z.int().nonnegative(),
    content_count: z.int().nonnegative(),
    limitation_count: z.int().nonnegative(),
  });

const readReport = createAnalysisViewResultReader(pythonWheelSchema);

/** Summarize retained Python wheel facts without reopening the .whl. */
export const projectPythonWheelView = (
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
          message: "Python wheel Evidence supports the summary view.",
        },
      ]),
    );
  const parsed = readReport(parent);
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  return ok({
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_python_wheel" as const,
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
      dist_info: report.dist_info,
      wheel: report.wheel,
      direct_url: report.direct_url,
      coverage: report.coverage,
      metadata_name: report.metadata?.name ?? null,
      metadata_version: report.metadata?.version ?? null,
      requires_python: report.metadata?.requires_python ?? null,
      requires_dist_count: report.metadata?.requires_dist.length ?? 0,
      entry_point_count: report.entry_points.length,
      native_extension_count: report.native_extensions.length,
      record_verification_status: report.record.verification_status,
      record_anomaly_count: report.record.anomalies.length,
      content_count: report.contents.length,
      limitation_count: report.limitations.length,
    },
    coverage: completeWithinViewCoverage(report.contents.length),
  });
};
