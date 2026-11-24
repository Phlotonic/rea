import { z } from "zod";
import { summaryViewResultBase } from "../analysisViewBase.js";
import { npmPackageSummarySchema } from "../npmPackageView.js";

export const npmPackageSummaryViewResultSchema = z.strictObject({
  ...summaryViewResultBase,
  parent_operation: z.literal("inspect_npm_package"),
  summary: npmPackageSummarySchema,
});
