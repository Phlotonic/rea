import { z } from "zod";
import { summaryViewResultBase } from "../analysisViewBase.js";
import { pytorchPickleSummarySchema } from "../pytorchPickleView.js";

export const pytorchPickleSummaryViewResultSchema = z.strictObject({
  ...summaryViewResultBase,
  parent_operation: z.literal("inspect_pytorch_checkpoint"),
  summary: pytorchPickleSummarySchema,
});
