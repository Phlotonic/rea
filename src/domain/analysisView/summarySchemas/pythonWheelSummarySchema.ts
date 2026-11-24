import { z } from "zod";
import { summaryViewResultBase } from "../analysisViewBase.js";
import { pythonWheelSummarySchema } from "../pythonWheelView.js";

export const pythonWheelSummaryViewResultSchema = z.strictObject({
  ...summaryViewResultBase,
  parent_operation: z.literal("inspect_python_wheel"),
  summary: pythonWheelSummarySchema,
});
