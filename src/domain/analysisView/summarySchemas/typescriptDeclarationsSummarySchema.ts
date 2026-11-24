import { z } from "zod";
import { summaryViewResultBase } from "../analysisViewBase.js";
import { typescriptDeclarationsSummarySchema } from "../typescriptDeclarationsView.js";

export const typescriptDeclarationsSummaryViewResultSchema = z.strictObject({
  ...summaryViewResultBase,
  parent_operation: z.literal("inspect_typescript_declarations"),
  summary: typescriptDeclarationsSummarySchema,
});
