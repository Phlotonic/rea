import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectTypeScriptDeclarationsInputSchema,
  typescriptDeclarationsSchema,
  type TypeScriptDeclarations,
} from "../../domain/javascript/typescriptDeclarations.js";
import type { Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { TypeScriptDeclarationsPort } from "../../ports/javascript/TypeScriptDeclarationsPort.js";
import { callerAnalysisParameters } from "../AnalysisInput.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_typescript_declarations";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class TypeScriptDeclarationsService {
  constructor(readonly provider: TypeScriptDeclarationsPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const selectedParameters = callerAnalysisParameters(rawInput);
    return executeArtifactInspection(
      {
        operation: OPERATION,
        inputSchema: inspectTypeScriptDeclarationsInputSchema,
        outputSchema: typescriptDeclarationsSchema,
        provider: this.provider,
        invalidOutputMessage:
          "TypeScript declarations provider returned malformed output or changed artifact identity.",
        toParameters: (input) => input,
        validateReport: (report, parameters) =>
          report.artifact.path === parameters.path &&
          validReport(report, parameters),
        buildEvidence: (value, identity, parameters) =>
          createEvidence(
            {
              path: value.artifact.path,
              format: "file",
              sha256: value.artifact.sha256,
            },
            identity,
            {
              operation: OPERATION,
              parameters: selectedParameters(parameters),
              result: value,
              confidence: "observed",
              limitations: value.limitations,
              locations: [
                { kind: "artifact-path" as const, path: value.artifact.path },
              ],
            },
          ),
      },
      rawInput,
      options,
    );
  }
}

const validReport = (
  report: TypeScriptDeclarations,
  input: { readonly max_file_bytes: number; readonly max_declarations: number },
): boolean =>
  report.artifact.bytes <= input.max_file_bytes &&
  report.declarations.length <= input.max_declarations &&
  report.coverage.declarations === report.declarations.length;
