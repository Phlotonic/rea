import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPythonWheelInputSchema,
  pythonWheelSchema,
  type PythonWheel,
} from "../../domain/python/pythonWheel.js";
import type { Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { PythonWheelPort } from "../../ports/python/PythonWheelPort.js";
import { callerAnalysisParameters } from "../AnalysisInput.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_python_wheel";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class PythonWheelService {
  constructor(readonly provider: PythonWheelPort) {}

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
        inputSchema: inspectPythonWheelInputSchema,
        outputSchema: pythonWheelSchema,
        provider: this.provider,
        invalidOutputMessage:
          "Python wheel provider returned malformed output or changed artifact identity.",
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
  report: PythonWheel,
  input: {
    readonly max_file_bytes: number;
    readonly max_entries: number;
    readonly max_metadata_bytes: number;
    readonly max_record_verify_bytes: number;
  },
): boolean => {
  if (
    report.artifact.bytes > input.max_file_bytes ||
    report.coverage.entries > input.max_entries ||
    report.contents.length > input.max_entries ||
    report.coverage.examined_metadata_bytes > input.max_metadata_bytes ||
    report.coverage.verified_record_bytes > input.max_record_verify_bytes
  )
    return false;
  return report.coverage.entries === report.contents.length;
};
