import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPytorchCheckpointInputSchema,
  pytorchCheckpointSchema,
  type PytorchCheckpoint,
} from "../../domain/python/pytorchPickle.js";
import type { Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { PytorchPicklePort } from "../../ports/python/PytorchPicklePort.js";
import { callerAnalysisParameters } from "../AnalysisInput.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_pytorch_checkpoint";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class PytorchPickleService {
  constructor(readonly provider: PytorchPicklePort) {}

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
        inputSchema: inspectPytorchCheckpointInputSchema,
        outputSchema: pytorchCheckpointSchema,
        provider: this.provider,
        invalidOutputMessage:
          "PyTorch/pickle provider returned malformed output or changed artifact identity.",
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
  report: PytorchCheckpoint,
  input: {
    readonly max_file_bytes: number;
    readonly max_entries: number;
    readonly max_pickle_bytes: number;
    readonly max_opcodes: number;
  },
): boolean =>
  report.artifact.bytes <= input.max_file_bytes &&
  report.coverage.entries <= input.max_entries &&
  report.coverage.examined_pickle_bytes <= input.max_pickle_bytes &&
  report.coverage.opcodes_decoded <= input.max_opcodes;
