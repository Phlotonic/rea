import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { NpmPackagePort } from "../../ports/javascript/NpmPackagePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectNpmPackageInputSchema,
  npmPackageSchema,
  type NpmPackage,
} from "../../domain/javascript/npmPackage.js";
import type { Result } from "../../domain/result.js";
import { callerAnalysisParameters } from "../AnalysisInput.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_npm_package";

/** Shared caller validation, output parsing, and Evidence provenance for CLI/MCP. */
export class NpmPackageService {
  constructor(readonly provider: NpmPackagePort) {}

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
        inputSchema: inspectNpmPackageInputSchema,
        outputSchema: npmPackageSchema,
        provider: this.provider,
        invalidOutputMessage:
          "npm package provider returned malformed output or changed artifact identity.",
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
  report: NpmPackage,
  input: {
    readonly max_file_bytes: number;
    readonly max_entries: number;
    readonly max_uncompressed_bytes: number;
  },
): boolean => {
  if (
    report.artifact.bytes > input.max_file_bytes ||
    report.coverage.entries > input.max_entries ||
    report.contents.length > input.max_entries ||
    report.coverage.uncompressed_bytes > input.max_uncompressed_bytes
  )
    return false;
  return report.coverage.entries === report.contents.length;
};
