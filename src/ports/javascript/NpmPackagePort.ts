import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectNpmPackageInput,
  NpmPackage,
} from "../../domain/javascript/npmPackage.js";
import type { Result } from "../../domain/result.js";

/** Offline read-only npm package tarball (.tgz) inspection port. */
export interface NpmPackagePort {
  readonly identity: ProviderIdentity;
  close(): Promise<void>;
  inspect(
    input: InspectNpmPackageInput,
    options?: ExecutionOptions,
  ): Promise<Result<NpmPackage, AnalysisError>>;
}
