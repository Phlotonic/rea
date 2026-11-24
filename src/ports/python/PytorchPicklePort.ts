import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectPytorchCheckpointInput,
  PytorchCheckpoint,
} from "../../domain/python/pytorchPickle.js";
import type { Result } from "../../domain/result.js";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";

/** Non-executing static PyTorch/pickle reader port. */
export interface PytorchPicklePort {
  readonly identity: ProviderIdentity;
  close(): Promise<void>;
  inspect(
    input: InspectPytorchCheckpointInput,
    options?: ExecutionOptions,
  ): Promise<Result<PytorchCheckpoint, AnalysisError>>;
}
