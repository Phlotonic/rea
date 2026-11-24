import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectPythonWheelInput,
  PythonWheel,
} from "../../domain/python/pythonWheel.js";
import type { Result } from "../../domain/result.js";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";

/** Stable read and .whl ZIP/dist-info/RECORD decoding, independent of pip or Python. */
export interface PythonWheelPort {
  readonly identity: ProviderIdentity;
  close(): Promise<void>;
  inspect(
    input: InspectPythonWheelInput,
    options?: ExecutionOptions,
  ): Promise<Result<PythonWheel, AnalysisError>>;
}
