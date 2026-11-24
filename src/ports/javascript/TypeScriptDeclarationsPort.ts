import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectTypeScriptDeclarationsInput,
  TypeScriptDeclarations,
} from "../../domain/javascript/typescriptDeclarations.js";
import type { Result } from "../../domain/result.js";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";

/** Static .d.ts / .d.ts.map surface reader without invoking tsc. */
export interface TypeScriptDeclarationsPort {
  readonly identity: ProviderIdentity;
  close(): Promise<void>;
  inspect(
    input: InspectTypeScriptDeclarationsInput,
    options?: ExecutionOptions,
  ): Promise<Result<TypeScriptDeclarations, AnalysisError>>;
}
