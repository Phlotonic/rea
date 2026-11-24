import { fixedCeilingConstraint } from "../domain/analysisErrorCore.js";
import { ArtifactOperationError } from "../domain/artifactOperationError.js";
import { decodeLimit } from "../domain/parseFailure.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../domain/parseFailureAnalysisError.js";
import {
  PYTORCH_PICKLE_FORMAT,
  PYTORCH_PICKLE_LIMIT_MAXIMA,
  type InspectPytorchCheckpointInput,
} from "../domain/python/pytorchPickle.js";
import { err, ok } from "../domain/result.js";
import { errorMessage } from "../kernel/errorMessage.js";
import { classifyProviderFailure } from "../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../providers/offlineArtifactFailure.js";
import {
  ArtifactReaderFailure,
  ArtifactResourceScope,
  artifactFilePrimaryFacts,
  projectArtifactCloseFailure,
  projectStableArtifactFailure,
  translateArtifactFailure,
  withStableArtifactHandle,
} from "../resources/index.js";
import { parsePytorchCheckpoint } from "./PytorchPickleParser.js";
import { PYTORCH_PICKLE_PROVIDER_IDENTITY } from "./PytorchPickleProviderIdentity.js";

const OPERATION = "inspect_pytorch_checkpoint";

const budgetRecovery = (
  parameter: keyof typeof PYTORCH_PICKLE_LIMIT_MAXIMA,
  selected: number,
): string =>
  selected >= PYTORCH_PICKLE_LIMIT_MAXIMA[parameter]
    ? `${parameter} is at this operation's maximum of ${String(PYTORCH_PICKLE_LIMIT_MAXIMA[parameter])}; select a smaller artifact.`
    : `Raise ${parameter} above ${String(selected)}, up to ${String(PYTORCH_PICKLE_LIMIT_MAXIMA[parameter])}, or select a smaller artifact.`;

const checkpointFailure = (
  cause: unknown,
  input: InspectPytorchCheckpointInput,
  identity?: { readonly sha256: string; readonly bytes: number },
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: PYTORCH_PICKLE_PROVIDER_IDENTITY.id,
      operation: OPERATION,
      path: input.path,
      description: "PyTorch checkpoint or pickle",
      recognise: (failure, origin) => {
        if (isParseLimit(failure, PYTORCH_PICKLE_FORMAT)) {
          const parameter = (
            Object.keys(
              PYTORCH_PICKLE_LIMIT_MAXIMA,
            ) as (keyof typeof PYTORCH_PICKLE_LIMIT_MAXIMA)[]
          ).find((name) => name === failure.failure.limit.name);
          return parseLimitConstraint(
            OPERATION,
            failure.failure.limit.name === "max_entries" ? "capacity" : "memory",
            failure,
            {
              path: input.path,
              retryable: false,
              ...(parameter === undefined
                ? {}
                : {
                    remediationAction: budgetRecovery(
                      parameter,
                      failure.failure.limit.maximum,
                    ),
                  }),
            },
          );
        }
        if (
          origin === "owned-or-classified" &&
          failure instanceof ArtifactReaderFailure
        ) {
          if (failure.reason === "limit" && failure.fixedAllowance !== undefined)
            return fixedCeilingConstraint(
              OPERATION,
              failure.boundary ?? "memory",
              failure.message,
              failure.fixedAllowance,
              { cause: failure },
            );
          if (failure.reason === "limit" && failure.boundary === "file-size")
            return undefined;
          if (
            failure.reason !== "path" &&
            failure.reason !== "integrity" &&
            failure.reason !== "cancelled"
          )
            return translateArtifactFailure(OPERATION, failure);
        }
        return undefined;
      },
      fileSize: (failure) =>
        parseLimitConstraint(
          OPERATION,
          "file-size",
          decodeLimit(
            PYTORCH_PICKLE_FORMAT,
            failure.message,
            { name: "max_file_bytes", maximum: input.max_file_bytes },
            { cause: failure },
          ),
          {
            retryable: false,
            remediationAction: budgetRecovery(
              "max_file_bytes",
              input.max_file_bytes,
            ),
          },
        ),
      unclassified: (failure) =>
        new ArtifactOperationError(
          OPERATION,
          "io",
          undefined,
          errorMessage(failure),
          { cause: failure },
        ),
    }),
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    PYTORCH_PICKLE_PROVIDER_IDENTITY.id,
    OPERATION,
    identity,
  );
};

/** Portable static parser over one bounded, identity-checked checkpoint/pickle file. */
export class PytorchPickleProvider {
  readonly identity = PYTORCH_PICKLE_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        PYTORCH_PICKLE_PROVIDER_IDENTITY.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectPytorchCheckpointInput,
    options?: { readonly signal?: AbortSignal },
  ) {
    let identity:
      | { readonly sha256: string; readonly bytes: number }
      | undefined;
    try {
      return await this.#resources.run(async () =>
        withStableArtifactHandle(
          input.path,
          input.max_file_bytes,
          {
            retainBytes: () => 4,
            signal: options?.signal,
            resourceScope: this.#resources,
            onIdentity: (verified) => {
              identity = verified;
            },
          },
          async ({ prefix, size, sha256, readRange }) =>
            ok(
              await parsePytorchCheckpoint(
                { prefix, size, readRange },
                { path: input.path, sha256, bytes: size },
                input,
                options?.signal,
              ),
            ),
        ),
      );
    } catch (cause) {
      return err(checkpointFailure(cause, input, identity));
    }
  }
}
