import { fixedCeilingConstraint } from "../domain/analysisErrorCore.js";
import { ArtifactOperationError } from "../domain/artifactOperationError.js";
import { decodeLimit } from "../domain/parseFailure.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../domain/parseFailureAnalysisError.js";
import {
  PYTHON_WHEEL_FORMAT,
  PYTHON_WHEEL_LIMIT_MAXIMA,
  type InspectPythonWheelInput,
} from "../domain/python/pythonWheel.js";
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
import { parsePythonWheel } from "./PythonWheelParser.js";
import { PYTHON_WHEEL_PROVIDER_IDENTITY } from "./PythonWheelProviderIdentity.js";

const OPERATION = "inspect_python_wheel";

const budgetRecovery = (
  parameter: keyof typeof PYTHON_WHEEL_LIMIT_MAXIMA,
  selected: number,
): string =>
  selected >= PYTHON_WHEEL_LIMIT_MAXIMA[parameter]
    ? `${parameter} is at this operation's maximum of ${String(PYTHON_WHEEL_LIMIT_MAXIMA[parameter])}; select a complete artifact within that bound.`
    : `Raise ${parameter} above ${String(selected)}, up to ${String(PYTHON_WHEEL_LIMIT_MAXIMA[parameter])}, or select a smaller artifact. The budget applies on the next call; repeating the unchanged request does not raise it.`;

const wheelFailure = (
  cause: unknown,
  input: InspectPythonWheelInput,
  identity?: { readonly sha256: string; readonly bytes: number },
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: PYTHON_WHEEL_PROVIDER_IDENTITY.id,
      operation: OPERATION,
      path: input.path,
      description: "Python wheel",
      recognise: (failure, origin) => {
        if (isParseLimit(failure, PYTHON_WHEEL_FORMAT)) {
          const parameter = (
            Object.keys(
              PYTHON_WHEEL_LIMIT_MAXIMA,
            ) as (keyof typeof PYTHON_WHEEL_LIMIT_MAXIMA)[]
          ).find((name) => name === failure.failure.limit.name);
          return parseLimitConstraint(
            OPERATION,
            failure.failure.limit.name === "max_entries"
              ? "capacity"
              : "memory",
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
          if (
            failure.reason === "limit" &&
            failure.fixedAllowance !== undefined
          )
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
            PYTHON_WHEEL_FORMAT,
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
    PYTHON_WHEEL_PROVIDER_IDENTITY.id,
    OPERATION,
    identity,
  );
};

/** Portable parser over one bounded, identity-checked Python .whl regular file. */
export class PythonWheelProvider {
  readonly identity = PYTHON_WHEEL_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        PYTHON_WHEEL_PROVIDER_IDENTITY.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectPythonWheelInput,
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
              await parsePythonWheel(
                { prefix, size, readRange },
                { path: input.path, sha256, bytes: size },
                input,
                options?.signal,
              ),
            ),
        ),
      );
    } catch (cause) {
      return err(wheelFailure(cause, input, identity));
    }
  }
}
