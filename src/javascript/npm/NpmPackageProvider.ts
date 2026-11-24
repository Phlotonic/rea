import { NPM_PACKAGE_PROVIDER_IDENTITY } from "./NpmPackageProviderIdentity.js";
import {
  ArtifactReaderFailure,
  ArtifactResourceScope,
  artifactFilePrimaryFacts,
  projectArtifactCloseFailure,
  projectStableArtifactFailure,
  translateArtifactFailure,
  withStableArtifactHandle,
} from "../../resources/index.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../../domain/parseFailureAnalysisError.js";
import { decodeLimit } from "../../domain/parseFailure.js";
import { fixedCeilingConstraint } from "../../domain/analysisErrorCore.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  NPM_PACKAGE_FORMAT,
  NPM_PACKAGE_LIMIT_MAXIMA,
  type InspectNpmPackageInput,
  type NpmPackage,
} from "../../domain/javascript/npmPackage.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../../domain/result.js";
import { errorMessage } from "../../kernel/errorMessage.js";
import { classifyProviderFailure } from "../../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../../providers/offlineArtifactFailure.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { NpmPackagePort } from "../../ports/javascript/NpmPackagePort.js";
import { parseNpmPackage } from "./NpmPackageParser.js";

const OPERATION = "inspect_npm_package";

const budgetRecovery = (
  parameter: keyof typeof NPM_PACKAGE_LIMIT_MAXIMA,
  selected: number,
): string =>
  selected >= NPM_PACKAGE_LIMIT_MAXIMA[parameter]
    ? `${parameter} is at this operation's maximum of ${String(NPM_PACKAGE_LIMIT_MAXIMA[parameter])}; select a complete artifact within that bound.`
    : `Raise ${parameter} above ${String(selected)}, up to ${String(NPM_PACKAGE_LIMIT_MAXIMA[parameter])}, or select a smaller artifact. The budget applies on the next call; repeating the unchanged request does not raise it.`;

const npmPackageFailure = (
  cause: unknown,
  input: InspectNpmPackageInput,
  identity?: { readonly sha256: string; readonly bytes: number },
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: NPM_PACKAGE_PROVIDER_IDENTITY.id,
      operation: OPERATION,
      path: input.path,
      description: "npm package tarball",
      recognise: (failure, origin) => {
        if (isParseLimit(failure, NPM_PACKAGE_FORMAT)) {
          const parameter = (
            Object.keys(
              NPM_PACKAGE_LIMIT_MAXIMA,
            ) as (keyof typeof NPM_PACKAGE_LIMIT_MAXIMA)[]
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
            NPM_PACKAGE_FORMAT,
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
    NPM_PACKAGE_PROVIDER_IDENTITY.id,
    OPERATION,
    identity,
  );
};

/** Offline provider reading local npm `.tgz` tarballs without running scripts or npm. */
export class NpmPackageProvider implements NpmPackagePort {
  readonly identity = NPM_PACKAGE_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        NPM_PACKAGE_PROVIDER_IDENTITY.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectNpmPackageInput,
    options?: ExecutionOptions,
  ): Promise<Result<NpmPackage, AnalysisError>> {
    let identity: { readonly sha256: string; readonly bytes: number } | undefined;
    try {
      return await this.#resources.run(async () =>
        withStableArtifactHandle(
          input.path,
          input.max_file_bytes,
          {
            retainBytes: (size) => size,
            signal: options?.signal,
            resourceScope: this.#resources,
            onIdentity: (verified) => {
              identity = verified;
            },
          },
          async ({ prefix, size, sha256 }) =>
            ok(
              await parseNpmPackage(
                Buffer.from(prefix.buffer, prefix.byteOffset, prefix.byteLength),
                {
                  artifact: {
                    path: input.path,
                    sha256,
                    bytes: size,
                  },
                  maxEntries: input.max_entries,
                  maxUncompressedBytes: input.max_uncompressed_bytes,
                  maxManifestBytes: input.max_manifest_bytes,
                },
              ),
            ),
        ),
      );
    } catch (cause) {
      return err(npmPackageFailure(cause, input, identity));
    }
  }
}
