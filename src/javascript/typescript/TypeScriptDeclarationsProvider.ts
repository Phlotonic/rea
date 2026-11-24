import { fixedCeilingConstraint } from "../../domain/analysisErrorCore.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  TYPESCRIPT_DECL_LIMIT_MAXIMA,
  TYPESCRIPT_DECLARATIONS_FORMAT,
  type InspectTypeScriptDeclarationsInput,
} from "../../domain/javascript/typescriptDeclarations.js";
import { decodeLimit, malformedInput } from "../../domain/parseFailure.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../../domain/parseFailureAnalysisError.js";
import { err, ok } from "../../domain/result.js";
import { errorMessage } from "../../kernel/errorMessage.js";
import { classifyProviderFailure } from "../../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../../providers/offlineArtifactFailure.js";
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
  parseTypeScriptDeclarations,
  type DeclarationMapInput,
} from "./TypeScriptDeclarationsParser.js";
import { TYPESCRIPT_DECLARATIONS_PROVIDER_IDENTITY } from "./TypeScriptDeclarationsProviderIdentity.js";

const OPERATION = "inspect_typescript_declarations";
const UTF8 = new TextDecoder("utf-8", { fatal: true });

const declFailure = (
  cause: unknown,
  input: InspectTypeScriptDeclarationsInput,
  identity?: { readonly sha256: string; readonly bytes: number },
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: TYPESCRIPT_DECLARATIONS_PROVIDER_IDENTITY.id,
      operation: OPERATION,
      path: input.path,
      description: "TypeScript declaration file",
      recognise: (failure, origin) => {
        if (isParseLimit(failure, TYPESCRIPT_DECLARATIONS_FORMAT)) {
          return parseLimitConstraint(OPERATION, "memory", failure, {
            path: input.path,
            retryable: false,
          });
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
            TYPESCRIPT_DECLARATIONS_FORMAT,
            failure.message,
            { name: "max_file_bytes", maximum: input.max_file_bytes },
            { cause: failure },
          ),
          {
            retryable: false,
            remediationAction: `Raise max_file_bytes up to ${String(TYPESCRIPT_DECL_LIMIT_MAXIMA.max_file_bytes)} or select a smaller declaration file.`,
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
    TYPESCRIPT_DECLARATIONS_PROVIDER_IDENTITY.id,
    OPERATION,
    identity,
  );
};

/** Portable static .d.ts/.d.mts/.d.cts reader over stable artifact handles. */
export class TypeScriptDeclarationsProvider {
  readonly identity = TYPESCRIPT_DECLARATIONS_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        TYPESCRIPT_DECLARATIONS_PROVIDER_IDENTITY.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectTypeScriptDeclarationsInput,
    options?: { readonly signal?: AbortSignal },
  ) {
    let identity:
      | { readonly sha256: string; readonly bytes: number }
      | undefined;
    try {
      return await this.#resources.run(async () => {
        let mapInput: DeclarationMapInput | undefined;
        if (input.declaration_map_path !== undefined) {
          mapInput = await withStableArtifactHandle(
            input.declaration_map_path,
            input.max_file_bytes,
            {
              retainBytes: () => 4,
              signal: options?.signal,
              resourceScope: this.#resources,
            },
            async ({ size, sha256, readRange }) => {
              const raw = await readRange(0, size);
              let text: string;
              try {
                text = UTF8.decode(raw);
              } catch {
                throw malformedInput(
                  TYPESCRIPT_DECLARATIONS_FORMAT,
                  "Selected declaration map is not valid UTF-8.",
                );
              }
              return { path: input.declaration_map_path!, sha256, text };
            },
          );
        }

        return withStableArtifactHandle(
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
          async ({ size, sha256, readRange }) => {
            const raw = await readRange(0, size);
            let text: string;
            try {
              text = UTF8.decode(raw);
            } catch {
              throw malformedInput(
                TYPESCRIPT_DECLARATIONS_FORMAT,
                "Selected TypeScript declaration file is not valid UTF-8.",
              );
            }
            return ok(
              parseTypeScriptDeclarations(
                text,
                { path: input.path, sha256, bytes: size },
                input,
                mapInput,
              ),
            );
          },
        );
      });
    } catch (cause) {
      return err(declFailure(cause, input, identity));
    }
  }
}
