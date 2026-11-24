import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

import { resolveArtifactPathByContext } from "../../application/javascript/JavaScriptArtifactPathResolution.js";
import { JavaScriptJsonDocuments } from "../../application/javascript/JavaScriptJsonDocuments.js";
import { createTypeScriptDeclarationsService } from "../../composition/typescriptDeclarations.js";
import { projectAnalysisView } from "../../domain/analysisView/analysisView.js";
import { analysisViewRequestSchema } from "../../domain/analysisView/analysisViewRequest.js";
import { typescriptDeclarationsSummaryViewResultSchema } from "../../domain/analysisView/summarySchemas/typescriptDeclarationsSummarySchema.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import {
  expandTsconfigAliasCandidates,
  findEnclosingTsconfig,
} from "../../domain/javascript/tsconfigPathAliases.js";
import { inspectTypeScriptDeclarationsInputSchema } from "../../domain/javascript/typescriptDeclarations.js";
import { parseTypeScriptDeclarations } from "./TypeScriptDeclarationsParser.js";

const SAMPLE_DTS = [
  '/// <reference types="node" />',
  'import type { Readable } from "node:stream";',
  "",
  "export interface ClientOptions<T = unknown> extends BaseOptions {",
  "  readonly endpoint: string;",
  "  timeoutMs?: number;",
  "  parse?(raw: string): T;",
  "}",
  "",
  "export declare class SdkClient<T> extends BaseClient implements Disposable {",
  "  static readonly VERSION: string;",
  "  constructor(options: ClientOptions<T>);",
  "  fetch(stream: Readable): Promise<T>;",
  "}",
  "",
  "export declare function createClient<T>(options: ClientOptions<T>): SdkClient<T>;",
  "export type ClientId = string;",
  "export declare const enum Status { Ok = 0, Error = 1 }",
  'export { Helper } from "./helper.js";',
  'export * from "./types.js";',
  'declare module "custom-plugin" { export interface Hook {} }',
  "//# sourceMappingURL=index.d.ts.map",
].join("\n");

const artifactFile = (
  path: string,
  kind: JavaScriptArtifactFile["kind"],
  value: string,
): JavaScriptArtifactFile => ({
  path,
  container_sha256: "a".repeat(64),
  sha256: createHash("sha256").update(value).digest("hex"),
  bytes: Buffer.byteLength(value),
  inventory_artifact_id: `art:${path}`,
  kind,
  unpacked: false,
  text: { included: true, value },
});

it("extracts TypeScript declaration surfaces, members, triple-slash refs, and declaration map", () => {
  const bytes = Buffer.from(SAMPLE_DTS, "utf8");
  const result = parseTypeScriptDeclarations(
    SAMPLE_DTS,
    {
      path: "/artifacts/dist/index.d.ts",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
    inspectTypeScriptDeclarationsInputSchema.parse({
      path: "/artifacts/dist/index.d.ts",
    }),
    {
      path: "/artifacts/dist/index.d.ts.map",
      sha256: "b".repeat(64),
      text: JSON.stringify({
        version: 3,
        file: "index.d.ts",
        sourceRoot: "../src",
        sources: ["index.ts", "client.ts"],
        mappings: "AAAA",
      }),
    },
  );

  expect(result.source_mapping_url).toBe("index.d.ts.map");
  expect(result.declaration_map).toMatchObject({
    version: 3,
    source_root: "../src",
    sources: ["index.ts", "client.ts"],
    has_mappings: true,
  });
  expect(result.triple_slash_references).toEqual([
    { kind: "types", value: "node", line: 1 },
  ]);
  expect(result.imports).toEqual([
    { specifier: "node:stream", type_only: true, names: ["Readable"], line: 2 },
  ]);
  expect(result.declarations.map((d) => [d.kind, d.name, d.exported])).toEqual([
    ["interface", "ClientOptions", true],
    ["class", "SdkClient", true],
    ["function", "createClient", true],
    ["type-alias", "ClientId", true],
    ["const-enum", "Status", true],
    ["re-export", "Helper", true],
    ["export-all", "*", true],
    ["module-augmentation", "custom-plugin", false],
  ]);
  const sdk = result.declarations.find((d) => d.name === "SdkClient");
  expect(sdk?.extends).toEqual(["BaseClient"]);
  expect(sdk?.implements).toEqual(["Disposable"]);
  expect(sdk?.members.map((m) => [m.name, m.kind, m.static])).toEqual([
    ["VERSION", "property", true],
    ["constructor", "constructor", false],
    ["fetch", "method", false],
  ]);
});

it("resolves tsconfig.json extends, paths wildcards, and baseUrl in JavaScriptArtifactPathResolution", () => {
  const baseTsconfig = `{
    // base config with JSONC comment
    "compilerOptions": {
      "baseUrl": ".",
      "paths": {
        "@shared/*": ["src/shared/*"],
      }
    }
  }`;
  const appTsconfig = `{
    "extends": "./tsconfig.base.json",
    "compilerOptions": {
      "paths": {
        "@/*": ["src/*"],
        "@shared/*": ["src/shared/*"]
      }
    }
  }`;
  const files = new Map<string, JavaScriptArtifactFile>(
    [
      artifactFile("tsconfig.base.json", "json", baseTsconfig),
      artifactFile("tsconfig.json", "json", appTsconfig),
      artifactFile("src/app/main.ts", "javascript", 'import { x } from "@/utils/auth";'),
      artifactFile("src/utils/auth.ts", "javascript", "export const x = 1;"),
      artifactFile("src/shared/log.ts", "javascript", "export const log = () => {};"),
    ].map((f) => [f.path, f]),
  );

  const loaded = findEnclosingTsconfig("src/app/main.ts", files);
  expect(loaded?.configPath).toBe("tsconfig.json");
  expect(expandTsconfigAliasCandidates("@/utils/auth", loaded!)).toContain(
    "src/utils/auth",
  );

  const jsonDocuments = new JavaScriptJsonDocuments();
  const res1 = resolveArtifactPathByContext({
    jsonDocuments,
    declaredPath: "@/utils/auth",
    sourcePath: "src/app/main.ts",
    context: "module-specifier",
    moduleKind: "import",
    files,
  });
  expect(res1.resolution_status).toBe("resolved");
  expect(res1.resolved_path).toBe("src/utils/auth.ts");
  expect(res1.limitations.some((l) => l.includes("tsconfig.json"))).toBe(true);

  const res2 = resolveArtifactPathByContext({
    jsonDocuments,
    declaredPath: "@shared/log",
    sourcePath: "src/app/main.ts",
    context: "module-specifier",
    moduleKind: "import",
    files,
  });
  expect(res2.resolution_status).toBe("resolved");
  expect(res2.resolved_path).toBe("src/shared/log.ts");
});

it("runs end-to-end through TypeScriptDeclarationsService and summary view", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rea-ts-decl-test-"));
  try {
    const dtsPath = join(dir, "index.d.ts");
    await writeFile(dtsPath, SAMPLE_DTS);
    const service = createTypeScriptDeclarationsService();
    try {
      const res = await service.inspect({ path: dtsPath });
      expect(res.ok).toBe(true);
      if (!res.ok) return;
      const view = projectAnalysisView(
        {
          predicateType: res.value.predicate_type,
          evidenceId: res.value.evidence_id,
          operation: res.value.operation,
          normalizedResult: res.value.normalized_result,
          subject: res.value.subject,
          limitations: res.value.limitations,
        },
        analysisViewRequestSchema.parse({ kind: "summary" }),
      );
      expect(view.ok).toBe(true);
      if (!view.ok) return;
      const summary = typescriptDeclarationsSummaryViewResultSchema.parse(view.value);
      expect(summary.summary.declaration_count).toBe(8);
      expect(summary.summary.exported_count).toBe(7);
    } finally {
      await service.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
