import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { contractNamed } from "../../src/cli/contractCliDescription.js";
import { TYPESCRIPT_DECLARATIONS_TOOL_CONTRACTS } from "../../src/contracts/javascript/typescriptDeclarationsToolContracts.js";
import { typescriptDeclarationsSchema } from "../../src/domain/javascript/typescriptDeclarations.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const contract = contractNamed(
  TYPESCRIPT_DECLARATIONS_TOOL_CONTRACTS,
  "inspect_typescript_declarations",
);
const completeSchema = contract.outputSchema.safeExtend({
  normalized_result: typescriptDeclarationsSchema,
});

cliTest(
  "inspects TypeScript .d.ts declarations through public CLI without invoking tsc",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-ts-decl-cli-");
    const dtsPath = join(root, "sdk.d.ts");
    await writeFile(
      dtsPath,
      [
        "export interface Config { readonly token: string; }",
        "export declare function init(cfg: Config): Promise<void>;",
        "",
      ].join("\n"),
    );

    const output = await cli.run({
      arguments: ["inspect-typescript-declarations", dtsPath, "--json"],
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const evidence = completeSchema.parse(output.json);
    expect(evidence).toMatchObject({
      confidence: "observed",
      operation: "inspect_typescript_declarations",
      normalized_result: {
        declarations: [
          { kind: "interface", name: "Config", exported: true },
          { kind: "function", name: "init", exported: true },
        ],
      },
    });
  },
);
