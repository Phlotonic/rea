import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { contractNamed } from "../../src/cli/contractCliDescription.js";
import { PYTORCH_PICKLE_TOOL_CONTRACTS } from "../../src/contracts/python/pytorchPickleToolContracts.js";
import { pytorchCheckpointSchema } from "../../src/domain/python/pytorchPickle.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const contract = contractNamed(
  PYTORCH_PICKLE_TOOL_CONTRACTS,
  "inspect_pytorch_checkpoint",
);
const completeSchema = contract.outputSchema.safeExtend({
  normalized_result: pytorchCheckpointSchema,
});

cliTest(
  "inspects Python pickle for unsafe globals through public CLI without execution",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-pytorch-pickle-cli-");
    const pklPath = join(root, "payload.pkl");
    const hex = execFileSync(
      "python3",
      [
        "-c",
        'import pickle; print(pickle.dumps({"weights": [1, 2, 3]}, protocol=4).hex())',
      ],
      { encoding: "utf8" },
    ).trim();
    await writeFile(pklPath, Buffer.from(hex, "hex"));

    const output = await cli.run({
      arguments: ["inspect-pytorch-checkpoint", pklPath, "--json"],
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const evidence = completeSchema.parse(output.json);
    expect(evidence).toMatchObject({
      confidence: "observed",
      operation: "inspect_pytorch_checkpoint",
      normalized_result: {
        container_format: "raw-pickle",
        pickle: {
          protocol: 4,
          terminated_with_stop: true,
          flagged_globals: [],
          top_level_keys: ["weights"],
        },
      },
    });
  },
);
