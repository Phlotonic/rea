import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { contractNamed } from "../../src/cli/contractCliDescription.js";
import { PYTHON_WHEEL_TOOL_CONTRACTS } from "../../src/contracts/python/pythonWheelToolContracts.js";
import { pythonWheelSchema } from "../../src/domain/python/pythonWheel.js";
import { buildStandardWheelFixture } from "../../src/python/PythonWheel.fixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const wheelContract = contractNamed(
  PYTHON_WHEEL_TOOL_CONTRACTS,
  "inspect_python_wheel",
);
const completeWheelEvidenceSchema = wheelContract.outputSchema.safeExtend({
  normalized_result: pythonWheelSchema,
});

cliTest(
  "inspects Python wheel metadata, tags, entry points and RECORD integrity through CLI",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-python-wheel-cli-");
    const wheelPath = join(root, "demo_pkg-1.2.3-py3-none-any.whl");
    const bytes = await buildStandardWheelFixture();
    await writeFile(wheelPath, bytes);

    const output = await cli.run({
      arguments: ["inspect-python-wheel", wheelPath, "--json"],
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const evidence = completeWheelEvidenceSchema.parse(output.json);
    expect(evidence).toMatchObject({
      confidence: "observed",
      operation: "inspect_python_wheel",
      subject: { local_path: wheelPath, identity: { format: "file" } },
      normalized_result: {
        artifact: {
          path: wheelPath,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          bytes: bytes.length,
        },
        metadata: {
          name: "demo-pkg",
          version: "1.2.3",
          license_expression: "MIT",
        },
        record: {
          verification_status: "verified",
          mismatched_count: 0,
        },
      },
    });
  },
);
