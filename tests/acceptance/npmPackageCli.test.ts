import { gzipSync } from "node:zlib";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { contractNamed } from "../../src/cli/contractCliDescription.js";
import { NPM_PACKAGE_TOOL_CONTRACTS } from "../../src/contracts/javascript/npmPackageToolContracts.js";
import { npmPackageSchema } from "../../src/domain/javascript/npmPackage.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const npmContract = contractNamed(
  NPM_PACKAGE_TOOL_CONTRACTS,
  "inspect_npm_package",
);
const completeNpmEvidenceSchema = npmContract.outputSchema.safeExtend({
  normalized_result: npmPackageSchema,
});

const buildSimpleTgz = (manifest: Record<string, unknown>): Buffer => {
  const payload = Buffer.from(JSON.stringify(manifest), "utf8");
  const header = Buffer.alloc(512, 0);
  header.write("package/package.json", 0, 100, "utf8");
  header.write("0000644\0", 100, 8, "ascii");
  header.write("0000000\0", 108, 8, "ascii");
  header.write("0000000\0", 116, 8, "ascii");
  header.write(`${payload.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
  header.write("00000000000\0", 136, 12, "ascii");
  header.fill(0x20, 148, 156);
  header.write("0", 156, 1, "ascii");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  let checksum = 0;
  for (let i = 0; i < 512; i += 1) checksum += header[i] ?? 0;
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  const rem = payload.length % 512;
  const padded =
    rem === 0 ? payload : Buffer.concat([payload, Buffer.alloc(512 - rem, 0)]);
  return gzipSync(Buffer.concat([header, padded, Buffer.alloc(1024, 0)]));
};

cliTest(
  "inspects npm .tgz tarballs through public CLI without running npm or lifecycle scripts",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-npm-cli-");
    const tgzPath = join(root, "demo-1.0.0.tgz");
    const tgz = buildSimpleTgz({
      name: "@demo/cli-pkg",
      version: "1.0.0",
      scripts: { postinstall: "node exploit.js" },
      dependencies: { debug: "^4.3.0" },
    });
    await writeFile(tgzPath, tgz);

    const output = await cli.run({
      arguments: ["inspect-npm-package", tgzPath, "--json"],
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const evidence = completeNpmEvidenceSchema.parse(output.json);
    expect(evidence.normalized_result.package_json?.name).toBe("@demo/cli-pkg");
    expect(evidence.normalized_result.package_json?.lifecycle_scripts).toEqual([
      { name: "postinstall", value: "node exploit.js" },
    ]);
    expect(evidence.normalized_result.coverage.entries).toBe(1);
  },
);
