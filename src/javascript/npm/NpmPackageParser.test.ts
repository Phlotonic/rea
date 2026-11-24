import { gzipSync } from "node:zlib";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createNpmPackageService } from "../../composition/npmPackage.js";
import { projectAnalysisView } from "../../domain/analysisView/analysisView.js";
import { analysisViewRequestSchema } from "../../domain/analysisView/analysisViewRequest.js";
import { npmPackageSummaryViewResultSchema } from "../../domain/analysisView/analysisViewResult.js";
import { parseNpmPackage } from "./NpmPackageParser.js";

interface SyntheticTarEntry {
  readonly path: string;
  readonly content?: Buffer | string;
  readonly typeFlag?: "0" | "5" | "2" | "1";
  readonly linkTarget?: string;
}

const buildTarHeader = (
  name: string,
  size: number,
  typeFlag: string,
  linkName = "",
): Buffer => {
  const header = Buffer.alloc(512, 0);
  header.write(name.slice(0, 100), 0, 100, "utf8");
  header.write("0000644\0", 100, 8, "ascii");
  header.write("0000000\0", 108, 8, "ascii");
  header.write("0000000\0", 116, 8, "ascii");
  header.write(`${size.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
  header.write("00000000000\0", 136, 12, "ascii");
  header.fill(0x20, 148, 156);
  header.write(typeFlag, 156, 1, "ascii");
  header.write(linkName.slice(0, 100), 157, 100, "utf8");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");

  let checksum = 0;
  for (let i = 0; i < 512; i += 1) checksum += header[i] ?? 0;
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
};

const pad512 = (buf: Buffer): Buffer => {
  const rem = buf.length % 512;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(512 - rem, 0)]);
};

const buildPaxRecord = (key: string, value: string): Buffer => {
  const body = ` ${key}=${value}\n`;
  let len = Buffer.byteLength(body) + String(Buffer.byteLength(body)).length;
  while (true) {
    const candidate = `${String(len)}${body}`;
    if (Buffer.byteLength(candidate) === len) {
      return Buffer.from(candidate, "utf8");
    }
    len = Buffer.byteLength(candidate);
  }
};

const buildTgz = (entries: readonly SyntheticTarEntry[]): Buffer => {
  const blocks: Buffer[] = [];
  for (const entry of entries) {
    const data =
      entry.content === undefined
        ? Buffer.alloc(0)
        : Buffer.isBuffer(entry.content)
          ? entry.content
          : Buffer.from(entry.content, "utf8");
    const flag = entry.typeFlag ?? "0";
    if (entry.path.length > 99) {
      const paxPayload = buildPaxRecord("path", entry.path);
      blocks.push(buildTarHeader("PaxHeaders/long", paxPayload.length, "x"));
      blocks.push(pad512(paxPayload));
      blocks.push(
        buildTarHeader(
          entry.path.slice(0, 99),
          data.length,
          flag,
          entry.linkTarget ?? "",
        ),
      );
    } else {
      blocks.push(
        buildTarHeader(entry.path, data.length, flag, entry.linkTarget ?? ""),
      );
    }
    if (data.length > 0) blocks.push(pad512(data));
  }
  blocks.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(blocks));
};

it("extracts package.json metadata, lifecycle hooks, types, native addons, credential redaction, and tar anomalies", async () => {
  const longTypesPath = `package/dist/${"nested/".repeat(16)}deep-types.d.ts`;
  const manifest = JSON.stringify({
    name: "@acme/demo-sdk",
    version: "2.3.4",
    description: "Demo SDK package",
    license: "MIT",
    type: "module",
    main: "./dist/index.cjs",
    module: "./dist/index.mjs",
    types: "./dist/index.d.ts",
    exports: {
      ".": { import: "./dist/index.mjs", require: "./dist/index.cjs" },
      "./utils": "./dist/utils.mjs",
    },
    imports: { "#internal": "./dist/internal.mjs" },
    bin: { "acme-cli": "./bin/cli.js" },
    engines: { node: ">=20" },
    os: ["linux", "darwin"],
    cpu: ["x64", "arm64"],
    repository: {
      type: "git",
      url: "https://user:supersecret@github.com/acme/demo-sdk.git",
    },
    homepage: "https://token:hidden@docs.acme.example/sdk",
    dependencies: { zod: "^4.0.0" },
    peerDependencies: { typescript: ">=5.0.0" },
    scripts: {
      test: "vitest run",
      postinstall: "node ./scripts/setup.js",
      prepare: "npm run build",
    },
  });

  const tgz = buildTgz([
    { path: "package/package.json", content: manifest },
    { path: "package/dist/index.mjs", content: "export const ok = true;\n" },
    { path: "package/dist/index.d.ts", content: "export declare const ok: boolean;\n" },
    { path: longTypesPath, content: "export interface Deep { id: string }\n" },
    { path: "package/dist/index.mjs.map", content: '{"version":3}' },
    { path: "package/bin/cli.js", content: "#!/usr/bin/env node\n" },
    { path: "package/prebuilds/linux-x64/addon.node", content: "ELF" },
    { path: "package/README.md", content: "# Demo SDK\n" },
    {
      path: "package/bad-link",
      typeFlag: "2",
      linkTarget: "../../etc/passwd",
    },
    { path: "package/../escape.js", content: "console.log(1)\n" },
  ]);

  const report = await parseNpmPackage(tgz, {
    artifact: {
      path: "/artifacts/demo-sdk-2.3.4.tgz",
      sha256: "a".repeat(64),
      bytes: tgz.length,
    },
    maxEntries: 1000,
    maxUncompressedBytes: 10 * 1024 * 1024,
    maxManifestBytes: 1024 * 1024,
  });

  expect(report.package_json?.name).toBe("@acme/demo-sdk");
  expect(report.package_json?.version).toBe("2.3.4");
  expect(report.package_json?.type).toBe("module");
  expect(report.package_json?.exports_keys).toEqual([".", "./utils"]);
  expect(report.package_json?.imports_keys).toEqual(["#internal"]);
  expect(report.package_json?.bin).toEqual([
    { command: "acme-cli", target: "./bin/cli.js" },
  ]);
  expect(report.package_json?.lifecycle_scripts).toEqual([
    { name: "postinstall", value: "node ./scripts/setup.js" },
    { name: "prepare", value: "npm run build" },
  ]);
  expect(report.package_json?.repository?.url).not.toContain("supersecret");
  expect(report.package_json?.homepage).not.toContain("hidden");
  expect(report.type_declarations).toEqual([
    "package/dist/index.d.ts",
    longTypesPath,
  ]);
  expect(report.source_maps).toEqual(["package/dist/index.mjs.map"]);
  expect(report.native_addons).toEqual(["package/prebuilds/linux-x64/addon.node"]);
  expect(report.suspicious_entries).toEqual([
    {
      path: "package/bad-link",
      reason: "symlink",
      link_target: "../../etc/passwd",
    },
    {
      path: "package/../escape.js",
      reason: "path-traversal",
      link_target: null,
    },
  ]);
  expect(
    report.contents.find((c) => c.path === "package/bin/cli.js")?.role,
  ).toBe("bin");
  expect(report.coverage.lifecycle_script_count).toBe(2);
  expect(report.coverage.native_addon_count).toBe(1);
  expect(report.coverage.suspicious_entry_count).toBe(2);
});

it("succeeds with limitations when package.json is missing or invalid JSON", async () => {
  const tgz = buildTgz([
    { path: "package/package.json", content: "{not valid json" },
    { path: "package/index.js", content: "module.exports = 1;\n" },
  ]);
  const report = await parseNpmPackage(tgz, {
    artifact: {
      path: "/artifacts/broken.tgz",
      sha256: "b".repeat(64),
      bytes: tgz.length,
    },
    maxEntries: 100,
    maxUncompressedBytes: 1024 * 1024,
    maxManifestBytes: 1024 * 1024,
  });
  expect(report.package_json).toBeNull();
  expect(report.contents.length).toBe(2);
  expect(
    report.limitations.some((line) => line.includes("not valid JSON")),
  ).toBe(true);
});

it("enforces max_uncompressed_bytes ceiling against highly compressible payloads", async () => {
  const hugePayload = Buffer.alloc(256 * 1024, 0x41);
  const tgz = buildTgz([{ path: "package/big.txt", content: hugePayload }]);
  await expect(
    parseNpmPackage(tgz, {
      artifact: {
        path: "/artifacts/bomb.tgz",
        sha256: "c".repeat(64),
        bytes: tgz.length,
      },
      maxEntries: 100,
      maxUncompressedBytes: 4096,
      maxManifestBytes: 1024,
    }),
  ).rejects.toThrow(/max_uncompressed_bytes/u);
});

it("runs end-to-end through NpmPackageService and summary analysisView", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rea-npm-pkg-test-"));
  try {
    const tgzPath = join(dir, "sample-1.0.0.tgz");
    const tgz = buildTgz([
      {
        path: "package/package.json",
        content: JSON.stringify({
          name: "sample-pkg",
          version: "1.0.0",
          license: "Apache-2.0",
          main: "index.js",
          scripts: { install: "echo hi" },
          dependencies: { lodash: "^4.17.21" },
        }),
      },
      { path: "package/index.js", content: "module.exports = {};\n" },
    ]);
    await writeFile(tgzPath, tgz);
    const service = createNpmPackageService();
    try {
      const res = await service.inspect({ path: tgzPath });
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
      const summary = npmPackageSummaryViewResultSchema.parse(view.value);
      expect(summary.summary.name).toBe("sample-pkg");
      expect(summary.summary.dependency_count).toBe(1);
      expect(summary.summary.lifecycle_scripts).toEqual([
        { name: "install", value: "echo hi" },
      ]);
    } finally {
      await service.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
