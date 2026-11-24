import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

import { createPythonWheelService } from "../composition/pythonWheel.js";
import { projectAnalysisView } from "../domain/analysisView/analysisView.js";
import { analysisViewRequestSchema } from "../domain/analysisView/analysisViewRequest.js";
import { pythonWheelSummaryViewResultSchema } from "../domain/analysisView/summarySchemas/pythonWheelSummarySchema.js";
import {
  inspectPythonWheelInputSchema,
  pythonWheelEntryRole,
} from "../domain/python/pythonWheel.js";
import {
  buildPythonWheelFixture,
  buildStandardWheelFixture,
  recordHash,
} from "./PythonWheel.fixture.js";
import {
  parsePythonWheel,
  parseRecordCsvLine,
  parseRfc822Headers,
  PYTHON_WHEEL_LIMITATIONS,
} from "./PythonWheelParser.js";

const byteSource = (bytes: Uint8Array) => ({
  prefix: bytes.subarray(0, Math.min(4, bytes.length)),
  size: bytes.length,
  readRange: async (offset: number, length: number) =>
    bytes.subarray(offset, offset + length),
});

const artifactOf = (bytes: Uint8Array, path = "/artifacts/demo.whl") => ({
  path,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

it("classifies Python wheel entry roles accurately", () => {
    expect(pythonWheelEntryRole("demo-1.0.dist-info/METADATA")).toBe("dist-info");
    expect(pythonWheelEntryRole("demo-1.0.data/scripts/run")).toBe("data");
    expect(pythonWheelEntryRole("demo/__init__.py")).toBe("python-source");
    expect(pythonWheelEntryRole("demo/__pycache__/a.pyc")).toBe("python-bytecode");
    expect(pythonWheelEntryRole("demo/types.pyi")).toBe("python-stub");
    expect(pythonWheelEntryRole("demo/py.typed")).toBe("python-stub");
    expect(pythonWheelEntryRole("demo/_ext.cpython-312-x86_64-linux-gnu.so")).toBe(
      "native-extension",
    );
    expect(pythonWheelEntryRole("demo/_ext.pyd")).toBe("native-extension");
    expect(pythonWheelEntryRole("demo/data.json")).toBe("resource");
  });

  it("parses RFC-822 folded headers and PEP 376 CSV lines with quoted paths", () => {
    const { headers } = parseRfc822Headers(
      "Name: demo\nSummary: First line\n continued line\nRequires-Dist: a>=1\nRequires-Dist: b>=2\n\nBody",
    );
    expect(headers.get("name")).toEqual(["demo"]);
    expect(headers.get("summary")).toEqual(["First line\ncontinued line"]);
    expect(headers.get("requires-dist")).toEqual(["a>=1", "b>=2"]);
    expect(parseRecordCsvLine('"pkg/a,b.py",sha256=abc,12')).toEqual([
      "pkg/a,b.py",
      "sha256=abc",
      "12",
    ]);
    expect(parseRecordCsvLine('"unterminated,sha256=abc,12')).toBeNull();
  });

  it("decodes a standard wheel, redacts transport URL credentials, and verifies RECORD", async () => {
    const bytes = await buildStandardWheelFixture({ includeNativeExt: true });
    const input = inspectPythonWheelInputSchema.parse({
      path: "/artifacts/demo_pkg-1.2.3-cp312-cp312-manylinux_2_17_x86_64.whl",
    });
    const result = await parsePythonWheel(
      byteSource(bytes),
      artifactOf(bytes, input.path),
      input,
    );

    expect(result.dist_info?.directory).toBe("demo_pkg-1.2.3.dist-info");
    expect(result.metadata?.name).toBe("demo-pkg");
    expect(result.metadata?.version).toBe("1.2.3");
    expect(result.metadata?.license_expression).toBe("MIT");
    expect(result.metadata?.requires_python).toBe(">=3.10");
    expect(result.metadata?.requires_dist).toEqual([
      "httpx>=0.27",
      "pytest>=8.0; extra == 'dev'",
    ]);
    expect(result.metadata?.home_page_credentials_redacted).toBe(true);
    expect(result.metadata?.home_page).not.toContain("secret");
    expect(result.metadata?.project_urls[0]?.url_credentials_redacted).toBe(true);
    expect(result.metadata?.project_urls[0]?.url).not.toContain("pass");
    expect(result.wheel?.root_is_purelib).toBe(false);
    expect(result.wheel?.tags).toEqual([
      {
        raw: "cp312-cp312-manylinux_2_17_x86_64",
        python_tag: "cp312",
        abi_tag: "cp312",
        platform_tag: "manylinux_2_17_x86_64",
      },
    ]);
    expect(result.entry_points).toEqual([
      { group: "console_scripts", name: "demo-cli", value: "demo_pkg.cli:main" },
      { group: "pytest11", name: "demo_plugin", value: "demo_pkg.plugin" },
    ]);
    expect(result.top_level).toEqual(["demo_pkg"]);
    expect(result.direct_url?.vcs).toBe("git");
    expect(result.direct_url?.commit_id).toBe("abcdef1234567890");
    expect(result.direct_url?.url_credentials_redacted).toBe(true);
    expect(result.native_extensions).toEqual([
      "demo_pkg/_native.cpython-312-x86_64-linux-gnu.so",
    ]);
    expect(result.record.verification_status).toBe("verified");
    expect(result.record.mismatched_count).toBe(0);
    expect(result.record.unrecorded_archive_count).toBe(0);
    expect(result.record.anomalies).toEqual([]);
    expect(result.record.verified_count).toBe(8);
    expect(result.record.unhashed_count).toBe(1); // RECORD itself
  });

  it("detects RECORD hash mismatches and unrecorded archive files", async () => {
    const bytes = await buildStandardWheelFixture({
      tamperInitPy: true,
      extraUnrecorded: true,
    });
    const input = inspectPythonWheelInputSchema.parse({
      path: "/artifacts/tampered.whl",
    });
    const result = await parsePythonWheel(
      byteSource(bytes),
      artifactOf(bytes, input.path),
      input,
    );

    expect(result.record.verification_status).toBe("mismatched");
    expect(result.record.mismatched_count).toBe(1);
    expect(result.record.unrecorded_archive_count).toBe(1);
    expect(
      result.record.anomalies.some(
        (item) =>
          item.kind === "hash-mismatch" && item.path === "demo_pkg/__init__.py",
      ),
    ).toBe(true);
    expect(
      result.record.anomalies.some(
        (item) =>
          item.kind === "unrecorded-in-record" &&
          item.path === "demo_pkg/sneaky.py",
      ),
    ).toBe(true);
  });

  it("reports missing archive files and unsupported hash algorithms explicitly", async () => {
    const init = "x = 1\n";
    const recordText = [
      `pkg/__init__.py,md5=1234567890,${String(init.length)}`,
      "pkg/ghost.py,sha256=abc,10",
      "pkg-1.0.dist-info/RECORD,,",
    ].join("\n");
    const bytes = await buildPythonWheelFixture([
      { name: "pkg/__init__.py", content: init },
      { name: "pkg-1.0.dist-info/METADATA", content: "Name: pkg\nVersion: 1.0\n" },
      { name: "pkg-1.0.dist-info/RECORD", content: recordText },
    ]);
    const input = inspectPythonWheelInputSchema.parse({
      path: "/artifacts/mixed.whl",
    });
    const result = await parsePythonWheel(
      byteSource(bytes),
      artifactOf(bytes, input.path),
      input,
    );

    expect(result.record.verification_status).toBe("mismatched");
    expect(result.record.unsupported_algorithm_count).toBe(1);
    expect(result.record.missing_from_archive_count).toBe(1);
    expect(result.record.unrecorded_archive_count).toBe(1); // METADATA not listed
  });

  it("succeeds with inventory and limitation when *.dist-info is absent or ambiguous", async () => {
    const noDistInfo = await buildPythonWheelFixture([
      { name: "pkg/__init__.py", content: "x = 1\n" },
    ]);
    const input = inspectPythonWheelInputSchema.parse({
      path: "/artifacts/plain.whl",
    });
    const res1 = await parsePythonWheel(
      byteSource(noDistInfo),
      artifactOf(noDistInfo, input.path),
      input,
    );
    expect(res1.dist_info).toBeNull();
    expect(res1.limitations).toContain(PYTHON_WHEEL_LIMITATIONS.noDistInfo);

    const twoDistInfo = await buildPythonWheelFixture([
      { name: "a-1.0.dist-info/METADATA", content: "Name: a\n" },
      { name: "b-1.0.dist-info/METADATA", content: "Name: b\n" },
    ]);
    const res2 = await parsePythonWheel(
      byteSource(twoDistInfo),
      artifactOf(twoDistInfo, input.path),
      input,
    );
    expect(res2.dist_info).toBeNull();
    expect(res2.limitations).toContain(PYTHON_WHEEL_LIMITATIONS.ambiguousDistInfo);
  });

  it("supports verify_record=false and enforces max_record_verify_bytes cleanly", async () => {
    const payload = "a".repeat(256);
    const recordText = [
      `pkg/big.py,${recordHash(payload, "sha256")},${String(payload.length)}`,
      "pkg-1.0.dist-info/RECORD,,",
    ].join("\n");
    const bytes = await buildPythonWheelFixture([
      { name: "pkg/big.py", content: payload },
      { name: "pkg-1.0.dist-info/RECORD", content: recordText },
    ]);

    const skipped = await parsePythonWheel(
      byteSource(bytes),
      artifactOf(bytes),
      inspectPythonWheelInputSchema.parse({
        path: "/artifacts/demo.whl",
        verify_record: false,
      }),
    );
    expect(skipped.record.verification_status).toBe("skipped");
    expect(skipped.limitations).toContain(PYTHON_WHEEL_LIMITATIONS.recordSkipped);

    const budgeted = await parsePythonWheel(
      byteSource(bytes),
      artifactOf(bytes),
      inspectPythonWheelInputSchema.parse({
        path: "/artifacts/demo.whl",
        max_record_verify_bytes: 32,
      }),
    );
    expect(budgeted.record.verification_status).toBe("partial");
    expect(budgeted.record.skipped_budget_count).toBe(1);
  });

  it("rejects non-ZIP bytes with typed malformed error", async () => {
    const bytes = new TextEncoder().encode("not a zip archive");
    await expect(
      parsePythonWheel(
        byteSource(bytes),
        artifactOf(bytes),
        inspectPythonWheelInputSchema.parse({ path: "/artifacts/bad.whl" }),
      ),
    ).rejects.toThrow(/not a ZIP archive/u);
  });

  it("runs end-to-end through PythonWheelService and summary analysisView", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rea-wheel-test-"));
    try {
      const wheelPath = join(dir, "demo_pkg-1.2.3-py3-none-any.whl");
      const bytes = await buildStandardWheelFixture();
      await writeFile(wheelPath, bytes);
      const service = createPythonWheelService();
      try {
        const result = await service.inspect({ path: wheelPath });
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(result.value.operation).toBe("inspect_python_wheel");
        expect(result.value.confidence).toBe("observed");
        const view = projectAnalysisView(
          {
            predicateType: result.value.predicate_type,
            evidenceId: result.value.evidence_id,
            operation: result.value.operation,
            normalizedResult: result.value.normalized_result,
            subject: result.value.subject,
            limitations: result.value.limitations,
          },
          analysisViewRequestSchema.parse({ kind: "summary" }),
        );
        expect(view.ok).toBe(true);
        if (!view.ok) return;
        const summary = pythonWheelSummaryViewResultSchema.parse(view.value);
        expect(summary.summary.metadata_name).toBe("demo-pkg");
        expect(summary.summary.record_verification_status).toBe("verified");
      } finally {
        await service.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
