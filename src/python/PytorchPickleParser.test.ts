import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BlobReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { expect, it } from "vitest";

import { createPytorchPickleService } from "../composition/pytorchPickle.js";
import { projectAnalysisView } from "../domain/analysisView/analysisView.js";
import { analysisViewRequestSchema } from "../domain/analysisView/analysisViewRequest.js";
import { pytorchPickleSummaryViewResultSchema } from "../domain/analysisView/summarySchemas/pytorchPickleSummarySchema.js";
import { inspectPytorchCheckpointInputSchema } from "../domain/python/pytorchPickle.js";
import { decodePickleStream } from "./PickleOpcodeDecoder.js";
import { parsePytorchCheckpoint } from "./PytorchPickleParser.js";

const byteSource = (bytes: Uint8Array) => ({
  prefix: bytes.subarray(0, Math.min(4, bytes.length)),
  size: bytes.length,
  readRange: async (offset: number, length: number) =>
    bytes.subarray(offset, offset + length),
});

const artifactOf = (bytes: Uint8Array, path = "/artifacts/model.pt") => ({
  path,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

const buildZip = async (
  entries: readonly { readonly name: string; readonly bytes: Uint8Array }[],
): Promise<Uint8Array> => {
  const writer = new Uint8ArrayWriter();
  const zip = new ZipWriter(writer, { bufferedWrite: true });
  for (const item of entries)
    await zip.add(item.name, new BlobReader(new Blob([item.bytes])));
  await zip.close();
  return writer.getData();
};

/** Generate a real Python pickle stream via python3 without executing anything on read. */
const pythonPickleHex = (script: string): Uint8Array => {
  const hex = execFileSync("python3", ["-c", script], { encoding: "utf8" }).trim();
  return Buffer.from(hex, "hex");
};

it("detects critical code-execution globals in a malicious pickle without executing it", () => {
  const payload = pythonPickleHex(`
import pickle
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))
print(pickle.dumps(Exploit(), protocol=4).hex())
`);
  const decoded = decodePickleStream(payload, 10000);
  expect(decoded.protocol).toBe(4);
  expect(decoded.terminated_with_stop).toBe(true);
  expect(decoded.reduce_count).toBeGreaterThanOrEqual(1);
  expect(
    decoded.flagged_globals.some(
      (g) =>
        (g.module === "posix" || g.module === "os") &&
        g.name === "system" &&
        g.severity === "critical",
    ),
  ).toBe(true);
});

it("reconstructs PyTorch ZIP checkpoint tensors, storages, version, and byteorder", async () => {
  // Hand-crafted protocol-2 PyTorch-compatible data.pkl mimicking torch.save(state_dict):
  // OrderedDict([("linear.weight", torch._utils._rebuild_tensor_v2(
  //   BINPERSID(('storage', torch.FloatStorage, '0', 'cpu', 6)),
  //   0, (2, 3), (3, 1), False, OrderedDict()
  // ))])
  const pkl = pythonPickleHex(`
import io, pickle, collections
buf = io.BytesIO()
class DummyStorage: pass
class StorageRef:
    def __init__(self, key): self.key = key
class FakeTensor:
    def __reduce__(self):
        return (RebuildPlaceholder, (StorageRef("0"), 0, (2, 3), (3, 1), False, collections.OrderedDict()))
# Build exact opcode stream directly using pickletools-compatible opcodes
stream = (
    b"\\x80\\x02"
    b"ccollections\\nOrderedDict\\n)R("
    b"X\\x0d\\x00\\x00\\x00linear.weight"
    b"ctorch._utils\\n_rebuild_tensor_v2\\n("
    b"(X\\x07\\x00\\x00\\x00storage"
    b"ctorch\\nFloatStorage\\n"
    b"X\\x01\\x00\\x00\\x000"
    b"X\\x03\\x00\\x00\\x00cpu"
    b"K\\x06tQ"
    b"K\\x00"
    b"K\\x02K\\x03\\x86"
    b"K\\x03K\\x01\\x86"
    b"\\x89"
    b"ccollections\\nOrderedDict\\n)R"
    b"tR"
    b"u."
)
print(stream.hex())
`);
  const zipBytes = await buildZip([
    { name: "archive/data.pkl", bytes: pkl },
    { name: "archive/version", bytes: new TextEncoder().encode("3\n") },
    { name: "archive/byteorder", bytes: new TextEncoder().encode("little\n") },
    { name: "archive/data/0", bytes: new Uint8Array(24) },
  ]);

  const input = inspectPytorchCheckpointInputSchema.parse({
    path: "/artifacts/linear.pt",
  });
  const result = await parsePytorchCheckpoint(
    byteSource(zipBytes),
    artifactOf(zipBytes, input.path),
    input,
  );

  expect(result.container_format).toBe("pytorch-zip");
  expect(result.archive?.prefix).toBe("archive");
  expect(result.archive?.version).toBe("3");
  expect(result.archive?.byteorder).toBe("little");
  expect(result.archive?.storages).toHaveLength(1);
  expect(result.pickle.protocol).toBe(2);
  expect(result.pickle.flagged_globals).toEqual([]);
  expect(result.pickle.top_level_keys).toEqual(["linear.weight"]);
  expect(result.tensors).toEqual([
    {
      name: "linear.weight",
      rebuilder: "torch._utils._rebuild_tensor_v2",
      dtype: "float32",
      storage_type: "FloatStorage",
      storage_key: "0",
      storage_location: "cpu",
      storage_numel: 6,
      storage_offset: 0,
      shape: [2, 3],
      stride: [3, 1],
      requires_grad: false,
      archive_member: "archive/data/0",
      archive_bytes: 24,
    },
  ]);
});

it("runs end-to-end on raw pickle through PytorchPickleService and summary view", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rea-pickle-test-"));
  try {
    const pklPath = join(dir, "sample.pkl");
    const bytes = pythonPickleHex(
      'import pickle; print(pickle.dumps({"lr": 0.001, "epoch": 5}, protocol=4).hex())',
    );
    await writeFile(pklPath, bytes);
    const service = createPytorchPickleService();
    try {
      const res = await service.inspect({ path: pklPath });
      expect(res.ok).toBe(true);
      if (!res.ok) return;
      expect(res.value.operation).toBe("inspect_pytorch_checkpoint");
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
      const summary = pytorchPickleSummaryViewResultSchema.parse(view.value);
      expect(summary.summary.container_format).toBe("raw-pickle");
      expect(summary.summary.pickle_protocol).toBe(4);
      expect(summary.summary.top_level_key_count).toBe(2);
      expect(summary.summary.flagged_global_count).toBe(0);
    } finally {
      await service.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
