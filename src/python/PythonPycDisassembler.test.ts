import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

import { createPythonPycService } from "../composition/pythonPyc.js";
import { projectAnalysisView } from "../domain/analysisView/analysisView.js";
import { analysisViewRequestSchema } from "../domain/analysisView/analysisViewRequest.js";
import { inspectPythonPycInputSchema } from "../domain/python/pythonPyc.js";
import {
  disassemblePythonBytecode,
  pythonPycDisassemblyProfileForMagic,
} from "./PythonPycDisassembler.js";
import { parsePythonPyc } from "./PythonPycParser.js";

it("decodes CPython 3.12 instructions, EXTENDED_ARG, inline caches, and jump targets", () => {
  // RESUME 0 | LOAD_GLOBAL (NULL + print, arg=1) + 4 cache units | EXTENDED_ARG 1 + LOAD_CONST 2 (arg=258)
  // | CALL 1 + 3 cache units | POP_TOP | RETURN_CONST 0
  const words = [
    151, 0,
    116, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    144, 1, 100, 2,
    171, 1, 0, 0, 0, 0, 0, 0,
    1, 0,
    121, 0,
  ];
  const result = disassemblePythonBytecode({
    magic: 3531,
    bytecode: Buffer.from(words),
    consts: [{ kind: "none" }],
    names: ["print"],
    varnames: null,
    freevars: null,
    cellvars: null,
    localsplusnames: [],
    maxInstructions: 64,
  });

  expect(result.status).toBe("decoded");
  expect(result.opcode_profile).toBe("cpython-3.12");
  expect(result.instructions.map((ins) => [ins.offset, ins.opname, ins.arg, ins.argrepr])).toEqual([
    [0, "RESUME", 0, null],
    [2, "LOAD_GLOBAL", 1, "NULL + print"],
    [12, "EXTENDED_ARG", 1, null],
    [14, "LOAD_CONST", 258, null],
    [16, "CALL", 1, null],
    [24, "POP_TOP", null, null],
    [26, "RETURN_CONST", 0, "None"],
  ]);
  expect(result.instructions[1]?.cache_entries).toBe(4);
  expect(result.instructions[4]?.cache_entries).toBe(3);
});

it("computes CPython 3.12 forward and backward relative jump targets accurately", () => {
  // 0: LOAD_FAST 0 ('x')
  // 2: POP_JUMP_IF_FALSE 2 -> target = 4 + 2*2 = 8
  // 4: JUMP_BACKWARD 3 -> target = 6 - 3*2 = 0
  // 6: NOP
  // 8: RETURN_CONST 0 (None)
  const result = disassemblePythonBytecode({
    magic: 3531,
    bytecode: Buffer.from([124, 0, 114, 2, 140, 3, 9, 0, 121, 0]),
    consts: [{ kind: "none" }],
    names: [],
    varnames: null,
    freevars: null,
    cellvars: null,
    localsplusnames: ["x"],
    maxInstructions: 64,
  });

  expect(result.instructions[0]).toMatchObject({ opname: "LOAD_FAST", argrepr: "x" });
  expect(result.instructions[1]).toMatchObject({
    offset: 2,
    opname: "POP_JUMP_IF_FALSE",
    jump_target: 8,
    argrepr: "to 8",
  });
  expect(result.instructions[2]).toMatchObject({
    offset: 4,
    opname: "JUMP_BACKWARD",
    jump_target: 0,
    argrepr: "to 0",
  });
});

it("truncates explicitly when max_instructions is reached and marks unsupported magics", () => {
  const truncated = disassemblePythonBytecode({
    magic: 3531,
    bytecode: Buffer.from([9, 0, 9, 0, 9, 0]),
    consts: [],
    names: [],
    varnames: null,
    freevars: null,
    cellvars: null,
    localsplusnames: [],
    maxInstructions: 2,
  });
  expect(truncated.status).toBe("truncated");
  expect(truncated.instruction_count).toBe(2);

  const unsupported = disassemblePythonBytecode({
    magic: 3666,
    bytecode: Buffer.from([9, 0]),
    consts: [],
    names: [],
    varnames: null,
    freevars: null,
    cellvars: null,
    localsplusnames: [],
    maxInstructions: 64,
  });
  expect(unsupported.status).toBe("unsupported-magic");
  expect(unsupported.opcode_profile).toBeNull();
  expect(pythonPycDisassemblyProfileForMagic(3531)).toBe("cpython-3.12");
});

it("matches live CPython dis output on a real compiled .pyc and projects via python-pyc view", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rea-pyc-disasm-"));
  try {
    const pyPath = join(dir, "sample.py");
    const pycPath = join(dir, "sample.pyc");
    await writeFile(
      pyPath,
      [
        "def compute(x, y):",
        "    total = 0",
        "    for i in range(x):",
        "        if i == y:",
        "            total += i * 2",
        "    return total",
        "",
      ].join("\n"),
    );

    const expectedJson = execFileSync(
      "python3",
      [
        "-c",
        `import dis, json, py_compile, marshal, sys
py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)
with open(sys.argv[2], "rb") as f:
    f.seek(16)
    mod = marshal.load(f)
fn = next(c for c in mod.co_consts if getattr(c, "co_name", None) == "compute")
print(json.dumps([[ins.offset, ins.opname, ins.arg] for ins in dis.get_instructions(fn)]))`,
        pyPath,
        pycPath,
      ],
      { encoding: "utf8" },
    );
    const expected = JSON.parse(expectedJson) as [number, string, number | null][];

    const bytes = await readFile(pycPath);
    const parsed = parsePythonPyc(
      bytes,
      {
        path: pycPath,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        bytes: bytes.length,
      },
      inspectPythonPycInputSchema.parse({ path: pycPath, disassemble: true }),
    );
    const compute = parsed.code_objects.find((code) => code.name === "compute");
    expect(compute?.disassembly?.status).toBe("decoded");
    expect(
      compute?.disassembly?.instructions.map((ins) => [
        ins.offset,
        ins.opname,
        ins.arg,
      ]),
    ).toEqual(expected);

    // Verify end-to-end through PythonPycService and python-pyc view selection of `disassembly`.
    const service = createPythonPycService();
    try {
      const ev = await service.inspect({ path: pycPath, disassemble: true });
      expect(ev.ok).toBe(true);
      if (!ev.ok) return;
      const view = projectAnalysisView(
        {
          predicateType: ev.value.predicate_type,
          evidenceId: ev.value.evidence_id,
          operation: ev.value.operation,
          normalizedResult: ev.value.normalized_result,
          subject: ev.value.subject,
          limitations: ev.value.limitations,
        },
        analysisViewRequestSchema.parse({
          kind: "python-pyc",
          collection: "code_objects",
          names: ["compute"],
          fields: ["name", "disassembly"],
        }),
      );
      expect(view.ok).toBe(true);
      if (!view.ok || view.value.kind !== "python-pyc") return;
      expect(view.value.items).toHaveLength(1);
      expect(view.value.items[0]?.disassembly?.status).toBe("decoded");
    } finally {
      await service.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
