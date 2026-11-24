import { malformedInput } from "../domain/parseFailure.js";
import {
  PYTORCH_PICKLE_FORMAT,
  type PytorchCheckpoint,
} from "../domain/python/pytorchPickle.js";

type GlobalRef = PytorchCheckpoint["pickle"]["globals"][number];
type FlaggedGlobal = PytorchCheckpoint["pickle"]["flagged_globals"][number];

/** Symbolic value on the non-executing Pickle VM stack. */
type SymValue =
  | { readonly kind: "mark" }
  | { readonly kind: "none" }
  | { readonly kind: "bool"; readonly value: boolean }
  | { readonly kind: "int"; readonly value: number }
  | { readonly kind: "float"; readonly value: number }
  | { readonly kind: "str"; readonly value: string }
  | { readonly kind: "bytes"; readonly length: number }
  | { readonly kind: "global"; readonly module: string; readonly name: string }
  | { readonly kind: "tuple"; readonly items: SymValue[] }
  | { readonly kind: "list"; readonly items: SymValue[] }
  | { readonly kind: "dict"; readonly entries: [SymValue, SymValue][] }
  | { readonly kind: "persid"; readonly pid: SymValue }
  | { readonly kind: "tensor"; readonly info: RebuiltTensor }
  | { readonly kind: "reduce"; readonly callable: SymValue; readonly args: SymValue }
  | { readonly kind: "opaque" };

export interface RebuiltTensor {
  readonly rebuilder: string;
  readonly dtype: string | null;
  readonly storage_type: string | null;
  readonly storage_key: string | null;
  readonly storage_location: string | null;
  readonly storage_numel: number | null;
  readonly storage_offset: number | null;
  readonly shape: number[];
  readonly stride: number[];
  readonly requires_grad: boolean | null;
}

export interface DecodedPickleResult {
  readonly protocol: number | null;
  readonly opcodes_decoded: number;
  readonly truncated: boolean;
  readonly terminated_with_stop: boolean;
  readonly reduce_count: number;
  readonly build_count: number;
  readonly newobj_count: number;
  readonly persistent_load_count: number;
  readonly globals: GlobalRef[];
  readonly flagged_globals: FlaggedGlobal[];
  readonly top_level_keys: string[];
  readonly tensors: readonly {
    readonly name: string | null;
    readonly info: RebuiltTensor;
  }[];
  readonly limitations: string[];
}

const STORAGE_DTYPE_MAP: Readonly<Record<string, string>> = {
  FloatStorage: "float32",
  DoubleStorage: "float64",
  HalfStorage: "float16",
  BFloat16Storage: "bfloat16",
  ByteStorage: "uint8",
  CharStorage: "int8",
  ShortStorage: "int16",
  IntStorage: "int32",
  LongStorage: "int64",
  BoolStorage: "bool",
  ComplexFloatStorage: "complex64",
  ComplexDoubleStorage: "complex128",
  QUInt8Storage: "quint8",
  QInt8Storage: "qint8",
  QInt32Storage: "qint32",
  UntypedStorage: "untyped",
};

const CRITICAL_MODULES = new Set([
  "os",
  "posix",
  "nt",
  "subprocess",
  "commands",
  "pty",
  "runpy",
  "ctypes",
  "webbrowser",
  "pip",
]);

const CRITICAL_BUILTINS = new Set([
  "eval",
  "exec",
  "__import__",
  "compile",
  "open",
  "getattr",
  "setattr",
]);

const HIGH_RISK_MODULES = new Set([
  "sys",
  "importlib",
  "shutil",
  "socket",
  "urllib",
  "http",
  "requests",
  "marshal",
  "builtins",
  "__builtin__",
  "types",
  "operator",
  "functools",
  "codecs",
  "pickle",
  "cPickle",
  "_pickle",
]);

const SAFE_COMMON_GLOBALS = new Set([
  "collections.OrderedDict",
  "builtins.set",
  "builtins.frozenset",
  "builtins.slice",
  "builtins.range",
  "builtins.bytearray",
  "builtins.bytes",
  "builtins.complex",
  "builtins.dict",
  "builtins.list",
  "builtins.tuple",
  "builtins.int",
  "builtins.float",
  "builtins.str",
  "builtins.bool",
  "builtins.object",
  "_codecs.encode",
  "torch._utils._rebuild_tensor_v2",
  "torch._utils._rebuild_tensor",
  "torch._utils._rebuild_parameter",
  "torch._utils._rebuild_qtensor",
  "torch._utils._rebuild_device_tensor_from_numpy",
  "torch.Size",
  "torch.FloatStorage",
  "torch.DoubleStorage",
  "torch.HalfStorage",
  "torch.BFloat16Storage",
  "torch.ByteStorage",
  "torch.CharStorage",
  "torch.ShortStorage",
  "torch.IntStorage",
  "torch.LongStorage",
  "torch.BoolStorage",
  "torch.ComplexFloatStorage",
  "torch.ComplexDoubleStorage",
  "torch.storage._load_from_bytes",
  "torch.UntypedStorage",
  "numpy.core.multiarray._reconstruct",
  "numpy._core.multiarray._reconstruct",
  "numpy.core.multiarray.scalar",
  "numpy._core.multiarray.scalar",
  "numpy.ndarray",
  "numpy.dtype",
]);

/** Classify a pickle global reference for code-execution / supply-chain risk. */
export const classifyPickleGlobal = (
  ref: GlobalRef,
): FlaggedGlobal | null => {
  const full = `${ref.module}.${ref.name}`;
  if (SAFE_COMMON_GLOBALS.has(full)) return null;
  const rootModule = ref.module.split(".")[0] ?? ref.module;

  if (CRITICAL_MODULES.has(rootModule)) {
    return {
      ...ref,
      severity: "critical",
      reason: `References OS/process execution or native FFI module ${JSON.stringify(ref.module)}.`,
    };
  }
  if (
    (ref.module === "builtins" || ref.module === "__builtin__") &&
    CRITICAL_BUILTINS.has(ref.name)
  ) {
    return {
      ...ref,
      severity: "critical",
      reason: `References dynamic code execution or attribute-resolution builtin ${full}.`,
    };
  }
  if (full === "torch.hub.load" || full === "torch.load") {
    return {
      ...ref,
      severity: "critical",
      reason: `References nested model/code loader ${full}.`,
    };
  }
  if (
    (ref.module === "types" && (ref.name === "CodeType" || ref.name === "FunctionType")) ||
    (ref.module === "marshal" && ref.name === "loads") ||
    (ref.module === "operator" && (ref.name === "attrgetter" || ref.name === "methodcaller"))
  ) {
    return {
      ...ref,
      severity: "critical",
      reason: `References Python code-object construction or gadget callable ${full}.`,
    };
  }
  if (HIGH_RISK_MODULES.has(rootModule)) {
    return {
      ...ref,
      severity: "high",
      reason: `References privileged standard-library or network module ${JSON.stringify(ref.module)}.`,
    };
  }
  if (!ref.module.startsWith("torch") && !ref.module.startsWith("numpy") && !ref.module.startsWith("collections")) {
    return {
      ...ref,
      severity: "review",
      reason: `References non-tensor external callable ${full} during unpickling.`,
    };
  }
  return null;
};

const utf8 = new TextDecoder("utf-8", { fatal: false });
const latin1 = new TextDecoder("latin1");

const intArray = (value: SymValue | undefined): number[] => {
  if (value?.kind !== "tuple" && value?.kind !== "list") return [];
  const out: number[] = [];
  for (const item of value.items) {
    if (item.kind === "int" && Number.isSafeInteger(item.value) && item.value >= 0)
      out.push(item.value);
  }
  return out;
};

const extractStorageFromPersid = (
  value: SymValue | undefined,
): {
  readonly storage_type: string | null;
  readonly dtype: string | null;
  readonly storage_key: string | null;
  readonly storage_location: string | null;
  readonly storage_numel: number | null;
} => {
  const empty = {
    storage_type: null,
    dtype: null,
    storage_key: null,
    storage_location: null,
    storage_numel: null,
  };
  if (value?.kind !== "persid") return empty;
  if (value.pid.kind !== "tuple") return empty;
  const items = value.pid.items;
  if (items.length < 5 || items[0]?.kind !== "str" || items[0].value !== "storage")
    return empty;
  const storageClass = items[1];
  const storageType =
    storageClass?.kind === "global"
      ? storageClass.name
      : storageClass?.kind === "str"
        ? storageClass.value
        : null;
  const dtype = storageType !== null ? (STORAGE_DTYPE_MAP[storageType] ?? null) : null;
  const storageKey = items[2]?.kind === "str" ? items[2].value : null;
  const storageLocation = items[3]?.kind === "str" ? items[3].value : null;
  const storageNumel =
    items[4]?.kind === "int" && Number.isSafeInteger(items[4].value) && items[4].value >= 0
      ? items[4].value
      : null;
  return {
    storage_type: storageType,
    dtype,
    storage_key: storageKey,
    storage_location: storageLocation,
    storage_numel: storageNumel,
  };
};

const tryBuildSymbolicObject = (callable: SymValue, args: SymValue): SymValue | null => {
  if (callable.kind !== "global" || args.kind !== "tuple") return null;
  const full = `${callable.module}.${callable.name}`;
  if (full === "collections.OrderedDict") {
    const entries: [SymValue, SymValue][] = [];
    const initial = args.items[0];
    if (initial?.kind === "list" || initial?.kind === "tuple") {
      for (const pair of initial.items) {
        if (pair.kind === "tuple" && pair.items.length === 2)
          entries.push([pair.items[0]!, pair.items[1]!]);
      }
    }
    return { kind: "dict", entries };
  }
  if (
    full === "torch._utils._rebuild_tensor_v2" ||
    full === "torch._utils._rebuild_tensor"
  ) {
    const items = args.items;
    const storage = extractStorageFromPersid(items[0]);
    const storageOffset =
      items[1]?.kind === "int" && items[1].value >= 0 ? items[1].value : null;
    const shape = intArray(items[2]);
    const stride = intArray(items[3]);
    const requiresGrad = items[4]?.kind === "bool" ? items[4].value : null;
    return {
      kind: "tensor",
      info: {
        rebuilder: full,
        ...storage,
        storage_offset: storageOffset,
        shape,
        stride,
        requires_grad: requiresGrad,
      },
    };
  }
  if (full === "torch._utils._rebuild_parameter") {
    const inner = args.items[0];
    const requiresGrad = args.items[1]?.kind === "bool" ? args.items[1].value : null;
    if (inner?.kind === "tensor") {
      return {
        kind: "tensor",
        info: {
          ...inner.info,
          rebuilder: full,
          requires_grad: requiresGrad ?? inner.info.requires_grad,
        },
      };
    }
  }
  return null;
};

const collectTensorsFromObject = (
  root: SymValue | undefined,
  prefix: string,
  out: { readonly name: string | null; readonly info: RebuiltTensor }[],
  seen: Set<SymValue>,
): void => {
  if (root === undefined || seen.has(root)) return;
  seen.add(root);
  if (root.kind === "tensor") {
    out.push({ name: prefix === "" ? null : prefix, info: root.info });
    return;
  }
  if (root.kind === "dict") {
    for (const [k, v] of root.entries) {
      const keyName = k.kind === "str" ? k.value : null;
      const nextPrefix =
        keyName === null ? prefix : prefix === "" ? keyName : `${prefix}.${keyName}`;
      collectTensorsFromObject(v, nextPrefix, out, seen);
    }
    return;
  }
  if (root.kind === "reduce") {
    // Handle collections.OrderedDict([(k, v), ...])
    if (
      root.callable.kind === "global" &&
      root.callable.name === "OrderedDict" &&
      root.args.kind === "tuple" &&
      root.args.items[0]?.kind === "list"
    ) {
      for (const pair of root.args.items[0].items) {
        if (pair.kind === "tuple" && pair.items.length === 2) {
          const k = pair.items[0];
          const v = pair.items[1];
          const keyName = k?.kind === "str" ? k.value : null;
          const nextPrefix =
            keyName === null ? prefix : prefix === "" ? keyName : `${prefix}.${keyName}`;
          collectTensorsFromObject(v, nextPrefix, out, seen);
        }
      }
      return;
    }
    collectTensorsFromObject(root.args, prefix, out, seen);
    return;
  }
  if (root.kind === "list" || root.kind === "tuple") {
    for (const item of root.items) collectTensorsFromObject(item, prefix, out, seen);
  }
};

const extractTopLevelKeys = (root: SymValue | undefined): string[] => {
  const keys: string[] = [];
  if (root?.kind === "dict") {
    for (const [k] of root.entries) {
      if (k.kind === "str") keys.push(k.value);
    }
    return keys;
  }
  if (
    root?.kind === "reduce" &&
    root.callable.kind === "global" &&
    root.callable.name === "OrderedDict" &&
    root.args.kind === "tuple" &&
    root.args.items[0]?.kind === "list"
  ) {
    for (const pair of root.args.items[0].items) {
      if (pair.kind === "tuple" && pair.items[0]?.kind === "str")
        keys.push(pair.items[0].value);
    }
  }
  return keys;
};

/** Decode Python pickle protocols 0–5 symbolically without executing any callable. */
export const decodePickleStream = (
  bytes: Uint8Array,
  maxOpcodes: number,
): DecodedPickleResult => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = 0;
  let protocol: number | null = null;
  let opcodesDecoded = 0;
  let truncated = false;
  let terminatedWithStop = false;
  let reduceCount = 0;
  let buildCount = 0;
  let newobjCount = 0;
  let persistentLoadCount = 0;

  const stack: SymValue[] = [];
  const memo = new Map<number, SymValue>();
  const globals: GlobalRef[] = [];
  const flaggedGlobals: FlaggedGlobal[] = [];
  const limitations: string[] = [];

  const need = (count: number): void => {
    if (pos + count > bytes.length)
      throw malformedInput(
        PYTORCH_PICKLE_FORMAT,
        `Truncated pickle stream at byte offset ${String(pos)} (needed ${String(count)} bytes).`,
      );
  };

  const readLine = (): string => {
    const start = pos;
    while (pos < bytes.length && bytes[pos] !== 0x0a) pos += 1;
    if (pos >= bytes.length)
      throw malformedInput(
        PYTORCH_PICKLE_FORMAT,
        `Unterminated newline-delimited pickle operand at byte offset ${String(start)}.`,
      );
    const end = pos > start && bytes[pos - 1] === 0x0d ? pos - 1 : pos;
    pos += 1;
    return latin1.decode(bytes.subarray(start, end));
  };

  const popMark = (): SymValue[] => {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      if (stack[i]?.kind === "mark") {
        const items = stack.slice(i + 1);
        stack.length = i;
        return items;
      }
    }
    return [];
  };

  const recordGlobal = (ref: GlobalRef): void => {
    globals.push(ref);
    const flagged = classifyPickleGlobal(ref);
    if (flagged !== null) flaggedGlobals.push(flagged);
  };

  const readU16 = (): number => {
    need(2);
    const v = view.getUint16(pos, true);
    pos += 2;
    return v;
  };
  const readI32 = (): number => {
    need(4);
    const v = view.getInt32(pos, true);
    pos += 4;
    return v;
  };
  const readU32 = (): number => {
    need(4);
    const v = view.getUint32(pos, true);
    pos += 4;
    return v;
  };
  const readU64Safe = (): number => {
    need(8);
    const lo = view.getUint32(pos, true);
    const hi = view.getUint32(pos + 4, true);
    pos += 8;
    return hi * 0x100000000 + lo;
  };
  const readSignedLittleInt = (len: number): number => {
    need(len);
    if (len === 0) return 0;
    if (len > 6) {
      pos += len;
      return 0;
    }
    let val = 0;
    for (let i = 0; i < len; i += 1) val += bytes[pos + i]! * 256 ** i;
    const signBit = 256 ** len / 2;
    if (val >= signBit) val -= 256 ** len;
    pos += len;
    return val;
  };

  while (pos < bytes.length) {
    if (opcodesDecoded >= maxOpcodes) {
      truncated = true;
      limitations.push(
        `Pickle VM decoding stopped after ${String(maxOpcodes)} opcodes (max_opcodes reached); remaining opcodes were not examined.`,
      );
      break;
    }
    const opOffset = pos;
    const op = bytes[pos]!;
    pos += 1;
    opcodesDecoded += 1;

    switch (op) {
      case 0x80: {
        // PROTO
        need(1);
        const proto = bytes[pos]!;
        pos += 1;
        if (proto > 5)
          throw malformedInput(
            PYTORCH_PICKLE_FORMAT,
            `Unsupported pickle protocol version ${String(proto)}.`,
          );
        protocol = proto;
        break;
      }
      case 0x95: {
        // FRAME (8-byte length prefix, protocol 4+)
        readU64Safe();
        break;
      }
      case 0x2e: {
        // STOP '.'
        terminatedWithStop = true;
        pos = bytes.length;
        break;
      }
      case 0x28: {
        // MARK '('
        stack.push({ kind: "mark" });
        break;
      }
      case 0x30: {
        // POP '0'
        stack.pop();
        break;
      }
      case 0x31: {
        // POP_MARK '1'
        popMark();
        break;
      }
      case 0x32: {
        // DUP '2'
        const top = stack[stack.length - 1];
        if (top !== undefined) stack.push(top);
        break;
      }
      case 0x4e: {
        // NONE 'N'
        stack.push({ kind: "none" });
        break;
      }
      case 0x88: {
        // NEWTRUE
        stack.push({ kind: "bool", value: true });
        break;
      }
      case 0x89: {
        // NEWFALSE
        stack.push({ kind: "bool", value: false });
        break;
      }
      case 0x49: {
        // INT 'I'
        const line = readLine();
        if (line === "01") stack.push({ kind: "bool", value: true });
        else if (line === "00") stack.push({ kind: "bool", value: false });
        else stack.push({ kind: "int", value: Number.parseInt(line, 10) || 0 });
        break;
      }
      case 0x4a: {
        // BININT 'J'
        stack.push({ kind: "int", value: readI32() });
        break;
      }
      case 0x4b: {
        // BININT1 'K'
        need(1);
        stack.push({ kind: "int", value: bytes[pos++]! });
        break;
      }
      case 0x4d: {
        // BININT2 'M'
        stack.push({ kind: "int", value: readU16() });
        break;
      }
      case 0x4c: {
        // LONG 'L'
        const line = readLine().replace(/L$/u, "");
        stack.push({ kind: "int", value: Number.parseInt(line, 10) || 0 });
        break;
      }
      case 0x8a: {
        // LONG1
        need(1);
        const len = bytes[pos++]!;
        stack.push({ kind: "int", value: readSignedLittleInt(len) });
        break;
      }
      case 0x8b: {
        // LONG4
        const len = readI32();
        if (len < 0)
          throw malformedInput(PYTORCH_PICKLE_FORMAT, "Negative LONG4 length.");
        stack.push({ kind: "int", value: readSignedLittleInt(len) });
        break;
      }
      case 0x46: {
        // FLOAT 'F'
        stack.push({ kind: "float", value: Number.parseFloat(readLine()) });
        break;
      }
      case 0x47: {
        // BINFLOAT 'G'
        need(8);
        const val = view.getFloat64(pos, false);
        pos += 8;
        stack.push({ kind: "float", value: val });
        break;
      }
      case 0x53: {
        // STRING 'S'
        const raw = readLine();
        const unquoted =
          raw.length >= 2 &&
          ((raw.startsWith("'") && raw.endsWith("'")) ||
            (raw.startsWith('"') && raw.endsWith('"')))
            ? raw.slice(1, -1)
            : raw;
        stack.push({ kind: "str", value: unquoted });
        break;
      }
      case 0x54: {
        // BINSTRING 'T'
        const len = readI32();
        if (len < 0) throw malformedInput(PYTORCH_PICKLE_FORMAT, "Negative BINSTRING length.");
        need(len);
        stack.push({ kind: "str", value: latin1.decode(bytes.subarray(pos, pos + len)) });
        pos += len;
        break;
      }
      case 0x55: {
        // SHORT_BINSTRING 'U'
        need(1);
        const len = bytes[pos++]!;
        need(len);
        stack.push({ kind: "str", value: latin1.decode(bytes.subarray(pos, pos + len)) });
        pos += len;
        break;
      }
      case 0x56: {
        // UNICODE 'V'
        stack.push({ kind: "str", value: readLine() });
        break;
      }
      case 0x58: {
        // BINUNICODE 'X'
        const len = readU32();
        need(len);
        stack.push({ kind: "str", value: utf8.decode(bytes.subarray(pos, pos + len)) });
        pos += len;
        break;
      }
      case 0x8c: {
        // SHORT_BINUNICODE
        need(1);
        const len = bytes[pos++]!;
        need(len);
        stack.push({ kind: "str", value: utf8.decode(bytes.subarray(pos, pos + len)) });
        pos += len;
        break;
      }
      case 0x8d: {
        // BINUNICODE8
        const len = readU64Safe();
        need(len);
        stack.push({ kind: "str", value: utf8.decode(bytes.subarray(pos, pos + len)) });
        pos += len;
        break;
      }
      case 0x42: {
        // BINBYTES 'B'
        const len = readU32();
        need(len);
        pos += len;
        stack.push({ kind: "bytes", length: len });
        break;
      }
      case 0x43: {
        // SHORT_BINBYTES 'C'
        need(1);
        const len = bytes[pos++]!;
        need(len);
        pos += len;
        stack.push({ kind: "bytes", length: len });
        break;
      }
      case 0x8e:
      case 0x96: {
        // BINBYTES8 / BYTEARRAY8
        const len = readU64Safe();
        need(len);
        pos += len;
        stack.push({ kind: "bytes", length: len });
        break;
      }
      case 0x63: {
        // GLOBAL 'c'
        const mod = readLine();
        const name = readLine();
        recordGlobal({ module: mod, name, opcode: "GLOBAL", offset: opOffset });
        stack.push({ kind: "global", module: mod, name });
        break;
      }
      case 0x93: {
        // STACK_GLOBAL
        const nameVal = stack.pop();
        const modVal = stack.pop();
        const mod = modVal?.kind === "str" ? modVal.value : "<dynamic>";
        const name = nameVal?.kind === "str" ? nameVal.value : "<dynamic>";
        recordGlobal({ module: mod, name, opcode: "STACK_GLOBAL", offset: opOffset });
        stack.push({ kind: "global", module: mod, name });
        break;
      }
      case 0x69: {
        // INST 'i'
        const mod = readLine();
        const name = readLine();
        const args = popMark();
        reduceCount += 1;
        recordGlobal({ module: mod, name, opcode: "INST", offset: opOffset });
        stack.push({
          kind: "reduce",
          callable: { kind: "global", module: mod, name },
          args: { kind: "tuple", items: args },
        });
        break;
      }
      case 0x6f: {
        // OBJ 'o'
        const items = popMark();
        reduceCount += 1;
        const callable = items[0] ?? { kind: "opaque" as const };
        stack.push({
          kind: "reduce",
          callable,
          args: { kind: "tuple", items: items.slice(1) },
        });
        break;
      }
      case 0x52: {
        // REDUCE 'R'
        const args = stack.pop() ?? { kind: "opaque" as const };
        const callable = stack.pop() ?? { kind: "opaque" as const };
        reduceCount += 1;
        const rebuilt = tryBuildSymbolicObject(callable, args);
        stack.push(rebuilt ?? { kind: "reduce", callable, args });
        break;
      }
      case 0x81: {
        // NEWOBJ
        const args = stack.pop() ?? { kind: "opaque" as const };
        const cls = stack.pop() ?? { kind: "opaque" as const };
        newobjCount += 1;
        stack.push({ kind: "reduce", callable: cls, args });
        break;
      }
      case 0x92: {
        // NEWOBJ_EX
        stack.pop(); // kwargs
        const args = stack.pop() ?? { kind: "opaque" as const };
        const cls = stack.pop() ?? { kind: "opaque" as const };
        newobjCount += 1;
        stack.push({ kind: "reduce", callable: cls, args });
        break;
      }
      case 0x62: {
        // BUILD 'b'
        const state = stack.pop();
        const target = stack.pop();
        buildCount += 1;
        if (target?.kind === "tensor") stack.push(target);
        else if (state?.kind === "dict" && target !== undefined) stack.push(state);
        else stack.push(target ?? { kind: "opaque" });
        break;
      }
      case 0x7d: {
        // EMPTY_DICT '}'
        stack.push({ kind: "dict", entries: [] });
        break;
      }
      case 0x64: {
        // DICT 'd'
        const items = popMark();
        const entries: [SymValue, SymValue][] = [];
        for (let i = 0; i + 1 < items.length; i += 2)
          entries.push([items[i]!, items[i + 1]!]);
        stack.push({ kind: "dict", entries });
        break;
      }
      case 0x73: {
        // SETITEM 's'
        const val = stack.pop() ?? { kind: "opaque" as const };
        const key = stack.pop() ?? { kind: "opaque" as const };
        const target = stack[stack.length - 1];
        if (target?.kind === "dict") target.entries.push([key, val]);
        break;
      }
      case 0x75: {
        // SETITEMS 'u'
        const items = popMark();
        const target = stack[stack.length - 1];
        if (target?.kind === "dict") {
          for (let i = 0; i + 1 < items.length; i += 2)
            target.entries.push([items[i]!, items[i + 1]!]);
        }
        break;
      }
      case 0x5d: {
        // EMPTY_LIST ']'
        stack.push({ kind: "list", items: [] });
        break;
      }
      case 0x6c: {
        // LIST 'l'
        stack.push({ kind: "list", items: popMark() });
        break;
      }
      case 0x61: {
        // APPEND 'a'
        const val = stack.pop() ?? { kind: "opaque" as const };
        const target = stack[stack.length - 1];
        if (target?.kind === "list") target.items.push(val);
        break;
      }
      case 0x65: {
        // APPENDS 'e'
        const items = popMark();
        const target = stack[stack.length - 1];
        if (target?.kind === "list") target.items.push(...items);
        break;
      }
      case 0x29: {
        // EMPTY_TUPLE ')'
        stack.push({ kind: "tuple", items: [] });
        break;
      }
      case 0x74: {
        // TUPLE 't'
        stack.push({ kind: "tuple", items: popMark() });
        break;
      }
      case 0x85: {
        // TUPLE1
        const a = stack.pop() ?? { kind: "opaque" as const };
        stack.push({ kind: "tuple", items: [a] });
        break;
      }
      case 0x86: {
        // TUPLE2
        const b = stack.pop() ?? { kind: "opaque" as const };
        const a = stack.pop() ?? { kind: "opaque" as const };
        stack.push({ kind: "tuple", items: [a, b] });
        break;
      }
      case 0x87: {
        // TUPLE3
        const c = stack.pop() ?? { kind: "opaque" as const };
        const b = stack.pop() ?? { kind: "opaque" as const };
        const a = stack.pop() ?? { kind: "opaque" as const };
        stack.push({ kind: "tuple", items: [a, b, c] });
        break;
      }
      case 0x8f: {
        // EMPTY_SET
        stack.push({ kind: "list", items: [] });
        break;
      }
      case 0x90: {
        // ADDITEMS
        const items = popMark();
        const target = stack[stack.length - 1];
        if (target?.kind === "list") target.items.push(...items);
        break;
      }
      case 0x91: {
        // FROZENSET
        stack.push({ kind: "list", items: popMark() });
        break;
      }
      case 0x70: {
        // PUT 'p'
        const idx = Number.parseInt(readLine(), 10);
        const top = stack[stack.length - 1];
        if (top !== undefined && Number.isFinite(idx)) memo.set(idx, top);
        break;
      }
      case 0x71: {
        // BINPUT 'q'
        need(1);
        const idx = bytes[pos++]!;
        const top = stack[stack.length - 1];
        if (top !== undefined) memo.set(idx, top);
        break;
      }
      case 0x72: {
        // LONG_BINPUT 'r'
        const idx = readU32();
        const top = stack[stack.length - 1];
        if (top !== undefined) memo.set(idx, top);
        break;
      }
      case 0x94: {
        // MEMOIZE
        const top = stack[stack.length - 1];
        if (top !== undefined) memo.set(memo.size, top);
        break;
      }
      case 0x67: {
        // GET 'g'
        const idx = Number.parseInt(readLine(), 10);
        stack.push(memo.get(idx) ?? { kind: "opaque" });
        break;
      }
      case 0x68: {
        // BINGET 'h'
        need(1);
        const idx = bytes[pos++]!;
        stack.push(memo.get(idx) ?? { kind: "opaque" });
        break;
      }
      case 0x6a: {
        // LONG_BINGET 'j'
        const idx = readU32();
        stack.push(memo.get(idx) ?? { kind: "opaque" });
        break;
      }
      case 0x50: {
        // PERSID 'P'
        persistentLoadCount += 1;
        stack.push({ kind: "persid", pid: { kind: "str", value: readLine() } });
        break;
      }
      case 0x51: {
        // BINPERSID 'Q'
        persistentLoadCount += 1;
        const pid = stack.pop() ?? { kind: "opaque" as const };
        stack.push({ kind: "persid", pid });
        break;
      }
      case 0x82:
      case 0x83:
      case 0x84: {
        // EXT1 / EXT2 / EXT4
        const code = op === 0x82 ? (need(1), bytes[pos++]!) : op === 0x83 ? readU16() : readI32();
        recordGlobal({
          module: "copyreg._extension_registry",
          name: `EXT_${String(code)}`,
          opcode: "EXT",
          offset: opOffset,
        });
        stack.push({ kind: "global", module: "copyreg._extension_registry", name: `EXT_${String(code)}` });
        break;
      }
      case 0x97: {
        // NEXT_BUFFER
        stack.push({ kind: "opaque" });
        break;
      }
      case 0x98: {
        // READONLY_BUFFER
        break;
      }
      default:
        throw malformedInput(
          PYTORCH_PICKLE_FORMAT,
          `Unknown or unsupported pickle opcode 0x${op.toString(16).padStart(2, "0")} at byte offset ${String(opOffset)}.`,
        );
    }
  }

  const root = stack[stack.length - 1];
  const tensors: { readonly name: string | null; readonly info: RebuiltTensor }[] = [];
  collectTensorsFromObject(root, "", tensors, new Set());
  const topLevelKeys = extractTopLevelKeys(root);

  return {
    protocol,
    opcodes_decoded: opcodesDecoded,
    truncated,
    terminated_with_stop: terminatedWithStop,
    reduce_count: reduceCount,
    build_count: buildCount,
    newobj_count: newobjCount,
    persistent_load_count: persistentLoadCount,
    globals,
    flagged_globals: flaggedGlobals,
    top_level_keys: topLevelKeys,
    tensors,
    limitations,
  };
};
