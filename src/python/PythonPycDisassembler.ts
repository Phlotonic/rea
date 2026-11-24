import type {
  PythonPycConst,
  PythonPycDisassembly,
  PythonPycInstruction,
} from "../domain/python/pythonPyc.js";

const NB_OPS: readonly string[] = [
  "+",
  "&",
  "//",
  "<<",
  "@",
  "*",
  "%",
  "|",
  "**",
  ">>",
  "-",
  "/",
  "^",
  "+=",
  "&=",
  "//=",
  "<<=",
  "@=",
  "*=",
  "%=",
  "|=",
  "**=",
  ">>=",
  "-=",
  "/=",
  "^=",
];

const CMP_OPS: readonly string[] = ["<", "<=", "==", "!=", ">", ">="];

const INTRINSIC_1_DESCS: readonly string[] = [
  "INTRINSIC_1_INVALID",
  "INTRINSIC_PRINT",
  "INTRINSIC_IMPORT_STAR",
  "INTRINSIC_STOPITERATION_ERROR",
  "INTRINSIC_ASYNC_GEN_WRAP",
  "INTRINSIC_UNARY_POSITIVE",
  "INTRINSIC_LIST_TO_TUPLE",
  "INTRINSIC_TYPEVAR",
  "INTRINSIC_PARAMSPEC",
  "INTRINSIC_TYPEVARTUPLE",
  "INTRINSIC_SUBSCRIPT_GENERIC",
  "INTRINSIC_TYPEALIAS",
];

const INTRINSIC_2_DESCS: readonly string[] = [
  "INTRINSIC_2_INVALID",
  "INTRINSIC_PREP_RERAISE_STAR",
  "INTRINSIC_TYPEVAR_WITH_BOUND",
  "INTRINSIC_TYPEVAR_WITH_CONSTRAINTS",
  "INTRINSIC_SET_FUNCTION_TYPE_PARAMS",
];

interface OpcodeProfile {
  readonly id: string;
  readonly haveArgument: number;
  readonly extendedArg: number;
  readonly opnames: ReadonlyMap<number, string>;
  readonly inlineCaches: ReadonlyMap<number, number>;
  readonly hasConst: ReadonlySet<number>;
  readonly hasName: ReadonlySet<number>;
  readonly hasLocal: ReadonlySet<number>;
  readonly hasFree: ReadonlySet<number>;
  readonly hasCompare: ReadonlySet<number>;
  readonly hasJrelForward: ReadonlySet<number>;
  readonly hasJrelBackward: ReadonlySet<number>;
  readonly hasJabs: ReadonlySet<number>;
  /** Multiplier to convert jump arg into byte offset delta (2 for 3.10+ wordcode, 1 for 3.8–3.9). */
  readonly jumpScale: 1 | 2;
  /** Bit shifts used by 3.11+/3.12+ for specialized name/compare opargs. */
  readonly shiftedLoadGlobal: boolean;
  readonly shiftedLoadAttr: boolean;
  readonly shiftedLoadSuperAttr: boolean;
  readonly compareShift: number;
  readonly binaryOpCode: number | null;
  readonly intrinsic1OpCode: number | null;
  readonly intrinsic2OpCode: number | null;
}

const fromEntries = (record: Readonly<Record<string, number>>): ReadonlyMap<number, string> =>
  new Map(Object.entries(record).map(([name, code]) => [code, name]));

const CPYTHON_312_OPNAMES = fromEntries({
  CACHE: 0,
  POP_TOP: 1,
  PUSH_NULL: 2,
  INTERPRETER_EXIT: 3,
  END_FOR: 4,
  END_SEND: 5,
  NOP: 9,
  UNARY_NEGATIVE: 11,
  UNARY_NOT: 12,
  UNARY_INVERT: 15,
  RESERVED: 17,
  BINARY_SUBSCR: 25,
  BINARY_SLICE: 26,
  STORE_SLICE: 27,
  GET_LEN: 30,
  MATCH_MAPPING: 31,
  MATCH_SEQUENCE: 32,
  MATCH_KEYS: 33,
  PUSH_EXC_INFO: 35,
  CHECK_EXC_MATCH: 36,
  CHECK_EG_MATCH: 37,
  WITH_EXCEPT_START: 49,
  GET_AITER: 50,
  GET_ANEXT: 51,
  BEFORE_ASYNC_WITH: 52,
  BEFORE_WITH: 53,
  END_ASYNC_FOR: 54,
  CLEANUP_THROW: 55,
  STORE_SUBSCR: 60,
  DELETE_SUBSCR: 61,
  GET_ITER: 68,
  GET_YIELD_FROM_ITER: 69,
  LOAD_BUILD_CLASS: 71,
  LOAD_ASSERTION_ERROR: 74,
  RETURN_GENERATOR: 75,
  RETURN_VALUE: 83,
  SETUP_ANNOTATIONS: 85,
  LOAD_LOCALS: 87,
  POP_EXCEPT: 89,
  STORE_NAME: 90,
  DELETE_NAME: 91,
  UNPACK_SEQUENCE: 92,
  FOR_ITER: 93,
  UNPACK_EX: 94,
  STORE_ATTR: 95,
  DELETE_ATTR: 96,
  STORE_GLOBAL: 97,
  DELETE_GLOBAL: 98,
  SWAP: 99,
  LOAD_CONST: 100,
  LOAD_NAME: 101,
  BUILD_TUPLE: 102,
  BUILD_LIST: 103,
  BUILD_SET: 104,
  BUILD_MAP: 105,
  LOAD_ATTR: 106,
  COMPARE_OP: 107,
  IMPORT_NAME: 108,
  IMPORT_FROM: 109,
  JUMP_FORWARD: 110,
  POP_JUMP_IF_FALSE: 114,
  POP_JUMP_IF_TRUE: 115,
  LOAD_GLOBAL: 116,
  IS_OP: 117,
  CONTAINS_OP: 118,
  RERAISE: 119,
  COPY: 120,
  RETURN_CONST: 121,
  BINARY_OP: 122,
  SEND: 123,
  LOAD_FAST: 124,
  STORE_FAST: 125,
  DELETE_FAST: 126,
  LOAD_FAST_CHECK: 127,
  POP_JUMP_IF_NOT_NONE: 128,
  POP_JUMP_IF_NONE: 129,
  RAISE_VARARGS: 130,
  GET_AWAITABLE: 131,
  MAKE_FUNCTION: 132,
  BUILD_SLICE: 133,
  JUMP_BACKWARD_NO_INTERRUPT: 134,
  MAKE_CELL: 135,
  LOAD_CLOSURE: 136,
  LOAD_DEREF: 137,
  STORE_DEREF: 138,
  DELETE_DEREF: 139,
  JUMP_BACKWARD: 140,
  LOAD_SUPER_ATTR: 141,
  CALL_FUNCTION_EX: 142,
  LOAD_FAST_AND_CLEAR: 143,
  EXTENDED_ARG: 144,
  LIST_APPEND: 145,
  SET_ADD: 146,
  MAP_ADD: 147,
  COPY_FREE_VARS: 149,
  YIELD_VALUE: 150,
  RESUME: 151,
  MATCH_CLASS: 152,
  FORMAT_VALUE: 155,
  BUILD_CONST_KEY_MAP: 156,
  BUILD_STRING: 157,
  LIST_EXTEND: 162,
  SET_UPDATE: 163,
  DICT_MERGE: 164,
  DICT_UPDATE: 165,
  CALL: 171,
  KW_NAMES: 172,
  CALL_INTRINSIC_1: 173,
  CALL_INTRINSIC_2: 174,
  LOAD_FROM_DICT_OR_GLOBALS: 175,
  LOAD_FROM_DICT_OR_DEREF: 176,
  INSTRUMENTED_LOAD_SUPER_ATTR: 237,
  INSTRUMENTED_POP_JUMP_IF_NONE: 238,
  INSTRUMENTED_POP_JUMP_IF_NOT_NONE: 239,
  INSTRUMENTED_RESUME: 240,
  INSTRUMENTED_CALL: 241,
  INSTRUMENTED_RETURN_VALUE: 242,
  INSTRUMENTED_YIELD_VALUE: 243,
  INSTRUMENTED_CALL_FUNCTION_EX: 244,
  INSTRUMENTED_JUMP_FORWARD: 245,
  INSTRUMENTED_JUMP_BACKWARD: 246,
  INSTRUMENTED_RETURN_CONST: 247,
  INSTRUMENTED_FOR_ITER: 248,
  INSTRUMENTED_POP_JUMP_IF_FALSE: 249,
  INSTRUMENTED_POP_JUMP_IF_TRUE: 250,
  INSTRUMENTED_END_FOR: 251,
  INSTRUMENTED_END_SEND: 252,
  INSTRUMENTED_INSTRUCTION: 253,
  INSTRUMENTED_LINE: 254,
});

const CPYTHON_312_PROFILE: OpcodeProfile = {
  id: "cpython-3.12",
  haveArgument: 90,
  extendedArg: 144,
  opnames: CPYTHON_312_OPNAMES,
  inlineCaches: new Map([
    [25, 1],
    [60, 1],
    [92, 1],
    [93, 1],
    [95, 4],
    [106, 9],
    [107, 1],
    [116, 4],
    [122, 1],
    [123, 1],
    [141, 1],
    [171, 3],
  ]),
  hasConst: new Set([100, 121, 172]),
  hasName: new Set([90, 91, 95, 96, 97, 98, 101, 106, 108, 109, 116, 141, 175]),
  hasLocal: new Set([124, 125, 126, 127, 143]),
  hasFree: new Set([135, 136, 137, 138, 139, 176]),
  hasCompare: new Set([107]),
  hasJrelForward: new Set([93, 110, 114, 115, 123, 128, 129]),
  hasJrelBackward: new Set([134, 140]),
  hasJabs: new Set(),
  jumpScale: 2,
  shiftedLoadGlobal: true,
  shiftedLoadAttr: true,
  shiftedLoadSuperAttr: true,
  compareShift: 4,
  binaryOpCode: 122,
  intrinsic1OpCode: 173,
  intrinsic2OpCode: 174,
};

const CPYTHON_311_PROFILE: OpcodeProfile = {
  id: "cpython-3.11",
  haveArgument: 90,
  extendedArg: 144,
  opnames: fromEntries({
    CACHE: 0,
    POP_TOP: 1,
    PUSH_NULL: 2,
    NOP: 9,
    UNARY_POSITIVE: 10,
    UNARY_NEGATIVE: 11,
    UNARY_NOT: 12,
    UNARY_INVERT: 15,
    BINARY_SUBSCR: 25,
    GET_LEN: 30,
    MATCH_MAPPING: 31,
    MATCH_SEQUENCE: 32,
    MATCH_KEYS: 33,
    PUSH_EXC_INFO: 35,
    CHECK_EXC_MATCH: 36,
    CHECK_EG_MATCH: 37,
    WITH_EXCEPT_START: 49,
    GET_AITER: 50,
    GET_ANEXT: 51,
    BEFORE_ASYNC_WITH: 52,
    BEFORE_WITH: 53,
    END_ASYNC_FOR: 54,
    STORE_SUBSCR: 60,
    DELETE_SUBSCR: 61,
    GET_ITER: 68,
    GET_YIELD_FROM_ITER: 69,
    PRINT_EXPR: 70,
    LOAD_BUILD_CLASS: 71,
    LOAD_ASSERTION_ERROR: 74,
    RETURN_GENERATOR: 75,
    LIST_TO_TUPLE: 82,
    RETURN_VALUE: 83,
    IMPORT_STAR: 84,
    SETUP_ANNOTATIONS: 85,
    YIELD_VALUE: 86,
    ASYNC_GEN_WRAP: 87,
    PREP_RERAISE_STAR: 88,
    POP_EXCEPT: 89,
    STORE_NAME: 90,
    DELETE_NAME: 91,
    UNPACK_SEQUENCE: 92,
    FOR_ITER: 93,
    UNPACK_EX: 94,
    STORE_ATTR: 95,
    DELETE_ATTR: 96,
    STORE_GLOBAL: 97,
    DELETE_GLOBAL: 98,
    SWAP: 99,
    LOAD_CONST: 100,
    LOAD_NAME: 101,
    BUILD_TUPLE: 102,
    BUILD_LIST: 103,
    BUILD_SET: 104,
    BUILD_MAP: 105,
    LOAD_ATTR: 106,
    COMPARE_OP: 107,
    IMPORT_NAME: 108,
    IMPORT_FROM: 109,
    JUMP_FORWARD: 110,
    JUMP_IF_FALSE_OR_POP: 111,
    JUMP_IF_TRUE_OR_POP: 112,
    POP_JUMP_FORWARD_IF_FALSE: 114,
    POP_JUMP_FORWARD_IF_TRUE: 115,
    LOAD_GLOBAL: 116,
    IS_OP: 117,
    CONTAINS_OP: 118,
    RERAISE: 119,
    COPY: 120,
    BINARY_OP: 122,
    SEND: 123,
    LOAD_FAST: 124,
    STORE_FAST: 125,
    DELETE_FAST: 126,
    POP_JUMP_FORWARD_IF_NOT_NONE: 128,
    POP_JUMP_FORWARD_IF_NONE: 129,
    RAISE_VARARGS: 130,
    GET_AWAITABLE: 131,
    MAKE_FUNCTION: 132,
    BUILD_SLICE: 133,
    JUMP_BACKWARD_NO_INTERRUPT: 134,
    MAKE_CELL: 135,
    LOAD_CLOSURE: 136,
    LOAD_DEREF: 137,
    STORE_DEREF: 138,
    DELETE_DEREF: 139,
    JUMP_BACKWARD: 140,
    CALL_FUNCTION_EX: 142,
    EXTENDED_ARG: 144,
    LIST_APPEND: 145,
    SET_ADD: 146,
    MAP_ADD: 147,
    LOAD_CLASSDEREF: 148,
    COPY_FREE_VARS: 149,
    RESUME: 151,
    MATCH_CLASS: 152,
    FORMAT_VALUE: 155,
    BUILD_CONST_KEY_MAP: 156,
    BUILD_STRING: 157,
    LOAD_METHOD: 160,
    LIST_EXTEND: 162,
    SET_UPDATE: 163,
    DICT_MERGE: 164,
    DICT_UPDATE: 165,
    PRECALL: 166,
    CALL: 171,
    KW_NAMES: 172,
    POP_JUMP_BACKWARD_IF_NOT_NONE: 173,
    POP_JUMP_BACKWARD_IF_NONE: 174,
    POP_JUMP_BACKWARD_IF_FALSE: 175,
    POP_JUMP_BACKWARD_IF_TRUE: 176,
  }),
  inlineCaches: new Map([
    [25, 4],
    [60, 1],
    [92, 1],
    [95, 4],
    [106, 4],
    [107, 2],
    [116, 5],
    [122, 1],
    [160, 10],
    [166, 1],
    [171, 4],
  ]),
  hasConst: new Set([100, 172]),
  hasName: new Set([90, 91, 95, 96, 97, 98, 101, 106, 108, 109, 116, 160]),
  hasLocal: new Set([124, 125, 126]),
  hasFree: new Set([135, 136, 137, 138, 139, 148]),
  hasCompare: new Set([107]),
  hasJrelForward: new Set([93, 110, 111, 112, 114, 115, 123, 128, 129]),
  hasJrelBackward: new Set([134, 140, 173, 174, 175, 176]),
  hasJabs: new Set(),
  jumpScale: 2,
  shiftedLoadGlobal: true,
  shiftedLoadAttr: false,
  shiftedLoadSuperAttr: false,
  compareShift: 0,
  binaryOpCode: 122,
  intrinsic1OpCode: null,
  intrinsic2OpCode: null,
};

const CPYTHON_310_PROFILE: OpcodeProfile = {
  id: "cpython-3.10",
  haveArgument: 90,
  extendedArg: 144,
  opnames: fromEntries({
    POP_TOP: 1,
    ROT_TWO: 2,
    ROT_THREE: 3,
    DUP_TOP: 4,
    DUP_TOP_TWO: 5,
    ROT_FOUR: 6,
    NOP: 9,
    UNARY_POSITIVE: 10,
    UNARY_NEGATIVE: 11,
    UNARY_NOT: 12,
    UNARY_INVERT: 15,
    BINARY_MATRIX_MULTIPLY: 16,
    INPLACE_MATRIX_MULTIPLY: 17,
    BINARY_POWER: 19,
    BINARY_MULTIPLY: 20,
    BINARY_MODULO: 22,
    BINARY_ADD: 23,
    BINARY_SUBTRACT: 24,
    BINARY_SUBSCR: 25,
    BINARY_FLOOR_DIVIDE: 26,
    BINARY_TRUE_DIVIDE: 27,
    INPLACE_FLOOR_DIVIDE: 28,
    INPLACE_TRUE_DIVIDE: 29,
    GET_LEN: 30,
    MATCH_MAPPING: 31,
    MATCH_SEQUENCE: 32,
    MATCH_KEYS: 33,
    COPY_DICT_WITHOUT_KEYS: 34,
    WITH_EXCEPT_START: 49,
    GET_AITER: 50,
    GET_ANEXT: 51,
    BEFORE_ASYNC_WITH: 52,
    END_ASYNC_FOR: 54,
    INPLACE_ADD: 55,
    INPLACE_SUBTRACT: 56,
    INPLACE_MULTIPLY: 57,
    INPLACE_MODULO: 59,
    STORE_SUBSCR: 60,
    DELETE_SUBSCR: 61,
    BINARY_LSHIFT: 62,
    BINARY_RSHIFT: 63,
    BINARY_AND: 64,
    BINARY_XOR: 65,
    BINARY_OR: 66,
    INPLACE_POWER: 67,
    GET_ITER: 68,
    GET_YIELD_FROM_ITER: 69,
    PRINT_EXPR: 70,
    LOAD_BUILD_CLASS: 71,
    YIELD_FROM: 72,
    GET_AWAITABLE: 73,
    LOAD_ASSERTION_ERROR: 74,
    INPLACE_LSHIFT: 75,
    INPLACE_RSHIFT: 76,
    INPLACE_AND: 77,
    INPLACE_XOR: 78,
    INPLACE_OR: 79,
    LIST_TO_TUPLE: 82,
    RETURN_VALUE: 83,
    IMPORT_STAR: 84,
    SETUP_ANNOTATIONS: 85,
    YIELD_VALUE: 86,
    POP_BLOCK: 87,
    POP_EXCEPT: 89,
    STORE_NAME: 90,
    DELETE_NAME: 91,
    UNPACK_SEQUENCE: 92,
    FOR_ITER: 93,
    UNPACK_EX: 94,
    STORE_ATTR: 95,
    DELETE_ATTR: 96,
    STORE_GLOBAL: 97,
    DELETE_GLOBAL: 98,
    ROT_N: 99,
    LOAD_CONST: 100,
    LOAD_NAME: 101,
    BUILD_TUPLE: 102,
    BUILD_LIST: 103,
    BUILD_SET: 104,
    BUILD_MAP: 105,
    LOAD_ATTR: 106,
    COMPARE_OP: 107,
    IMPORT_NAME: 108,
    IMPORT_FROM: 109,
    JUMP_FORWARD: 110,
    JUMP_IF_FALSE_OR_POP: 111,
    JUMP_IF_TRUE_OR_POP: 112,
    JUMP_ABSOLUTE: 113,
    POP_JUMP_IF_FALSE: 114,
    POP_JUMP_IF_TRUE: 115,
    LOAD_GLOBAL: 116,
    IS_OP: 117,
    CONTAINS_OP: 118,
    RERAISE: 119,
    JUMP_IF_NOT_EXC_MATCH: 121,
    SETUP_FINALLY: 122,
    LOAD_FAST: 124,
    STORE_FAST: 125,
    DELETE_FAST: 126,
    GEN_START: 129,
    RAISE_VARARGS: 130,
    CALL_FUNCTION: 131,
    MAKE_FUNCTION: 132,
    BUILD_SLICE: 133,
    LOAD_CLOSURE: 135,
    LOAD_DEREF: 136,
    STORE_DEREF: 137,
    DELETE_DEREF: 138,
    CALL_FUNCTION_KW: 141,
    CALL_FUNCTION_EX: 142,
    SETUP_WITH: 143,
    EXTENDED_ARG: 144,
    LIST_APPEND: 145,
    SET_ADD: 146,
    MAP_ADD: 147,
    LOAD_CLASSDEREF: 148,
    MATCH_CLASS: 152,
    SETUP_ASYNC_WITH: 154,
    FORMAT_VALUE: 155,
    BUILD_CONST_KEY_MAP: 156,
    BUILD_STRING: 157,
    LOAD_METHOD: 160,
    CALL_METHOD: 161,
    LIST_EXTEND: 162,
    SET_UPDATE: 163,
    DICT_MERGE: 164,
    DICT_UPDATE: 165,
  }),
  inlineCaches: new Map(),
  hasConst: new Set([100]),
  hasName: new Set([90, 91, 95, 96, 97, 98, 101, 106, 108, 109, 116, 160]),
  hasLocal: new Set([124, 125, 126]),
  hasFree: new Set([135, 136, 137, 138, 148]),
  hasCompare: new Set([107]),
  hasJrelForward: new Set([93, 110, 122, 143, 154]),
  hasJrelBackward: new Set(),
  hasJabs: new Set([111, 112, 113, 114, 115, 121]),
  jumpScale: 2,
  shiftedLoadGlobal: false,
  shiftedLoadAttr: false,
  shiftedLoadSuperAttr: false,
  compareShift: 0,
  binaryOpCode: null,
  intrinsic1OpCode: null,
  intrinsic2OpCode: null,
};

const CPYTHON_38_39_PROFILE: OpcodeProfile = {
  ...CPYTHON_310_PROFILE,
  id: "cpython-3.8-3.9",
  jumpScale: 1,
};

const PROFILE_BY_MAGIC = new Map<number, OpcodeProfile>([
  [3413, CPYTHON_38_39_PROFILE],
  [3425, CPYTHON_38_39_PROFILE],
  [3439, CPYTHON_310_PROFILE],
  [3494, CPYTHON_311_PROFILE],
  [3495, CPYTHON_311_PROFILE],
  [3531, CPYTHON_312_PROFILE],
]);

export const pythonPycDisassemblyProfileForMagic = (
  magic: number,
): string | null => PROFILE_BY_MAGIC.get(magic)?.id ?? null;

const formatConstPreview = (constant: PythonPycConst | undefined): string | null => {
  if (constant === undefined) return null;
  switch (constant.kind) {
    case "none":
      return "None";
    case "bool":
      return constant.value ? "True" : "False";
    case "int":
      return constant.value ?? `<int:${String(constant.bits)}b>`;
    case "float":
      return String(constant.value);
    case "str":
      return JSON.stringify(constant.value);
    case "bytes":
      return `<bytes:${String(constant.bytes)}B>`;
    case "code":
      return `<code ${constant.name} at line ${String(constant.firstlineno)}>`;
    case "ellipsis":
      return "...";
    case "slice":
      return "<slice>";
    case "complex":
      return `(${String(constant.real)}+${String(constant.imag)}j)`;
    case "tuple":
    case "list":
    case "set":
    case "frozenset":
    case "dict":
      return `<${constant.kind}:${String(constant.length)}>`;
    case "other":
      return `<${constant.type}>`;
  }
};

export interface DisassembleCodeContext {
  readonly magic: number;
  readonly bytecode: Buffer;
  readonly consts: readonly PythonPycConst[];
  readonly names: readonly string[];
  readonly varnames: readonly string[] | null;
  readonly freevars: readonly string[] | null;
  readonly cellvars: readonly string[] | null;
  readonly localsplusnames: readonly string[] | null;
  readonly maxInstructions: number;
}

const resolveOperand = (
  profile: OpcodeProfile,
  opcode: number,
  arg: number,
  nextOffset: number,
  cacheEntries: number,
  context: DisassembleCodeContext,
): { readonly argrepr: string | null; readonly jumpTarget: number | null } => {
  const afterCaches = nextOffset + cacheEntries * 2;
  if (profile.hasJrelForward.has(opcode)) {
    const target = afterCaches + arg * profile.jumpScale;
    return { argrepr: `to ${String(target)}`, jumpTarget: target };
  }
  if (profile.hasJrelBackward.has(opcode)) {
    const target = afterCaches - arg * profile.jumpScale;
    return { argrepr: `to ${String(target)}`, jumpTarget: target };
  }
  if (profile.hasJabs.has(opcode)) {
    const target = arg * profile.jumpScale;
    return { argrepr: `to ${String(target)}`, jumpTarget: target };
  }
  if (profile.hasConst.has(opcode)) {
    return { argrepr: formatConstPreview(context.consts[arg]), jumpTarget: null };
  }
  if (profile.hasName.has(opcode)) {
    if (opcode === 116 && profile.shiftedLoadGlobal) {
      const name = context.names[arg >> 1];
      if (name === undefined) return { argrepr: null, jumpTarget: null };
      return {
        argrepr: (arg & 1) !== 0 ? `NULL + ${name}` : name,
        jumpTarget: null,
      };
    }
    if (opcode === 106 && profile.shiftedLoadAttr) {
      const name = context.names[arg >> 1];
      if (name === undefined) return { argrepr: null, jumpTarget: null };
      return {
        argrepr: (arg & 1) !== 0 ? `method:${name}` : name,
        jumpTarget: null,
      };
    }
    if (opcode === 141 && profile.shiftedLoadSuperAttr) {
      const name = context.names[arg >> 2];
      return { argrepr: name ?? null, jumpTarget: null };
    }
    return { argrepr: context.names[arg] ?? null, jumpTarget: null };
  }
  if (profile.hasLocal.has(opcode)) {
    const table = context.localsplusnames ?? context.varnames;
    return { argrepr: table?.[arg] ?? null, jumpTarget: null };
  }
  if (profile.hasFree.has(opcode)) {
    if (context.localsplusnames !== null) {
      return { argrepr: context.localsplusnames[arg] ?? null, jumpTarget: null };
    }
    const combined = [...(context.cellvars ?? []), ...(context.freevars ?? [])];
    return { argrepr: combined[arg] ?? null, jumpTarget: null };
  }
  if (profile.hasCompare.has(opcode)) {
    const idx = profile.compareShift > 0 ? arg >> profile.compareShift : arg;
    return { argrepr: CMP_OPS[idx] ?? null, jumpTarget: null };
  }
  if (profile.binaryOpCode !== null && opcode === profile.binaryOpCode) {
    return { argrepr: NB_OPS[arg] ?? null, jumpTarget: null };
  }
  if (profile.intrinsic1OpCode !== null && opcode === profile.intrinsic1OpCode) {
    return { argrepr: INTRINSIC_1_DESCS[arg] ?? null, jumpTarget: null };
  }
  if (profile.intrinsic2OpCode !== null && opcode === profile.intrinsic2OpCode) {
    return { argrepr: INTRINSIC_2_DESCS[arg] ?? null, jumpTarget: null };
  }
  return { argrepr: null, jumpTarget: null };
};

/** Decode CPython wordcode bytes into structured instructions without executing code. */
export const disassemblePythonBytecode = (
  context: DisassembleCodeContext,
): PythonPycDisassembly => {
  const profile = PROFILE_BY_MAGIC.get(context.magic);
  if (profile === undefined) {
    return {
      status: "unsupported-magic",
      opcode_profile: null,
      instruction_count: 0,
      instructions: [],
    };
  }

  const bytes = context.bytecode;
  const instructions: PythonPycInstruction[] = [];
  let extendedArg = 0;
  let offset = 0;
  let truncated = false;

  while (offset + 1 < bytes.length) {
    if (instructions.length >= context.maxInstructions) {
      truncated = true;
      break;
    }
    const opcode = bytes[offset]!;
    const rawArg = bytes[offset + 1]!;
    const opname = profile.opnames.get(opcode) ?? `UNKNOWN_${String(opcode)}`;
    const hasArg = opcode >= profile.haveArgument;
    const fullArg = hasArg ? (extendedArg << 8) | rawArg : null;
    const cacheEntries = profile.inlineCaches.get(opcode) ?? 0;

    if (opcode === profile.extendedArg) {
      extendedArg = fullArg ?? 0;
      instructions.push({
        offset,
        opcode,
        opname,
        arg: extendedArg,
        argrepr: null,
        jump_target: null,
        cache_entries: 0,
      });
      offset += 2;
      continue;
    }

    extendedArg = 0;
    const nextOffset = offset + 2;
    const resolved =
      fullArg === null
        ? { argrepr: null, jumpTarget: null }
        : resolveOperand(
            profile,
            opcode,
            fullArg,
            nextOffset,
            cacheEntries,
            context,
          );

    instructions.push({
      offset,
      opcode,
      opname,
      arg: fullArg,
      argrepr: resolved.argrepr,
      jump_target: resolved.jumpTarget,
      cache_entries: cacheEntries,
    });

    offset = nextOffset + cacheEntries * 2;
  }

  return {
    status: truncated ? "truncated" : "decoded",
    opcode_profile: profile.id,
    instruction_count: instructions.length,
    instructions,
  };
};
