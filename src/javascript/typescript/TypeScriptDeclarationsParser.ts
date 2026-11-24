import { parse } from "@babel/parser";
import * as t from "@babel/types";

import {
  TYPESCRIPT_DECLARATIONS_FORMAT,
  type InspectTypeScriptDeclarationsInput,
  type TypeScriptDeclarations,
} from "../../domain/javascript/typescriptDeclarations.js";
import { malformedInput } from "../../domain/parseFailure.js";

const BASE_LIMITATIONS = [
  "This workflow parses TypeScript declaration syntax statically with Babel without invoking tsc or type-checking against external @types packages.",
  "TypeScript declarations describe declared API surfaces only; they do not prove runtime JavaScript implementations match those signatures.",
] as const;

type Declaration = TypeScriptDeclarations["declarations"][number];
type Member = Declaration["members"][number];
type ImportEntry = TypeScriptDeclarations["imports"][number];
type TripleSlash = TypeScriptDeclarations["triple_slash_references"][number];

const TRIPLE_SLASH_RE =
  /^\s*\/\/\/\s*<reference\s+(path|types|lib|no-default-lib)\s*=\s*["']([^"']+)["']\s*\/?>/iu;
const SOURCE_MAPPING_URL_RE = /\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/u;

const extractTripleSlashAndSourceMap = (
  text: string,
): {
  readonly references: TripleSlash[];
  readonly sourceMappingUrl: string | null;
} => {
  const references: TripleSlash[] = [];
  let sourceMappingUrl: string | null = null;
  const lines = text.split(/\r?\n/u);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    const refMatch = TRIPLE_SLASH_RE.exec(line);
    if (refMatch !== null) {
      const kind = refMatch[1]!.toLowerCase() as TripleSlash["kind"];
      const value = refMatch[2]!.trim();
      if (value !== "") references.push({ kind, value, line: i + 1 });
    }
    const smMatch = SOURCE_MAPPING_URL_RE.exec(line);
    if (smMatch !== null && smMatch[1] !== undefined) {
      sourceMappingUrl = smMatch[1].trim() || null;
    }
  }
  return { references, sourceMappingUrl };
};

const entityNameText = (node: t.Node | null | undefined): string | null => {
  if (node === null || node === undefined) return null;
  if (t.isIdentifier(node)) return node.name;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isNumericLiteral(node)) return String(node.value);
  if (t.isTSQualifiedName(node)) {
    const left = entityNameText(node.left);
    return left === null ? node.right.name : `${left}.${node.right.name}`;
  }
  if (t.isMemberExpression(node) && !node.computed) {
    const obj = entityNameText(node.object);
    const prop = entityNameText(node.property);
    return obj !== null && prop !== null ? `${obj}.${prop}` : (prop ?? obj);
  }
  return null;
};

const typeParamNames = (
  params: t.Node | null | undefined,
): string[] => {
  if (!t.isTSTypeParameterDeclaration(params)) return [];
  const out: string[] = [];
  for (const param of params.params) {
    if (typeof param.name === "string" && param.name !== "")
      out.push(param.name);
  }
  return out;
};

const extractInterfaceMembers = (body: t.TSInterfaceBody): Member[] => {
  const members: Member[] = [];
  for (const elem of body.body) {
    if (t.isTSPropertySignature(elem)) {
      const name = entityNameText(elem.key) ?? "<computed>";
      members.push({
        name,
        kind: "property",
        optional: elem.optional === true,
        readonly: elem.readonly === true,
        static: false,
      });
    } else if (t.isTSMethodSignature(elem)) {
      const name = entityNameText(elem.key) ?? "<computed>";
      members.push({
        name,
        kind: elem.kind === "get" ? "getter" : elem.kind === "set" ? "setter" : "method",
        optional: elem.optional === true,
        readonly: false,
        static: false,
      });
    } else if (t.isTSCallSignatureDeclaration(elem)) {
      members.push({
        name: "()",
        kind: "call-signature",
        optional: false,
        readonly: false,
        static: false,
      });
    } else if (t.isTSConstructSignatureDeclaration(elem)) {
      members.push({
        name: "new()",
        kind: "constructor",
        optional: false,
        readonly: false,
        static: false,
      });
    } else if (t.isTSIndexSignature(elem)) {
      members.push({
        name: "[]",
        kind: "index-signature",
        optional: false,
        readonly: elem.readonly === true,
        static: false,
      });
    }
  }
  return members;
};

const extractClassMembers = (body: t.ClassBody): Member[] => {
  const members: Member[] = [];
  for (const elem of body.body) {
    if (t.isClassProperty(elem) || t.isClassAccessorProperty(elem)) {
      const name = entityNameText(elem.key) ?? "<computed>";
      members.push({
        name,
        kind: "property",
        optional: elem.optional === true,
        readonly: elem.readonly === true,
        static: elem.static === true,
      });
    } else if (t.isClassMethod(elem) || t.isTSDeclareMethod(elem)) {
      const name = entityNameText(elem.key) ?? "<computed>";
      const kind: Member["kind"] =
        elem.kind === "constructor"
          ? "constructor"
          : elem.kind === "get"
            ? "getter"
            : elem.kind === "set"
              ? "setter"
              : "method";
      members.push({
        name,
        kind,
        optional: elem.optional === true,
        readonly: false,
        static: elem.static === true,
      });
    } else if (t.isTSIndexSignature(elem)) {
      members.push({
        name: "[]",
        kind: "index-signature",
        optional: false,
        readonly: elem.readonly === true,
        static: elem.static === true,
      });
    }
  }
  return members;
};

const extractEnumMembers = (node: t.TSEnumDeclaration): Member[] => {
  const members: Member[] = [];
  for (const member of node.body.members) {
    const name = entityNameText(member.id) ?? "<computed>";
    members.push({
      name,
      kind: "enum-member",
      optional: false,
      readonly: true,
      static: false,
    });
  }
  return members;
};

const lineOf = (node: t.Node): number => node.loc?.start.line ?? 0;

const collectDeclaration = (
  node: t.Statement | t.Declaration,
  exported: boolean,
  out: Declaration[],
  maxDeclarations: number,
  state: { truncated: boolean },
): void => {
  const push = (decl: Declaration): void => {
    if (out.length >= maxDeclarations) {
      state.truncated = true;
      return;
    }
    out.push(decl);
  };

  if (t.isExportNamedDeclaration(node)) {
    if (node.declaration != null) {
      collectDeclaration(node.declaration, true, out, maxDeclarations, state);
      return;
    }
    const sourceSpec = node.source?.value ?? null;
    for (const spec of node.specifiers) {
      if (t.isExportSpecifier(spec)) {
        const name = entityNameText(spec.exported) ?? "<unknown>";
        push({
          kind: "re-export",
          name,
          exported: true,
          ambient: false,
          line: lineOf(spec),
          source_specifier: sourceSpec,
          type_parameters: [],
          extends: [],
          implements: [],
          members: [],
        });
      } else if (t.isExportNamespaceSpecifier(spec)) {
        push({
          kind: "re-export",
          name: t.isIdentifier(spec.exported)
            ? spec.exported.name
            : spec.exported.value,
          exported: true,
          ambient: false,
          line: lineOf(spec),
          source_specifier: sourceSpec,
          type_parameters: [],
          extends: [],
          implements: [],
          members: [],
        });
      }
    }
    return;
  }

  if (t.isExportAllDeclaration(node)) {
    push({
      kind: "export-all",
      name: "*",
      exported: true,
      ambient: false,
      line: lineOf(node),
      source_specifier: node.source.value,
      type_parameters: [],
      extends: [],
      implements: [],
      members: [],
    });
    return;
  }

  if (t.isExportDefaultDeclaration(node)) {
    const name =
      (t.isIdentifier(node.declaration) ? node.declaration.name : null) ??
      ("id" in node.declaration && t.isIdentifier(node.declaration.id)
        ? node.declaration.id.name
        : null) ??
      "default";
    push({
      kind: "export-default",
      name,
      exported: true,
      ambient: false,
      line: lineOf(node),
      source_specifier: null,
      type_parameters: [],
      extends: [],
      implements: [],
      members: [],
    });
    return;
  }

  if (t.isTSDeclareFunction(node) || t.isFunctionDeclaration(node)) {
    push({
      kind: "function",
      name: node.id?.name ?? "<anonymous>",
      exported,
      ambient: Boolean("declare" in node && node.declare),
      line: lineOf(node),
      source_specifier: null,
      type_parameters: typeParamNames(node.typeParameters),
      extends: [],
      implements: [],
      members: [],
    });
    return;
  }

  if (t.isClassDeclaration(node)) {
    const ext = entityNameText(node.superClass);
    const impls: string[] = [];
    for (const impl of node.implements ?? []) {
      if (t.isTSClassImplements(impl)) {
        const name = entityNameText(impl.expression);
        if (name !== null) impls.push(name);
      }
    }
    push({
      kind: "class",
      name: node.id?.name ?? "<anonymous>",
      exported,
      ambient: Boolean(node.declare),
      line: lineOf(node),
      source_specifier: null,
      type_parameters: typeParamNames(node.typeParameters),
      extends: ext === null ? [] : [ext],
      implements: impls,
      members: extractClassMembers(node.body),
    });
    return;
  }

  if (t.isTSInterfaceDeclaration(node)) {
    const exts: string[] = [];
    for (const ext of node.extends ?? []) {
      const name = entityNameText(ext.expression);
      if (name !== null) exts.push(name);
    }
    push({
      kind: "interface",
      name: node.id.name,
      exported,
      ambient: Boolean(node.declare),
      line: lineOf(node),
      source_specifier: null,
      type_parameters: typeParamNames(node.typeParameters),
      extends: exts,
      implements: [],
      members: extractInterfaceMembers(node.body),
    });
    return;
  }

  if (t.isTSTypeAliasDeclaration(node)) {
    push({
      kind: "type-alias",
      name: node.id.name,
      exported,
      ambient: Boolean(node.declare),
      line: lineOf(node),
      source_specifier: null,
      type_parameters: typeParamNames(node.typeParameters),
      extends: [],
      implements: [],
      members: [],
    });
    return;
  }

  if (t.isTSEnumDeclaration(node)) {
    push({
      kind: node.const ? "const-enum" : "enum",
      name: node.id.name,
      exported,
      ambient: Boolean(node.declare),
      line: lineOf(node),
      source_specifier: null,
      type_parameters: [],
      extends: [],
      implements: [],
      members: extractEnumMembers(node),
    });
    return;
  }

  if (t.isVariableDeclaration(node)) {
    for (const declarator of node.declarations) {
      const name = entityNameText(declarator.id) ?? "<destructured>";
      push({
        kind: "variable",
        name,
        exported,
        ambient: Boolean(node.declare),
        line: lineOf(declarator),
        source_specifier: null,
        type_parameters: [],
        extends: [],
        implements: [],
        members: [],
      });
    }
    return;
  }

  if (t.isTSModuleDeclaration(node)) {
    const isStringModule = t.isStringLiteral(node.id);
    const name = entityNameText(node.id) ?? "<anonymous>";
    push({
      kind: isStringModule ? "module-augmentation" : "namespace",
      name,
      exported,
      ambient: Boolean(node.declare),
      line: lineOf(node),
      source_specifier: isStringModule ? name : null,
      type_parameters: [],
      extends: [],
      implements: [],
      members: [],
    });
  }
};

export interface DeclarationMapInput {
  readonly path: string;
  readonly sha256: string;
  readonly text: string;
}

const parseDeclarationMap = (
  mapInput: DeclarationMapInput,
  limitations: string[],
): TypeScriptDeclarations["declaration_map"] => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(mapInput.text);
  } catch {
    limitations.push(
      `Companion declaration map ${JSON.stringify(mapInput.path)} is not valid JSON.`,
    );
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    limitations.push(
      `Companion declaration map ${JSON.stringify(mapInput.path)} root is not a JSON object.`,
    );
    return null;
  }
  const obj = parsed as Record<string, unknown>;
  const version =
    typeof obj.version === "number" && Number.isInteger(obj.version)
      ? obj.version
      : null;
  const sourceRoot =
    typeof obj.sourceRoot === "string" && obj.sourceRoot.trim() !== ""
      ? obj.sourceRoot
      : null;
  const sources = Array.isArray(obj.sources)
    ? obj.sources.filter((item): item is string => typeof item === "string")
    : [];
  const hasMappings =
    typeof obj.mappings === "string" && obj.mappings.length > 0;
  return {
    path: mapInput.path,
    sha256: mapInput.sha256,
    version,
    source_root: sourceRoot,
    sources,
    has_mappings: hasMappings,
  };
};

/** Parse one TypeScript declaration file (.d.ts/.d.mts/.d.cts) statically. */
export const parseTypeScriptDeclarations = (
  text: string,
  artifact: { readonly path: string; readonly sha256: string; readonly bytes: number },
  input: InspectTypeScriptDeclarationsInput,
  declarationMapInput?: DeclarationMapInput,
): TypeScriptDeclarations => {
  const limitations: string[] = [...BASE_LIMITATIONS];
  const { references, sourceMappingUrl } = extractTripleSlashAndSourceMap(text);

  let ast: ReturnType<typeof parse>;
  try {
    ast = parse(text, {
      sourceType: "unambiguous",
      errorRecovery: true,
      plugins: [["typescript", { dts: true }], "decorators-legacy"],
    });
  } catch (cause: unknown) {
    throw malformedInput(
      TYPESCRIPT_DECLARATIONS_FORMAT,
      `Failed to parse TypeScript declarations: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }

  const parseErrors = ast.errors?.length ?? 0;
  if (parseErrors > 0)
    limitations.push(
      `Babel recovered from ${String(parseErrors)} syntax error(s); declaration inventory may be incomplete.`,
    );

  const imports: ImportEntry[] = [];
  const declarations: Declaration[] = [];
  const state = { truncated: false };

  for (const stmt of ast.program.body) {
    if (t.isImportDeclaration(stmt)) {
      const names: string[] = [];
      for (const spec of stmt.specifiers) {
        if (t.isImportDefaultSpecifier(spec)) names.push("default");
        else if (t.isImportNamespaceSpecifier(spec)) names.push(`* as ${spec.local.name}`);
        else if (t.isImportSpecifier(spec)) {
          names.push(entityNameText(spec.imported) ?? spec.local.name);
        }
      }
      imports.push({
        specifier: stmt.source.value,
        type_only: stmt.importKind === "type",
        names,
        line: lineOf(stmt),
      });
      continue;
    }
    collectDeclaration(stmt, false, declarations, input.max_declarations, state);
  }

  if (state.truncated)
    limitations.push(
      `Declaration inventory reached max_declarations (${String(input.max_declarations)}); later declarations were omitted.`,
    );

  const declarationMap =
    declarationMapInput === undefined
      ? null
      : parseDeclarationMap(declarationMapInput, limitations);

  return {
    artifact: {
      path: artifact.path,
      sha256: artifact.sha256,
      bytes: artifact.bytes,
    },
    source_mapping_url: sourceMappingUrl,
    declaration_map: declarationMap,
    triple_slash_references: references,
    imports,
    declarations,
    coverage: {
      status: state.truncated || parseErrors > 0 ? "partial" : "complete",
      declarations: declarations.length,
      parse_errors: parseErrors,
    },
    limitations,
  };
};
