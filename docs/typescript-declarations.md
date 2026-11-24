# TypeScript declarations and tsconfig path aliases

## Inspecting `.d.ts` / `.d.ts.map` API surfaces

`inspect_typescript_declarations` / `inspect-typescript-declarations` extracts
the declared API surface of a shipped TypeScript declaration file (`.d.ts`,
`.d.mts`, `.d.cts`) and optional companion `.d.ts.map` declaration source map
without invoking `tsc` or executing code.

```bash
rea inspect-typescript-declarations /absolute/path/to/dist/index.d.ts --json
rea inspect-typescript-declarations /absolute/path/to/dist/index.d.ts \
  --declaration-map-path /absolute/path/to/dist/index.d.ts.map --json
```

Returns:
- **`triple_slash_references`**: `/// <reference path|types|lib|no-default-lib="..." />`
- **`imports`**: imported module specifiers, `type_only` flag, and imported names
- **`declarations`**: exported and ambient functions, classes, interfaces, type
  aliases, enums/const enums, variables, namespaces, ambient `declare module "..."`
  augmentations, re-exports, and `export *`, complete with member inventories
  (`method`, `property`, `constructor`, `getter`, `setter`, `index-signature`,
  `call-signature`, `enum-member`), type parameters, and heritage clauses
- **`source_mapping_url`** and **`declaration_map`**: companion `.d.ts.map`
  version, `sourceRoot`, `sources`, and mapping presence.

## `tsconfig.json` `paths` and `baseUrl` resolution

During JavaScript/TypeScript application graph analysis
(`analyze_javascript_application`), bare module specifiers that do not match a
Node builtin, package self-reference, or `node_modules` package now consult the
nearest enclosing `tsconfig.json` (following artifact-confined `extends` chains
with JSONC comment/trailing-comma support) to resolve `compilerOptions.paths`
(exact and `*` wildcard patterns) and `compilerOptions.baseUrl` with an explicit
limitation recording that resolution came from `tsconfig.json`.
