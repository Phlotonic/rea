import {
  inspectTypeScriptDeclarationsInputSchema,
  typescriptDeclarationsSchema,
} from "../../domain/javascript/typescriptDeclarations.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceEffects, toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static TypeScript declaration surface inspection needs neither tsc nor execution. */
export const TYPESCRIPT_DECLARATIONS_TOOL_CONTRACTS = [
  {
    name: "inspect_typescript_declarations",
    availability: "standalone",
    cli: true,
    ...toolContractMetadata("inspect_typescript_declarations", evidenceEffects),
    kind: "artifact-provider",
    requiresActiveTarget: true,
    description:
      "Inspect a local TypeScript declaration file (.d.ts, .d.mts, .d.cts) and optional companion .d.ts.map without invoking tsc or executing code. Extracts triple-slash references, imports, exported/ambient API declarations (functions, classes, interfaces, type aliases, enums, variables, namespaces, module augmentations, re-exports) with member inventories, generics, heritage clauses, and declaration-map source provenance.",
    inputSchema: inspectTypeScriptDeclarationsInputSchema,
    outputSchema: evidenceResultOf(typescriptDeclarationsSchema),
    examples: [
      {
        title: "Inspect exported API surfaces from a shipped SDK .d.ts",
        input: { path: "/artifacts/dist/index.d.ts" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
