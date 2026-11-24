import type { Logger } from "pino";

import { createTypeScriptDeclarationsService } from "../composition/typescriptDeclarations.js";
import { TYPESCRIPT_DECLARATIONS_TOOL_CONTRACTS } from "../contracts/javascript/typescriptDeclarationsToolContracts.js";
import { contractNamed } from "./contractCliDescription.js";
import { registerContractCommand } from "./contractCommand.js";
import { deliverWithService } from "./contractCommandRunners.js";
import type { CliInstance } from "./types.js";

/** Inspect TypeScript declaration surfaces without invoking tsc. */
export const registerTypeScriptDeclarationsCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  registerContractCommand(
    cli,
    logger,
    contractNamed(
      TYPESCRIPT_DECLARATIONS_TOOL_CONTRACTS,
      "inspect_typescript_declarations",
    ),
    {
      description:
        "Inspect TypeScript .d.ts/.d.mts/.d.cts exported API surfaces and optional .d.ts.map declaration maps without invoking tsc",
      positionals: ["path"],
      callerPaths: ["path", "declaration_map_path"],
      evidenceDelivery: true,
      fields: {
        path: { description: "Local TypeScript declaration file (.d.ts/.d.mts/.d.cts)" },
        declaration_map_path: {
          description: "Optional companion .d.ts.map declaration map path",
        },
      },
    },
    deliverWithService(
      createTypeScriptDeclarationsService,
      "rea-typescript-declarations",
    ),
  );
};
