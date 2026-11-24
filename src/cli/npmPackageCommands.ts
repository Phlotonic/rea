import type { Logger } from "pino";

import { createNpmPackageService } from "../composition/npmPackage.js";
import { NPM_PACKAGE_TOOL_CONTRACTS } from "../contracts/javascript/npmPackageToolContracts.js";
import { contractNamed } from "./contractCliDescription.js";
import { registerContractCommand } from "./contractCommand.js";
import { deliverWithService } from "./contractCommandRunners.js";
import type { CliInstance } from "./types.js";

/** Inspect operator-selected npm tarballs through the same shared workflow as MCP. */
export const registerNpmPackageCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  registerContractCommand(
    cli,
    logger,
    contractNamed(NPM_PACKAGE_TOOL_CONTRACTS, "inspect_npm_package"),
    {
      description:
        "Inspect npm .tgz package.json manifest, lifecycle scripts, types, native addons, and tar contents without npm or script execution",
      positionals: ["path"],
      callerPaths: ["path"],
      evidenceDelivery: true,
      fields: { path: { description: "Local npm package tarball (.tgz)" } },
    },
    deliverWithService(createNpmPackageService, "rea-npm-package"),
  );
};
