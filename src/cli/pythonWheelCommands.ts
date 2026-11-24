import type { Logger } from "pino";

import { createPythonWheelService } from "../composition/pythonWheel.js";
import { PYTHON_WHEEL_TOOL_CONTRACTS } from "../contracts/python/pythonWheelToolContracts.js";
import { contractNamed } from "./contractCliDescription.js";
import { registerContractCommand } from "./contractCommand.js";
import { deliverWithService } from "./contractCommandRunners.js";
import type { CliInstance } from "./types.js";

/** Inspect operator-selected Python wheels through the same shared workflow as MCP. */
export const registerPythonWheelCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  registerContractCommand(
    cli,
    logger,
    contractNamed(PYTHON_WHEEL_TOOL_CONTRACTS, "inspect_python_wheel"),
    {
      description:
        "Inspect Python .whl metadata, tags, entry points, RECORD integrity and ZIP contents without installing or executing",
      positionals: ["path"],
      callerPaths: ["path"],
      evidenceDelivery: true,
      fields: { path: { description: "Local Python .whl distribution" } },
    },
    deliverWithService(createPythonWheelService, "rea-python-wheel"),
  );
};
