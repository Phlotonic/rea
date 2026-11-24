import type { Logger } from "pino";

import { createPytorchPickleService } from "../composition/pytorchPickle.js";
import { PYTORCH_PICKLE_TOOL_CONTRACTS } from "../contracts/python/pytorchPickleToolContracts.js";
import { contractNamed } from "./contractCliDescription.js";
import { registerContractCommand } from "./contractCommand.js";
import { deliverWithService } from "./contractCommandRunners.js";
import type { CliInstance } from "./types.js";

/** Inspect PyTorch checkpoints and Python pickles without executing code. */
export const registerPytorchPickleCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  registerContractCommand(
    cli,
    logger,
    contractNamed(PYTORCH_PICKLE_TOOL_CONTRACTS, "inspect_pytorch_checkpoint"),
    {
      description:
        "Inspect PyTorch ZIP checkpoints (.pt/.pth/.ckpt) and Python pickles (.pkl) symbolically for unsafe globals and tensor layout",
      positionals: ["path"],
      callerPaths: ["path"],
      evidenceDelivery: true,
      fields: {
        path: { description: "Local PyTorch checkpoint or Python pickle file" },
      },
    },
    deliverWithService(createPytorchPickleService, "rea-pytorch-pickle"),
  );
};
