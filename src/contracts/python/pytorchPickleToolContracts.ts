import {
  inspectPytorchCheckpointInputSchema,
  pytorchCheckpointSchema,
} from "../../domain/python/pytorchPickle.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceEffects, toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static PyTorch/pickle inspection never executes callables or invokes Python. */
export const PYTORCH_PICKLE_TOOL_CONTRACTS = [
  {
    name: "inspect_pytorch_checkpoint",
    availability: "standalone",
    cli: true,
    ...toolContractMetadata("inspect_pytorch_checkpoint", evidenceEffects),
    kind: "artifact-provider",
    requiresActiveTarget: true,
    description:
      "Inspect a local PyTorch checkpoint (.pt/.pth/.ckpt/.bin ZIP) or standalone Python pickle (.pkl/.pickle) without executing pickle opcodes, invoking Python, or loading weights. Decodes pickle protocols 0–5 symbolically, lists all referenced globals and flags high-risk code-execution/privileged imports (os, subprocess, eval, exec, __import__, ctypes, etc.), reconstructs state_dict tensor shapes, dtypes, strides, and ZIP storage mappings, and reports top-level keys and archive version/byteorder. Absence of flagged globals does not prove a pickle is safe.",
    inputSchema: inspectPytorchCheckpointInputSchema,
    outputSchema: evidenceResultOf(pytorchCheckpointSchema),
    examples: [
      {
        title: "Audit a PyTorch checkpoint for unsafe globals and tensor layout",
        input: { path: "/artifacts/model.pt" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
