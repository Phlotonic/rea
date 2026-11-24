import {
  inspectPythonWheelInputSchema,
  pythonWheelSchema,
} from "../../domain/python/pythonWheel.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceEffects, toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static Python wheel inspection is independent of pip, Python, and native providers. */
export const PYTHON_WHEEL_TOOL_CONTRACTS = [
  {
    name: "inspect_python_wheel",
    availability: "standalone",
    cli: true,
    ...toolContractMetadata("inspect_python_wheel", evidenceEffects),
    kind: "artifact-provider",
    requiresActiveTarget: true,
    description:
      "Inspect a local Python .whl ZIP distribution without installing, importing, executing code, or contacting PyPI. Returns *.dist-info/METADATA fields (name, version, summary, license, requires_python, requires_dist, project_urls), WHEEL compatibility tags and purelib flag, entry_points.txt console/GUI/plugin hooks, top_level.txt, direct_url.json, native extension paths (.so/.pyd/.dylib), ZIP contents inventory, and RECORD size + SHA-256/384/512 verification results with explicit anomalies. Missing or ambiguous *.dist-info succeeds with inventory and limitations. Invalid ZIP input fails without partial success. Metadata claims do not prove runtime behavior or package safety.",
    inputSchema: inspectPythonWheelInputSchema,
    outputSchema: evidenceResultOf(pythonWheelSchema),
    examples: [
      {
        title: "Inspect Python wheel metadata, tags, entry points and RECORD integrity",
        input: { path: "/artifacts/demo_pkg-1.2.3-py3-none-any.whl" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
