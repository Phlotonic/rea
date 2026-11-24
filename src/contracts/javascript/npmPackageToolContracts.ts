import {
  inspectNpmPackageInputSchema,
  npmPackageSchema,
} from "../../domain/javascript/npmPackage.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceEffects, toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static npm .tgz tarball inspection without npm install, lifecycle scripts, or network. */
export const NPM_PACKAGE_TOOL_CONTRACTS = [
  {
    name: "inspect_npm_package",
    availability: "standalone",
    cli: true,
    ...toolContractMetadata("inspect_npm_package", evidenceEffects),
    kind: "artifact-provider",
    requiresActiveTarget: true,
    description:
      "Inspect a local npm package tarball (.tgz) statically without running npm, install/lifecycle scripts, or network requests. Decompresses under an explicit uncompressed-byte ceiling (anti-gzip-bomb), extracts package.json identity, entrypoints (main, module, browser, types, exports/imports keys, bin), dependencies, highlighted lifecycle scripts (preinstall/install/postinstall/prepare/pack/publish), TypeScript .d.ts surfaces, source maps, native addons (.node, binding.gyp, prebuilds), suspicious tar entries (symlinks, hardlinks, path traversal, absolute paths), and member roles. Credentials in repository, homepage, and bugs URLs are redacted. Missing or malformed package.json succeeds with inventory and explicit limitations. Complete Evidence is the result.",
    inputSchema: inspectNpmPackageInputSchema,
    outputSchema: evidenceResultOf(npmPackageSchema),
    examples: [
      {
        title: "Inspect an npm tarball manifest, lifecycle hooks, and contents",
        input: { path: "/artifacts/demo-package-1.2.3.tgz" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
