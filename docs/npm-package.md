# npm Package Tarball Inspection (`inspect_npm_package`)

`inspect_npm_package` / `rea inspect-npm-package` performs static, read-only inspection of a local npm package tarball (`.tgz`) without running `npm`, executing install/lifecycle scripts, resolving dependencies, or making network requests.

## Usage

### CLI

```bash
rea inspect-npm-package /artifacts/demo-package-1.2.3.tgz
```

### MCP

```json
{
  "tool": "inspect_npm_package",
  "arguments": {
    "path": "/artifacts/demo-package-1.2.3.tgz"
  }
}
```

## What It Extracts

- **`package_json`**: Package identity (`name`, `version`, `description`, `license`, `private`, `type`), entrypoints (`main`, `module`, `browser`, `types`/`typings`, `exports_keys`, `imports_keys`, `bin`, `files`), runtime constraints (`engines`, `os`, `cpu`), credential-redacted `repository`/`homepage`/`bugs_url`, dependency lists (`dependencies`, `dev_dependencies`, `peer_dependencies`, `optional_dependencies`), and all declared `scripts`.
- **`lifecycle_scripts`**: Explicitly highlights high-signal install, pack, and publish hooks (`preinstall`, `install`, `postinstall`, `preuninstall`, `uninstall`, `postuninstall`, `prepare`, `prepack`, `postpack`, `prepublish`, `prepublishOnly`, `publish`, `postpublish`) for rapid supply-chain review.
- **Surfaces & native payloads**: Enumerates TypeScript declaration files (`type_declarations`: `.d.ts`, `.d.mts`, `.d.cts`), source maps (`source_maps`), and native addon assets (`native_addons`: `.node`, `binding.gyp`, `CMakeLists.txt`, `prebuilds/*`).
- **Tar archive safety & inventory**: Streaming gunzip enforces `max_uncompressed_bytes` (anti-gzip-bomb ceiling) and `max_entries`, parses POSIX/USTAR, PAX extended headers, and GNU LongName/LongLink entries, classifies member `role` values, and flags `suspicious_entries` (`path-traversal`, `absolute-path`, `symlink`, `hardlink`).

## Limitations

- Static inspection only: lifecycle scripts are never executed, remote dependencies are not fetched or resolved, and npm registry provenance/signatures are not verified.
- Missing, oversize, or malformed `package.json` manifests succeed with the tar member inventory and explicit limitations.
