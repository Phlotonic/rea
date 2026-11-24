# Python wheel inspection

`inspect_python_wheel` / `inspect-python-wheel` inspects a local Python `.whl`
ZIP distribution without installing, importing, executing package code, or
contacting PyPI. It requires no Python installation or native analysis engine.

```bash
rea inspect-python-wheel /absolute/path/to/demo_pkg-1.2.3-py3-none-any.whl --json
```

```json
{
  "name": "inspect_python_wheel",
  "arguments": { "path": "/artifacts/demo_pkg-1.2.3-py3-none-any.whl" }
}
```

## What is returned

- **`dist_info`**: resolved root `*.dist-info` directory and paths to `METADATA`,
  `WHEEL`, `RECORD`, `entry_points.txt`, `top_level.txt`, and `direct_url.json`.
- **`metadata`**: Core Metadata fields (`Name`, `Version`, `Summary`, `Author`,
  `License`, `License-Expression`, `Requires-Python`, `Requires-Dist`,
  `Provides-Extra`, `Classifier`, `Project-URL`, `Home-page`). Embedded URL
  credentials are redacted with explicit flags.
- **`wheel`**: PEP 427 `Wheel-Version`, `Generator`, `Root-Is-Purelib`, `Build`,
  and parsed `(python_tag, abi_tag, platform_tag)` compatibility tags.
- **`entry_points`**, **`top_level`**, and **`direct_url`**: parsed console/GUI/plugin
  entry points, top-level packages, and PEP 610 direct-URL provenance.
- **`record`**: PEP 376 `RECORD` verification across sizes and supported hashes
  (`sha256`, `sha384`, `sha512`), reporting `hash-mismatch`, `size-mismatch`,
  `missing-in-archive`, `unrecorded-in-record`, `duplicate-record-entry`,
  `unsupported-algorithm`, `encrypted-member`, `malformed-row`, and
  `budget-exceeded` anomalies explicitly.
- **`native_extensions`** and **`contents`**: file inventory with path-derived
  roles (`dist-info`, `data`, `python-source`, `python-bytecode`, `python-stub`,
  `native-extension`, `resource`).

## Limitations

Metadata declarations and `RECORD` hashes describe archive contents only; they
do not prove runtime behavior, dependency resolution results, or package safety.
Missing or ambiguous `*.dist-info` directories succeed with inventory and
explicit limitations. Set `verify_record: false` to skip hashing members, or
adjust `max_record_verify_bytes` when inspecting large distributions.
