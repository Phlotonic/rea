# PyTorch checkpoints and Python pickles

`inspect_pytorch_checkpoint` / `inspect-pytorch-checkpoint` statically inspects
local PyTorch ZIP checkpoints (`.pt`, `.pth`, `.ckpt`, `.bin`) and standalone
Python pickle files (`.pkl`, `.pickle`) without executing pickle opcodes,
invoking Python, or loading tensor buffers into memory.

```bash
rea inspect-pytorch-checkpoint /absolute/path/to/model.pt --json
```

```json
{
  "name": "inspect_pytorch_checkpoint",
  "arguments": { "path": "/artifacts/model.pt" }
}
```

## What is returned

- **`container_format`**: `"pytorch-zip"` or `"raw-pickle"`.
- **`archive`**: for ZIP-based checkpoints, reports the archive prefix,
  `data.pkl` path, `version`, `byteorder`, entry count, and `data/*` tensor
  storage inventory.
- **`pickle`**: decoded protocol version (0–5), opcode count, `REDUCE` /
  `BUILD` / `NEWOBJ` / `BINPERSID` counts, all referenced globals
  (`GLOBAL`, `STACK_GLOBAL`, `INST`, `EXT*`), `top_level_keys`, and
  **`flagged_globals`** classifying code-execution or privileged imports
  (`os`, `subprocess`, `builtins.eval`/`exec`/`__import__`, `ctypes`,
  `marshal.loads`, `types.CodeType`, network modules, etc.) with byte offsets.
- **`tensors`**: reconstructed `state_dict` / `OrderedDict` tensor entries
  (`name`, `rebuilder`, `dtype`, `storage_type`, `storage_key`, `storage_location`,
  `storage_numel`, `storage_offset`, `shape`, `stride`, `requires_grad`, and
  cross-referenced ZIP `archive_member` / `archive_bytes`).

## Limitations

Flagged globals identify known code-execution or privileged imports; absence of
flagged globals does not prove that unpickling a file is safe. Set `max_opcodes`
or `max_pickle_bytes` higher when inspecting unusually large graphs.
