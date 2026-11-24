/** Bundled static PyTorch/pickle reader identity; never executes pickle opcodes. */
export const PYTORCH_PICKLE_PROVIDER_IDENTITY = {
  id: "rea-pytorch-pickle",
  name: "REA PyTorch and pickle checkpoint reader",
  version: "1",
} as const;
