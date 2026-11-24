import { PytorchPickleService } from "../application/python/PytorchPickleService.js";
import type { PytorchPicklePort } from "../ports/python/PytorchPicklePort.js";
import { PytorchPickleProvider } from "../python/PytorchPickleProvider.js";

/** Compose read-only PyTorch/pickle inspection without executing any callable. */
export const createPytorchPickleService = (): PytorchPickleService => {
  const provider: PytorchPicklePort = new PytorchPickleProvider();
  return new PytorchPickleService(provider);
};
