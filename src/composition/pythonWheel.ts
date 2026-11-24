import { PythonWheelService } from "../application/python/PythonWheelService.js";
import type { PythonWheelPort } from "../ports/python/PythonWheelPort.js";
import { PythonWheelProvider } from "../python/PythonWheelProvider.js";

/** Compose read-only .whl inspection without installing, importing, or network. */
export const createPythonWheelService = (): PythonWheelService => {
  const provider: PythonWheelPort = new PythonWheelProvider();
  return new PythonWheelService(provider);
};
