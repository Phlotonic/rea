import { TypeScriptDeclarationsService } from "../application/javascript/TypeScriptDeclarationsService.js";
import { TypeScriptDeclarationsProvider } from "../javascript/typescript/TypeScriptDeclarationsProvider.js";
import type { TypeScriptDeclarationsPort } from "../ports/javascript/TypeScriptDeclarationsPort.js";

/** Compose read-only .d.ts / .d.ts.map surface inspection without invoking tsc. */
export const createTypeScriptDeclarationsService =
  (): TypeScriptDeclarationsService => {
    const provider: TypeScriptDeclarationsPort =
      new TypeScriptDeclarationsProvider();
    return new TypeScriptDeclarationsService(provider);
  };
