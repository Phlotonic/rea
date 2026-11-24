import type { NpmPackagePort } from "../ports/javascript/NpmPackagePort.js";
import { NpmPackageService } from "../application/javascript/NpmPackageService.js";
import { NpmPackageProvider } from "../javascript/npm/NpmPackageProvider.js";

/** Compose read-only npm .tgz inspection without npm install, execution, or network. */
export const createNpmPackageService = (): NpmPackageService => {
  const provider: NpmPackagePort = new NpmPackageProvider();
  return new NpmPackageService(provider);
};
