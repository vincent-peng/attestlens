import { readFileSync } from 'node:fs';

export function readPackageVersion(): string {
  const packageJsonUrl = new URL('../package.json', import.meta.url);
  const packageJson = JSON.parse(readFileSync(packageJsonUrl, 'utf-8')) as { version?: unknown };
  if (typeof packageJson.version !== 'string' || packageJson.version.length === 0) {
    throw new Error('Unable to determine AttestLens version from package.json');
  }
  return packageJson.version;
}

export const ATTESTLENS_VERSION = readPackageVersion();

export function buildAttestLensUserAgent(): string {
  return `AttestLens/${ATTESTLENS_VERSION} (Security Scanner; +https://attestlens.dev)`;
}
