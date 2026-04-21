import { prepareAttestValidationCli } from '../src/validation/attest.js';

prepareAttestValidationCli().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
