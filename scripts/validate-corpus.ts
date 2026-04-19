#!/usr/bin/env node
import { runValidationCorpusCli } from '../src/validation/corpus.js';

runValidationCorpusCli().catch((error) => {
  console.error(`Validation corpus failed: ${error.message}`);
  process.exit(1);
});
