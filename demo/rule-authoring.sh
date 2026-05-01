#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${ATTESTLENS_CLI:-}" ]]; then
  read -r -a CLI_CMD <<< "${ATTESTLENS_CLI}"
else
  CLI_CMD=(npx @attestlens/cli)
fi

SOURCE_FILE="demo/sg-pdpa-2012.txt"
PROJECT_DIR="demo/test-project"
PROPOSED_OUTPUT="/tmp/proposed-sg-pdpa.json"
VALIDATED_OUTPUT="${HOME}/.attestlens/jurisdictions/sg-pdpa/latest.json"

echo "Clearway SG PDPA authoring demo"
echo "Source: ${SOURCE_FILE}"
echo "Project: ${PROJECT_DIR}"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo
  echo "OPENAI_API_KEY is not set. Skipping propose-rules and the rest of the demo."
  echo "Set OPENAI_API_KEY and rerun to exercise the full pipeline."
  exit 0
fi

echo
echo "1. Proposing rules from SG PDPA source text"
"${CLI_CMD[@]}" propose-rules \
  --jurisdiction sg-pdpa \
  --source "${SOURCE_FILE}" \
  --output "${PROPOSED_OUTPUT}"

echo
echo "2. Reviewing and approving the proposed pack"
ATTESTLENS_UNSAFE_TEST_MODE=1 "${CLI_CMD[@]}" review-pack \
  --proposed "${PROPOSED_OUTPUT}" \
  --reviewer "demo-reviewer" \
  --approve-all \
  --output "${VALIDATED_OUTPUT}"

echo
echo "3. Scanning the demo project with the approved SG PDPA pack"
"${CLI_CMD[@]}" scan "${PROJECT_DIR}" --jurisdiction sg-pdpa
