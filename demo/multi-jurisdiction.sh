#!/usr/bin/env bash
set -uo pipefail

if [[ "${TRACE:-}" == "1" ]]; then
  set -x
fi

if [[ -n "${ATTESTLENS_CLI:-}" ]]; then
  read -r -a CLI_CMD <<< "${ATTESTLENS_CLI}"
else
  CLI_CMD=(npx @attestlens/cli)
fi

EXTRA_AUDIT_FLAGS=()
if [[ -n "${ATTESTLENS_DEMO_EXTRA_FLAGS:-}" ]]; then
  read -r -a EXTRA_AUDIT_FLAGS <<< "${ATTESTLENS_DEMO_EXTRA_FLAGS}"
fi

if [[ -n "${ATTESTLENS_DEMO_DIR:-}" ]]; then
  WORK_DIR="${ATTESTLENS_DEMO_DIR}"
  mkdir -p "${WORK_DIR}"
else
  WORK_DIR="$(mktemp -d)"
fi

PROJECT_DIR="${WORK_DIR}/demo-project"
OUTPUT_DIR="${WORK_DIR}/outputs"
rm -rf "${PROJECT_DIR}" "${OUTPUT_DIR}"
mkdir -p "${PROJECT_DIR}" "${OUTPUT_DIR}"

cleanup() {
  if [[ -z "${ATTESTLENS_DEMO_DIR:-}" && "${KEEP_DEMO_PROJECT:-}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  else
    echo
    echo "Demo project kept at: ${PROJECT_DIR}"
    echo "Agent outputs kept at: ${OUTPUT_DIR}"
  fi
}
trap cleanup EXIT

# Force the built-in static fallback when GuardVibe is not intentionally wired.
# This keeps the demo deterministic while still running Clearway's normal audit command.
export ATTESTLENS_GUARDVIBE_PATH="${ATTESTLENS_GUARDVIBE_PATH:-attestlens-demo-static-fallback}"

cat > "${PROJECT_DIR}/privacy-policy.html" <<'HTML'
<!doctype html>
<html>
  <body>
    <h1>Privacy Policy</h1>
    <p>We collect personal information and personal data from customers.</p>
    <p>Contact privacy@example.test for privacy questions.</p>
  </body>
</html>
HTML

cat > "${PROJECT_DIR}/config.json" <<'JSON'
{
  "transfer_data_overseas": true,
  "data_transfer_note": "We transfer personal data outside the EEA to third-country processors without documented safeguards."
}
JSON

cat > "${PROJECT_DIR}/package.json" <<'JSON'
{
  "name": "clearway-multi-jurisdiction-demo-target",
  "version": "1.0.0",
  "private": true,
  "description": "Demo target intentionally omits a privacy-policy homepage link.",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {}
}
JSON

cat > "${PROJECT_DIR}/package-lock.json" <<'JSON'
{
  "name": "clearway-multi-jurisdiction-demo-target",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "clearway-multi-jurisdiction-demo-target",
      "version": "1.0.0",
      "dependencies": {}
    }
  }
}
JSON

cat > "${PROJECT_DIR}/Dockerfile" <<'DOCKER'
FROM node:22
WORKDIR /app
COPY package.json package-lock.json ./
COPY server.js ./
USER root
CMD ["node", "server.js"]
DOCKER

cat > "${PROJECT_DIR}/server.js" <<'JS'
const http = require('node:http');

const api_secret_key = 'demo_secret_key_1234567890';
const corsHeader = "Access-Control-Allow-Origin: '*'";

http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/signup') {
    const body = { email: req.body?.email, token: req.body?.token };
    console.log('customer email submitted', {
      email: req.body?.email,
      authToken: req.body?.token
    });
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.end(JSON.stringify({ ok: true, body, corsHeader, api_secret_key }));
    return;
  }

  res.statusCode = 404;
  res.end('not found');
}).listen(3000);
JS

run_audit() {
  local jurisdiction="$1"
  local output_file="${OUTPUT_DIR}/${jurisdiction}.json"
  local stderr_file="${OUTPUT_DIR}/${jurisdiction}.stderr"

  echo
  echo "$ ${CLI_CMD[*]} audit ./demo-project --jurisdiction ${jurisdiction} --opinion --format agent ${EXTRA_AUDIT_FLAGS[*]}"

  (
    cd "${WORK_DIR}" || exit 1
    "${CLI_CMD[@]}" audit ./demo-project \
      --jurisdiction "${jurisdiction}" \
      --opinion \
      --format agent \
      "${EXTRA_AUDIT_FLAGS[@]}" \
      > "${output_file}" 2> "${stderr_file}"
  )
  local status=$?
  printf "%s" "${status}" > "${output_file}.status"

  if ! node -e 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"))' "${output_file}" >/dev/null 2>&1; then
    echo "Audit for ${jurisdiction} did not return valid agent JSON." >&2
    echo "stderr:" >&2
    cat "${stderr_file}" >&2
    exit 1
  fi
}

echo "Clearway multi-jurisdiction demo"
echo "Demo project: ${PROJECT_DIR}"

run_audit "au-privacy-act"
run_audit "us-ccpa"
run_audit "eu-gdpr"

node - "${OUTPUT_DIR}/au-privacy-act.json" "${OUTPUT_DIR}/us-ccpa.json" "${OUTPUT_DIR}/eu-gdpr.json" <<'NODE'
const fs = require('node:fs');

const files = process.argv.slice(2);
const runs = [
  {
    label: 'AU Privacy Act',
    file: files[0],
    principles: ['APP_6', 'APP_11'],
  },
  {
    label: 'US CCPA/CPRA',
    file: files[1],
    principles: ['CCPA_100', 'CCPA_120', 'CCPA_135'],
  },
  {
    label: 'EU GDPR',
    file: files[2],
    principles: ['GDPR_Art5', 'GDPR_Art32', 'GDPR_Art44'],
  },
];

const citations = {
  APP_6: 'APP Guidelines Chapter 6.1',
  APP_11: 'APP Guidelines Chapter 11.1',
  CCPA_100: 'Cal. Civ. Code §1798.100',
  CCPA_120: 'Cal. Civ. Code §1798.120',
  CCPA_135: 'Cal. Civ. Code §1798.135',
  GDPR_Art5: 'GDPR Art. 5',
  GDPR_Art32: 'GDPR Art. 32',
  GDPR_Art44: 'GDPR Art. 44-49',
};

for (const run of runs) {
  const data = JSON.parse(fs.readFileSync(run.file, 'utf8'));
  const status = fs.readFileSync(`${run.file}.status`, 'utf8').trim();

  console.log(`\n=== ${run.label} ===`);
  console.log(`Command exit: ${status} (non-zero is expected for NON_COMPLIANT agent output)`);
  console.log(`Verdict: ${data.verdict} | confidence: ${data.confidence} | score: ${data.score} | risk: ${data.riskLevel}`);
  console.log(`Summary: ${data.summary}`);
  console.log('Cited controls and remediations:');

  for (const principle of run.principles) {
    const action = data.actions.find((candidate) => candidate.principle === principle);
    if (!action) {
      console.log(`- ${principle} (${citations[principle]}): not cited in this run`);
      continue;
    }

    const remediation = action.remediation || action.action;
    console.log(`- ${principle} (${citations[principle]}): ${action.verdict}; ${remediation}`);
  }
}

console.log('\nSame demo project, three different compliance realities.');
NODE
