# SG PDPA Demo Output

Expected walkthrough from:

```bash
bash demo/rule-authoring.sh
```

If `OPENAI_API_KEY` is missing, the script exits cleanly after printing a skip message.

```text
Clearway SG PDPA authoring demo
Source: demo/sg-pdpa-2012.txt
Project: demo/test-project

1. Proposing rules from SG PDPA source text
$ npx @attestlens/cli propose-rules --jurisdiction sg-pdpa --source demo/sg-pdpa-2012.txt --output /tmp/proposed-sg-pdpa.json
Wrote proposed pack to /tmp/proposed-sg-pdpa.json

2. Reviewing and approving the proposed pack
$ ATTESTLENS_UNSAFE_TEST_MODE=1 npx @attestlens/cli review-pack --proposed /tmp/proposed-sg-pdpa.json --reviewer demo-reviewer --approve-all --output ~/.attestlens/jurisdictions/sg-pdpa/latest.json
Wrote validated pack to ~/.attestlens/jurisdictions/sg-pdpa/latest.json
Wrote runtime pack to ~/.attestlens/jurisdictions/sg-pdpa/latest.runtime.json

3. Scanning the demo project with the approved SG PDPA pack
$ npx @attestlens/cli scan demo/test-project --jurisdiction sg-pdpa
Findings:
- SGPDPA-CONSENT-001: Missing consent or preference mechanism
- SGPDPA-PURPOSE-001: Privacy notice missing purpose statement
- VS-HARDKEY or SGPDPA-SEC-001: hardcoded secret / plaintext personal data signal
```

Expected demo properties:

- The reviewed pack is saved to `~/.attestlens/jurisdictions/sg-pdpa/latest.json`.
- The runtime pack is saved beside it as `latest.runtime.json`.
- The scanner discovers the runtime pack automatically when `--jurisdiction sg-pdpa` is used.
- Reviewed rules load deterministically. No LLM calls happen during the scan.

Intentional violations in `demo/test-project`:

- `index.html` has a signup form with no visible consent or privacy notice.
- `server.js` contains a hardcoded API key.
- No access-request flow or privacy policy content is present.
