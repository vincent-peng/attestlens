import { describe, expect, it } from 'vitest';

import { SAST_LITE_RULES, scanSastLiteFiles } from './sast-lite.js';
import { ATTESTLENS_VERSION } from '../../version.js';

const CASES: Array<{ ruleId: string; positive: string; negative: string }> = [
  {
    ruleId: 'VS-SAST-001',
    positive: 'const serviceToken = "abcdEFGH1234567890";',
    negative: 'const serviceToken = process.env.SERVICE_TOKEN;',
  },
  {
    ruleId: 'VS-SAST-002',
    positive: 'res.cookie("session", sessionId);',
    negative: 'res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "lax" });',
  },
  {
    ruleId: 'VS-SAST-003',
    positive: 'crypto.createHash("md5").update(value);',
    negative: 'crypto.createHash("sha256").update(value);',
  },
  {
    ruleId: 'VS-SAST-004',
    positive: 'db.query("select * from users where id=" + req.params.id);',
    negative: 'db.query("select * from users where id=$1", [req.params.id]);',
  },
  {
    ruleId: 'VS-SAST-005',
    positive: 'fs.readFile(req.query.path, "utf8");',
    negative: 'fs.readFile(path.join(SAFE_DIR, filename), "utf8");',
  },
  {
    ruleId: 'VS-SAST-006',
    positive: 'fetch(req.query.url);',
    negative: 'fetch("https://api.example.com/status");',
  },
  {
    ruleId: 'VS-SAST-007',
    positive: 'console.log("token", token);',
    negative: 'console.log("user id", user.id);',
  },
  {
    ruleId: 'VS-SAST-008',
    positive: 'const body = JSON.parse(req.body.payload);',
    negative: 'const body = schema.parse(JSON.parse(payload));',
  },
  {
    ruleId: 'VS-SAST-009',
    positive: 'router.post("/api/user", async (req, res) => createUser(req.body));',
    negative: 'router.post("/api/user", validate(userSchema), async (req, res) => createUser(req.body));',
  },
  {
    ruleId: 'VS-SAST-010',
    positive: 'app.use(cors({ origin: "*" }));',
    negative: 'app.use(cors({ origin: "https://app.example.com" }));',
  },
  {
    ruleId: 'VS-SAST-011',
    positive: 'token = req.query.token;',
    negative: 'token = req.body.token;',
  },
  {
    ruleId: 'VS-SAST-012',
    positive: 'localStorage.setItem("authToken", token);',
    negative: 'sessionStorage.setItem("theme", theme);',
  },
  {
    ruleId: 'VS-SAST-013',
    positive: 's3.putObject({ Bucket: bucket, Key: key, Body: body });',
    negative: 's3.putObject({ Bucket: bucket, Key: key, Body: body, ServerSideEncryption: "AES256" });',
  },
  {
    ruleId: 'VS-SAST-014',
    positive: 'const unsafe = /(a+)+$/;',
    negative: 'const safe = /^[a-z0-9_-]+$/;',
  },
  {
    ruleId: 'VS-SAST-015',
    positive: 'router.get("/admin", (req, res) => listUsers());',
    negative: 'router.get("/admin", requireAuth, (req, res) => listUsers());',
  },
  {
    ruleId: 'VS-SAST-016',
    positive: 'res.json({ stack: error.stack });',
    negative: 'logger.error(error.stack); res.json({ error: "Internal error" });',
  },
  {
    ruleId: 'VS-SAST-017',
    positive: 'router.post("/account/delete", (req, res) => deleteAccount());',
    negative: 'router.post("/account/delete", csrfProtection, (req, res) => deleteAccount());',
  },
  {
    ruleId: 'VS-SAST-018',
    positive: 'res.redirect(req.query.next);',
    negative: 'res.redirect("/dashboard");',
  },
  {
    ruleId: 'VS-SAST-019',
    positive: 'email: req.body.email,',
    negative: 'email: req.body.email, consent: req.body.consent,',
  },
  {
    ruleId: 'VS-SAST-020',
    positive: 'users.insert({ email: req.body.email });',
    negative: 'users.insert({ email: req.body.email, retention: "30d" });',
  },
];

describe('SAST-lite rules', () => {
  it('defines 20 rules with remediation prompts', () => {
    expect(SAST_LITE_RULES).toHaveLength(20);
    expect(SAST_LITE_RULES.every(rule => rule.fixPrompt.length > 0)).toBe(true);
  });

  it.each(CASES)('detects $ruleId positive fixtures', ({ ruleId, positive }) => {
    const findings = scanSastLiteFiles([{
      relativePath: `src/${ruleId}.ts`,
      content: positive,
    }], ATTESTLENS_VERSION);

    expect(findings.some(finding => finding.sourceRule === ruleId)).toBe(true);
    expect(findings.find(finding => finding.sourceRule === ruleId)?.fixPrompt).toBeTruthy();
  });

  it.each(CASES)('does not flag $ruleId negative fixtures', ({ ruleId, negative }) => {
    const findings = scanSastLiteFiles([{
      relativePath: `src/${ruleId}.ts`,
      content: negative,
    }], ATTESTLENS_VERSION);

    expect(findings.some(finding => finding.sourceRule === ruleId)).toBe(false);
  });
});
