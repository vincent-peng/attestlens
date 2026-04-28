import crypto from 'node:crypto';

import type { AttestLensFinding, Severity } from '../../schema/index.js';

export interface SastLiteFile {
  relativePath: string;
  content: string;
}

interface SastLiteRule {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  fix: string;
  fixPrompt: string;
  pattern: RegExp;
}

const SOURCE_FILE_PATTERN = /\.(?:ts|tsx|js|jsx|mjs|cjs)$/i;

export const SAST_LITE_RULES: SastLiteRule[] = [
  {
    id: 'VS-SAST-001',
    severity: 'critical',
    category: 'SAST Lite',
    title: 'Hardcoded credential in source',
    description: 'A source file appears to assign a credential-like value directly in code.',
    fix: 'Rotate the value and load credentials from a server-side secret manager or environment variable.',
    fixPrompt: 'Replace the hardcoded credential with a server-side secret lookup, rotate the exposed value, and add a regression test that prevents committing literal credentials.',
    pattern: /\b(?:const|let|var)\s+\w*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey)\w*\s*=\s*['"](?!process\.env|YOUR_|example|placeholder|dummy|changeme|test_)[A-Za-z0-9_./+=:-]{12,}['"]/i,
  },
  {
    id: 'VS-SAST-002',
    severity: 'high',
    category: 'SAST Lite',
    title: 'Insecure session cookie configuration',
    description: 'A session or auth cookie is set without visible Secure, HttpOnly, or SameSite protections.',
    fix: 'Set httpOnly, secure, and sameSite on sensitive cookies.',
    fixPrompt: 'Update the cookie-setting code so sensitive cookies are httpOnly, secure in production, and have an explicit sameSite policy.',
    pattern: /^(?!.*(?:httpOnly|secure|sameSite)).*\b(?:res|reply)\.cookie\s*\(\s*['"](?:session|token|auth)[^'"]*['"]/i,
  },
  {
    id: 'VS-SAST-003',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Weak cryptographic algorithm',
    description: 'Weak cryptography such as MD5, SHA-1, DES, or RC4 appears in source code.',
    fix: 'Replace weak cryptography with modern, approved algorithms and review stored hashes or encrypted data.',
    fixPrompt: 'Replace the weak cryptographic primitive with an approved algorithm and add a migration note for any existing hashes or ciphertext.',
    pattern: /\b(?:createHash|createCipher)\s*\(\s*['"](?:md5|sha1|des|rc4|blowfish)['"]|\b(?:md5|sha1)\s*\(/i,
  },
  {
    id: 'VS-SAST-004',
    severity: 'critical',
    category: 'SAST Lite',
    title: 'SQL query built from request input',
    description: 'A database query appears to concatenate or interpolate request-controlled input.',
    fix: 'Use parameterized queries or the ORM parameter binding API.',
    fixPrompt: 'Refactor this query to use parameter binding, validate the request input, and add a test proving raw request values are not concatenated into SQL.',
    pattern: /\b(?:query|execute|raw)\s*\([^;\n]*(?:\+|\$\{)[^;\n]*(?:req\.|params\.|query\.|body\.)/i,
  },
  {
    id: 'VS-SAST-005',
    severity: 'high',
    category: 'SAST Lite',
    title: 'Filesystem path uses request input',
    description: 'Filesystem access appears to use request-controlled input without visible path validation.',
    fix: 'Normalize and constrain file paths to an allowlisted base directory before filesystem access.',
    fixPrompt: 'Add path normalization, reject traversal outside the allowed base directory, and add tests for ../ traversal attempts.',
    pattern: /\b(?:fs\.)?(?:readFile|writeFile|createReadStream|createWriteStream)\s*\([^;\n]*(?:req\.|params\.|query\.|body\.)/i,
  },
  {
    id: 'VS-SAST-006',
    severity: 'high',
    category: 'SAST Lite',
    title: 'Outbound request uses untrusted URL input',
    description: 'An outbound request appears to use request-controlled URL input.',
    fix: 'Allowlist destinations and validate URL scheme, host, and path before making outbound requests.',
    fixPrompt: 'Add SSRF protection by validating the destination against an allowlist and rejecting private/internal network targets.',
    pattern: /\b(?:fetch|axios\.(?:get|post|request)|https?\.get|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)/i,
  },
  {
    id: 'VS-SAST-007',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Sensitive data logged',
    description: 'A logging statement appears to include credential or authentication data.',
    fix: 'Remove sensitive values from logs and log only stable identifiers or redacted metadata.',
    fixPrompt: 'Remove the sensitive value from this log call, replace it with redacted metadata, and add a logging test or lint rule if available.',
    pattern: /\bconsole\.\w+\s*\([^;\n]*(?:password|token|secret|credential|auth)/i,
  },
  {
    id: 'VS-SAST-008',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Untrusted JSON parsed without validation',
    description: 'Request-controlled JSON is parsed without visible schema validation.',
    fix: 'Validate parsed JSON with a schema before using or merging it.',
    fixPrompt: 'Add schema validation around this JSON.parse call and reject inputs that include prototype-polluting keys.',
    pattern: /\bJSON\.parse\s*\(\s*(?:req\.|params\.|query\.|body\.|input)/i,
  },
  {
    id: 'VS-SAST-009',
    severity: 'low',
    category: 'SAST Lite',
    title: 'Mutation route lacks visible input validation',
    description: 'A mutation route handler appears without nearby schema or validation middleware.',
    fix: 'Add request validation middleware or a schema parser before processing input.',
    fixPrompt: 'Add a zod, joi, or equivalent schema validation step to this mutation route before business logic runs.',
    pattern: /^(?!.*(?:validate|schema|zod|joi)).*\b(?:app|router)\.(?:post|put|patch)\s*\([^;\n]*(?:req\s*,\s*res)/i,
  },
  {
    id: 'VS-SAST-010',
    severity: 'high',
    category: 'SAST Lite',
    title: 'Wildcard CORS origin',
    description: 'CORS appears to allow any origin.',
    fix: 'Restrict CORS to trusted origins and vary by environment.',
    fixPrompt: 'Replace wildcard CORS with an explicit allowlist of trusted origins and tests for rejected origins.',
    pattern: /\b(?:origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"])/i,
  },
  {
    id: 'VS-SAST-011',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Sensitive data read from URL parameters',
    description: 'Credential or personal-data fields appear to be read from URL query parameters.',
    fix: 'Move sensitive values out of URLs and use body fields or secure server-side state.',
    fixPrompt: 'Replace the sensitive URL parameter flow with a request body or server-side state flow and scrub existing logs that may contain the parameter.',
    pattern: /\b(?:password|token|secret|ssn|credit_card|tax_file_number)\s*(?:=|:)\s*(?:req\.query|searchParams|get\()/i,
  },
  {
    id: 'VS-SAST-012',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Sensitive data stored in localStorage',
    description: 'Sensitive authentication or credential data appears to be stored in localStorage.',
    fix: 'Avoid localStorage for sensitive data; use httpOnly cookies or short-lived in-memory state.',
    fixPrompt: 'Move this sensitive value out of localStorage and into an httpOnly cookie or short-lived memory-only state.',
    pattern: /\blocalStorage\.setItem\s*\([^;\n]*(?:password|token|secret|key|auth)/i,
  },
  {
    id: 'VS-SAST-013',
    severity: 'high',
    category: 'SAST Lite',
    title: 'Cloud object upload lacks visible encryption setting',
    description: 'Cloud object upload code appears without a visible server-side encryption setting.',
    fix: 'Enable server-side encryption for object uploads and enforce it at the bucket policy level.',
    fixPrompt: 'Add server-side encryption to this object upload and enforce encryption with a bucket policy or equivalent control.',
    pattern: /\b(?:s3|storage)\.(?:putObject|upload|save)\s*\(\s*\{(?![^;\n]*(?:ServerSideEncryption|encryption|kms))/i,
  },
  {
    id: 'VS-SAST-014',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Potential catastrophic regular expression',
    description: 'A regular expression appears to include nested quantifiers that can cause ReDoS.',
    fix: 'Simplify the regex or use a safe-regex validation library before accepting untrusted input.',
    fixPrompt: 'Rewrite this regex to avoid nested quantifiers and add a regression test with long adversarial input.',
    pattern: /(?:new RegExp\s*\(\s*['"][^'"]*(?:\([^)]*[+*][^)]*\)[+*])|\/[^/\n]*(?:\([^)]*[+*][^)]*\)[+*])[^/\n]*\/)/i,
  },
  {
    id: 'VS-SAST-015',
    severity: 'high',
    category: 'SAST Lite',
    title: 'Sensitive route lacks visible authentication',
    description: 'An admin or sensitive API route appears without visible authentication middleware.',
    fix: 'Require authentication and authorization before executing sensitive route logic.',
    fixPrompt: 'Add authentication and authorization middleware to this sensitive route and test unauthenticated access.',
    pattern: /^(?!.*(?:auth|requireAuth|authenticate|authorize)).*\b(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"]\/(?:admin|api\/(?:user|data|config))[^'"]*['"]/i,
  },
  {
    id: 'VS-SAST-016',
    severity: 'low',
    category: 'SAST Lite',
    title: 'Stack trace exposed in response',
    description: 'An HTTP response appears to expose an exception stack trace.',
    fix: 'Return generic error messages to clients and log stack traces server-side only.',
    fixPrompt: 'Replace this response with a generic client-safe error and keep stack traces in server-side logs only.',
    pattern: /\b(?:res|reply)\.(?:send|json)\s*\([^;\n]*(?:err|error|exception)\.stack/i,
  },
  {
    id: 'VS-SAST-017',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'State-changing route lacks visible CSRF protection',
    description: 'A state-changing route appears without visible CSRF protection.',
    fix: 'Add CSRF protection or use same-site cookie and token controls for browser-authenticated routes.',
    fixPrompt: 'Add CSRF middleware or token validation to this state-changing route and test missing-token rejection.',
    pattern: /^(?!.*(?:csrf|csrfProtection|verifyCsrf)).*\b(?:app|router)\.(?:post|put|delete|patch)\s*\(/i,
  },
  {
    id: 'VS-SAST-018',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Redirect uses untrusted input',
    description: 'Redirect destination appears to come from request-controlled input.',
    fix: 'Validate redirect targets against an allowlist or use relative paths only.',
    fixPrompt: 'Constrain this redirect to allowlisted destinations and add tests for external redirect attempts.',
    pattern: /\b(?:res\.)?redirect\s*\(\s*(?:req\.query|req\.body|params\.|query\.)/i,
  },
  {
    id: 'VS-SAST-019',
    severity: 'medium',
    category: 'SAST Lite',
    title: 'Personal data collected without visible consent check',
    description: 'Personal data appears to be collected from request input without a visible consent or notice check.',
    fix: 'Confirm collection is necessary and add consent, notice, or lawful-basis checks where required.',
    fixPrompt: 'Add an explicit consent, notice, or lawful-basis check before collecting this personal data field.',
    pattern: /^(?!.*(?:consent|notice|lawful)).*\b(?:email|phone|address|dob|fullName)\s*[:=]\s*(?:req\.body|body\.)/i,
  },
  {
    id: 'VS-SAST-020',
    severity: 'low',
    category: 'SAST Lite',
    title: 'Personal data write lacks visible retention control',
    description: 'A personal-data write appears without a visible retention, expiry, or deletion control.',
    fix: 'Attach retention metadata or lifecycle deletion logic to personal-data records.',
    fixPrompt: 'Add retention or expiry metadata to this personal-data write path and document the deletion lifecycle.',
    pattern: /^(?!.*(?:expire|expiry|retention|ttl|deleteAt)).*\b(?:users|profiles)\.(?:insert|create)\s*\([^;\n]*(?:email|phone|address|dob)/i,
  },
];

export function scanSastLiteFiles(files: SastLiteFile[], scannerVersion: string): AttestLensFinding[] {
  const findings: AttestLensFinding[] = [];

  for (const file of files) {
    if (!SOURCE_FILE_PATTERN.test(file.relativePath)) continue;
    const lines = file.content.split('\n');
    for (const rule of SAST_LITE_RULES) {
      const match = findFirstMatch(lines, rule.pattern);
      if (!match) continue;
      findings.push(makeFinding(scannerVersion, rule, file.relativePath, match.line, match.code));
    }
  }

  return findings;
}

function findFirstMatch(lines: string[], pattern: RegExp): { line: number; code: string } | null {
  for (let index = 0; index < lines.length; index += 1) {
    pattern.lastIndex = 0;
    if (pattern.test(lines[index] || '')) {
      return { line: index + 1, code: (lines[index] || '').trim() };
    }
  }
  return null;
}

function makeFinding(
  scannerVersion: string,
  rule: SastLiteRule,
  file: string,
  line: number,
  code: string,
): AttestLensFinding {
  const payload = `${rule.id}:${file}:${line}`;
  return {
    id: crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12),
    source: 'guardvibe',
    sourceRule: rule.id,
    severity: rule.severity,
    category: rule.category,
    title: rule.title,
    description: rule.description,
    file,
    line,
    code,
    fix: rule.fix,
    fixPrompt: rule.fixPrompt,
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion,
      rawOutput: {
        sourceRule: rule.id,
        file,
        line,
      },
      scannerCommand: 'attestlens sast-lite',
    },
  };
}
