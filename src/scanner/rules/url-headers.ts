/**
 * AttestLens — URL Security Header Checks
 * 
 * Checks HTTP response headers for missing or misconfigured security headers.
 * Each check maps to APP_11.1 (Security of personal information).
 */

import type { Severity } from '../../schema/index.js';

export interface HeaderCheck {
  id: string;
  header: string;
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  validate: (value: string | undefined) => boolean; // true = PASS
}

export const HEADER_CHECKS: HeaderCheck[] = [
  {
    id: 'AL-URL-001',
    header: 'content-security-policy',
    severity: 'high',
    title: 'Missing Content-Security-Policy Header',
    description: 'Content-Security-Policy prevents XSS, clickjacking, and other code injection attacks by specifying approved sources of content.',
    fixPrompt: `Add a Content-Security-Policy header to your server configuration:

For Next.js (next.config.js):
\`\`\`js
const cspHeader = \`
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
\`

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: cspHeader }] }]
  }
}
\`\`\`

This addresses APP 11.1 — taking reasonable steps to protect personal information from misuse, interference, and loss.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-002',
    header: 'strict-transport-security',
    severity: 'high',
    title: 'Missing Strict-Transport-Security Header',
    description: 'HSTS forces browsers to always use HTTPS, preventing protocol downgrade attacks and cookie hijacking.',
    fixPrompt: `Add a Strict-Transport-Security header to your server configuration:

\`\`\`
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
\`\`\`

For Express:
\`\`\`js
app.use(require('helmet')());
// or specifically:
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});
\`\`\`

This addresses APP 11.1 — protecting personal information during transmission.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-003',
    header: 'x-frame-options',
    severity: 'medium',
    title: 'Missing X-Frame-Options Header',
    description: 'X-Frame-Options prevents clickjacking by controlling whether a page can be embedded in an iframe. Modern browsers also support CSP frame-ancestors directive.',
    fixPrompt: `Add an X-Frame-Options header (or use CSP frame-ancestors):

\`\`\`
X-Frame-Options: DENY
\`\`\`

Or use Content-Security-Policy instead:
\`\`\`
Content-Security-Policy: ...; frame-ancestors 'none';
\`\`\`

For Express:
\`\`\`js
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
\`\`\`

This addresses APP 11.1 — preventing clickjacking attacks that could expose personal information.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-004',
    header: 'x-content-type-options',
    severity: 'low',
    title: 'Missing X-Content-Type-Options Header',
    description: 'X-Content-Type-Options: nosniff prevents browsers from MIME-type sniffing, which can execute uploaded files as scripts.',
    fixPrompt: `Add the X-Content-Type-Options header:

\`\`\`
X-Content-Type-Options: nosniff
\`\`\`

For Express:
\`\`\`js
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
\`\`\`

This addresses APP 11.1 — preventing content type confusion attacks.`,
    validate: (value) => value?.toLowerCase() === 'nosniff',
  },
  {
    id: 'AL-URL-005',
    header: 'referrer-policy',
    severity: 'medium',
    title: 'Missing Referrer-Policy Header',
    description: 'Referrer-Policy controls how much referrer information is shared with other sites. Without it, browsers may send full URLs including sensitive path/query parameters.',
    fixPrompt: `Add a Referrer-Policy header:

\`\`\`
Referrer-Policy: strict-origin-when-cross-origin
\`\`\`

For Next.js:
\`\`\`js
module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }] }]
  }
}
\`\`\`

This addresses APP 6.1 — controlling disclosure of personal information via referrer headers.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-006',
    header: 'permissions-policy',
    severity: 'low',
    title: 'Missing Permissions-Policy Header',
    description: 'Permissions-Policy controls which browser features and APIs the page can use (camera, microphone, geolocation, etc.).',
    fixPrompt: `Add a Permissions-Policy header:

\`\`\`
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
\`\`\`

For Express:
\`\`\`js
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});
\`\`\`

This addresses APP 11.1 — restricting access to sensitive browser APIs.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-007',
    header: 'x-xss-protection',
    severity: 'info',
    title: 'Missing X-XSS-Protection Header (Legacy)',
    description: 'X-XSS-Protection is a legacy header for older browsers. Modern browsers rely on Content-Security-Policy instead. Only needed if supporting IE or old browsers.',
    fixPrompt: `X-XSS-Protection is a legacy header. Modern browsers use Content-Security-Policy instead.

If you need to support older browsers:
\`\`\`
X-XSS-Protection: 1; mode=block
\`\`\`

However, the preferred approach is to use Content-Security-Policy, which provides stronger XSS protection. Consider this a low-priority fix unless you have specific IE/legacy browser requirements.

This addresses APP 11.1 — XSS prevention.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-008',
    header: 'cross-origin-opener-policy',
    severity: 'medium',
    title: 'Missing Cross-Origin-Opener-Policy Header',
    description: 'COOP isolates your document from cross-origin documents opened via window.open or links, preventing side-channel attacks like Spectre.',
    fixPrompt: `Add a Cross-Origin-Opener-Policy header:

\`\`\`
Cross-Origin-Opener-Policy: same-origin
\`\`\`

For Express:
\`\`\`js
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
});
\`\`\`

This addresses APP 11.1 — protecting against cross-origin information leaks.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-009',
    header: 'cross-origin-resource-policy',
    severity: 'medium',
    title: 'Missing Cross-Origin-Resource-Policy Header',
    description: 'CORP prevents cross-origin resources from being loaded by other sites, mitigating speculative side-channel attacks.',
    fixPrompt: `Add a Cross-Origin-Resource-Policy header:

\`\`\`
Cross-Origin-Resource-Policy: same-origin
\`\`\`

For Express:
\`\`\`js
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});
\`\`\`

This addresses APP 11.1 — preventing cross-origin resource access.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-010',
    header: 'cross-origin-embedder-policy',
    severity: 'low',
    title: 'Missing Cross-Origin-Embedder-Policy Header',
    description: 'COEP requires all loaded resources to opt-in to being loaded, enabling use of SharedArrayBuffer and preventing data leaks.',
    fixPrompt: `Add a Cross-Origin-Embedder-Policy header:

\`\`\`
Cross-Origin-Embedder-Policy: require-corp
\`\`\`

Note: This can break third-party resources that don\'t set CORP headers. Use \`credentialless\` for a softer approach:

\`\`\`
Cross-Origin-Embedder-Policy: credentialless
\`\`\`

This addresses APP 11.1 — preventing cross-origin data leakage.`,
    validate: (value) => !!value,
  },
  {
    id: 'AL-URL-011',
    header: 'cache-control',
    severity: 'medium',
    title: 'Missing or Weak Cache-Control Header',
    description: 'Without proper Cache-Control, sensitive pages may be cached by browsers or CDNs, potentially exposing personal information.',
    fixPrompt: `Add appropriate Cache-Control headers for pages containing personal information:

\`\`\`
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0
\`\`\`

For Express:
\`\`\`js
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});
\`\`\`

This addresses APP 11.1 — preventing caching of personal information.`,
    validate: (value) => {
      if (!value) return false;
      // Fail if cache-control allows caching on sensitive endpoints
      // We can't determine "sensitive" from headers alone, so we pass if present
      return true;
    },
  },
  {
    id: 'AL-URL-012',
    header: 'server',
    severity: 'info',
    title: 'Server Version Disclosure',
    description: 'The Server header reveals technology version information that attackers can use to find known vulnerabilities.',
    fixPrompt: `Remove or minimize the Server header to avoid version disclosure:

For Express:
\`\`\`js
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('Server', ''); // or a generic value
  next();
});
\`\`\`

For Nginx:
\`\`\`
server_tokens off;
\`\`\`

For Apache:
\`\`\`
ServerTokens Prod
ServerSignature Off
\`\`\`

This addresses APP 11.1 — reducing information disclosure that could aid attacks.`,
    validate: (value) => {
      if (!value) return true; // No server header is good
      // Fail if server header contains version info
      const versionPattern = /\d+\.\d+/;
      return !versionPattern.test(value);
    },
  },
];
