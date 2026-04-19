/**
 * AttestLens — JavaScript Bundle Security Analysis
 * 
 * Patterns for detecting security vulnerabilities in client-side JavaScript bundles.
 * Scans fetched JS content for dangerous patterns like XSS vectors, eval usage, etc.
 */

import type { Severity } from '../../schema/index.js';
import type { APPMapping } from '../../schema/index.js';

export interface JSPattern {
  id: string;
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
  /** Only match in non-minified context (skip common framework internals) */
  skipMinified?: boolean;
}

const app11Mapping: APPMapping = {
  principle: 'APP_11',
  obligation: 'Take reasonable steps to protect personal information from misuse, interference, and loss',
  status: 'fail',
  confidence: 0.90,
};

const app61Mapping: APPMapping = {
  principle: 'APP_6',
  obligation: 'Use or disclose personal information only for the primary purpose for which it was collected',
  status: 'fail',
  confidence: 0.85,
};

export const JS_PATTERNS: JSPattern[] = [
  {
    id: 'AL-JS-001',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{[^}]*__html\s*:/g,
    severity: 'high',
    title: 'dangerouslySetInnerHTML Usage Detected',
    description: 'React\'s dangerouslySetInnerHTML was found in client-side code. If the HTML content comes from user input or an untrusted source, this creates an XSS vulnerability.',
    fixPrompt: `Replace dangerouslySetInnerHTML with safer alternatives:

1. **If rendering user content**, sanitize it first:
   \`\`\`typescript
   import DOMPurify from 'dompurify';
   
   const SafeHTML = ({ content }: { content: string }) => (
     <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />
   );
   \`\`\`

2. **Better: Use React components instead of raw HTML**:
   \`\`\`typescript
   // Instead of:
   <div dangerouslySetInnerHTML={{ __html: userContent }} />
   
   // Use:
   <div>{userContent}</div>  // React auto-escapes
   \`\`\`

3. **If you MUST use dangerouslySetInnerHTML**, ensure the content is sanitized and comes from a trusted source.

This addresses APP 11.1 (Security) — protecting against XSS attacks.`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-JS-002',
    pattern: /eval\s*\(/g,
    severity: 'high',
    title: 'eval() Usage Detected',
    description: 'The eval() function was found in client-side code. eval() executes arbitrary JavaScript strings, creating a severe XSS and code injection risk, especially if the argument includes user input.',
    fixPrompt: `Replace eval() with safer alternatives:

1. **For JSON parsing**: Use \`JSON.parse()\` instead:
   \`\`\`typescript
   // Instead of: eval('(' + jsonString + ')')
   const data = JSON.parse(jsonString);
   \`\`\`

2. **For dynamic property access**: Use bracket notation:
   \`\`\`typescript
   // Instead of: eval('obj.' + propertyName)
   const value = obj[propertyName];
   \`\`\`

3. **For computed expressions**: Use \`new Function()\` with strict validation, or refactor to avoid dynamic code execution entirely.

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-JS-003',
    pattern: /document\.write\s*\(/g,
    severity: 'medium',
    title: 'document.write() Usage Detected',
    description: 'document.write() was found in client-side code. This can be used for XSS attacks and causes performance issues by blocking page parsing.',
    fixPrompt: `Replace document.write() with DOM manipulation:

\`\`\`typescript
// Instead of:
document.write('<div>' + userInput + '</div>');

// Use:
const div = document.createElement('div');
div.textContent = userInput; // Auto-escapes HTML
document.body.appendChild(div);
\`\`\`

Or use React/Vue/Svelte framework methods that handle escaping automatically.

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-JS-004',
    pattern: /\.innerHTML\s*=\s*/g,
    severity: 'medium',
    title: 'innerHTML Assignment Detected',
    description: 'Direct innerHTML assignment was found. If the assigned content includes untrusted data, this creates an XSS vulnerability. React\'s JSX and other frameworks auto-escape content by default.',
    fixPrompt: `Replace innerHTML with safer DOM manipulation:

\`\`\`typescript
// Instead of:
element.innerHTML = userInput;

// Use:
element.textContent = userInput; // Auto-escapes HTML

// Or for structured content:
const fragment = document.createDocumentFragment();
// ... build DOM safely
element.appendChild(fragment);
\`\`\`

In React, use JSX which auto-escapes:
\`\`\`tsx
<div>{userInput}</div>  // Safe — auto-escaped
\`\`\`

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-JS-005',
    pattern: /window\.location\s*=\s*[^;]*[+$]/g,
    severity: 'medium',
    title: 'Potential Open Redirect via window.location',
    description: 'A dynamic window.location assignment was found. If the URL includes user input, this can be exploited for open redirect attacks (phishing, session theft).',
    fixPrompt: `Validate and sanitize URL redirects:

\`\`\`typescript
// Instead of:
window.location = userInput;

// Use a whitelist:
const ALLOWED_ORIGINS = ['https://yoursite.com', 'https://app.yoursite.com'];

function safeRedirect(url: string) {
  try {
    const parsed = new URL(url, window.location.origin);
    if (ALLOWED_ORIGINS.includes(parsed.origin)) {
      window.location.href = parsed.href;
    } else {
      console.error('Redirect blocked: untrusted origin');
    }
  } catch {
    console.error('Invalid URL');
  }
}
\`\`\`

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-JS-006',
    pattern: /\.postMessage\s*\(\s*[^,)]*\s*,\s*['"]\*['"]\s*[^)]*\)/g,
    severity: 'medium',
    title: 'postMessage With Wildcard Origin (*)',
    description: 'postMessage() calls were found passing "*" as the target origin. This allows any window to receive the message, which can leak data to malicious frames.',
    fixPrompt: `Always specify a specific origin in postMessage calls:

\`\`\`typescript
// Instead of:
window.postMessage(data, '*');
parent.postMessage(data, '*');

// Always specify a trusted origin:
window.postMessage(data, 'https://yoursite.com');
iframe.contentWindow.postMessage(data, 'https://trusted-app.com');
\`\`\`

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-JS-007',
    pattern: /\.js\.map(?:\?.*)?$/m,
    severity: 'low',
    title: 'JavaScript Source Map Available',
    description: 'A JavaScript source map (.js.map) is accessible. Source maps expose original source code, variable names, and internal structure, which aids attackers in finding vulnerabilities.',
    fixPrompt: `Disable source maps in production:

\`\`\`javascript
// next.config.js
module.exports = {
  productionBrowserSourceMaps: false,
}

// webpack.config.js
module.exports = {
  devtool: process.env.NODE_ENV === 'production' ? false : 'source-map',
}

// Vite
// vite.config.ts
export default defineConfig({
  build: {
    sourcemap: process.env.NODE_ENV !== 'production',
  }
})
\`\`\`

Also ensure your web server doesn't serve .map files:
\`\`\`
# Nginx
location ~ \\.map$ {
  deny all;
  return 404;
}
\`\`\`

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
    skipMinified: true, // Source maps are expected in dev, only flag in prod context
  },
  {
    id: 'AL-JS-008',
    pattern: /console\.(log|debug|info|warn|error)\s*\(/g,
    severity: 'info',
    title: 'Console Logging in Production Code',
    description: 'Console logging statements were found in client-side code. While not a direct security vulnerability, verbose logging can leak sensitive data (tokens, user info, API responses) to browser developer tools.',
    fixPrompt: `Remove or guard console logging in production:

\`\`\`typescript
// Option 1: Guard with environment check
if (process.env.NODE_ENV !== 'production') {
  console.log(data);
}

// Option 2: Use a logging library that strips console in production
// Install: npm install loglevel
import log from 'loglevel';
log.setLevel(process.env.NODE_ENV === 'production' ? 'error' : 'debug');

// Option 3: Use build-time stripping (terser, babel-plugin-transform-remove-console)
// In next.config.js:
module.exports = {
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },
}
\`\`\`

This addresses APP 11.1 (Security) — preventing information leakage.`,
    appMappings: [app11Mapping],
    skipMinified: true, // Minified code often has leftover console.log
  },
];