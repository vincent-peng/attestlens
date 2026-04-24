/**
 * AttestLens — Infrastructure Security Checks
 * 
 * Probes for common infrastructure misconfigurations on remote URLs.
 * Checks for exposed sensitive files, debug endpoints, and information disclosure.
 */

import type { Severity } from '../../schema/index.js';
import type { APPMapping } from '../../schema/index.js';

export interface InfraCheck {
  id: string;
  path: string;
  method: string;
  /** HTTP status code(s) that indicate the vulnerability is present */
  vulnerableStatuses: number[];
  /** Content patterns that confirm the vulnerability (regex) */
  contentPatterns?: RegExp[];
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
}

const app11Mapping: APPMapping = {
  principle: 'APP_11',
  obligation: 'Take reasonable steps to protect personal information from misuse, interference, and loss',
  status: 'fail',
  confidence: 0.95,
};

const app61Mapping: APPMapping = {
  principle: 'APP_6',
  obligation: 'Use or disclose personal information only for the primary purpose for which it was collected',
  status: 'fail',
  confidence: 0.90,
};

const app51Mapping: APPMapping = {
  principle: 'APP_5',
  obligation: 'Notify individuals about the collection of their personal information',
  status: 'fail',
  confidence: 0.80,
};

export const INFRA_CHECKS: InfraCheck[] = [
  {
    id: 'AL-INFRA-001',
    path: '/.git/HEAD',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/ref: refs\//],
    severity: 'critical',
    title: 'Exposed Git Repository',
    description: 'The .git/HEAD file is publicly accessible, which means the entire Git repository can be downloaded. This exposes source code, commit history, potentially hardcoded secrets, and internal project structure.',
    fixPrompt: `This is a CRITICAL issue — your entire source code may be downloadable:

1. **Immediately block access** to .git directories:
   
   Nginx:
   \`\`\`
   location ~ /\\.git {
     deny all;
     return 404;
   }
   \`\`\`
   
   Apache (.htaccess):
   \`\`\`
   RedirectMatch 404 /\\.git
   \`\`\`
   
   Express:
   \`\`\`js
   app.use((req, res, next) => {
     if (req.path.includes('.git')) return res.status(404).send();
     next();
   });
   \`\`\`

2. **Rotate ALL secrets** that were in the repository (even historical commits)
3. **Assume the code is compromised** — review for hardcoded credentials

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-INFRA-002',
    path: '/.env',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/(?:DATABASE_URL|API_KEY|SECRET|PASSWORD|TOKEN)\s*=/i],
    severity: 'critical',
    title: 'Exposed .env File',
    description: 'The .env file is publicly accessible. This file typically contains database credentials, API keys, and other secrets that should never be exposed.',
    fixPrompt: `This is a CRITICAL issue — your environment variables may be publicly accessible:

1. **Immediately block access** to .env files:
   
   Nginx:
   \`\`\`
   location ~ /\\.env {
     deny all;
     return 404;
   }
   \`\`\`
   
   Apache (.htaccess):
   \`\`\`
   <FilesMatch "^\\.env">
     Require all denied
   </FilesMatch>
   \`\`\`

2. **Rotate ALL secrets** in the .env file — assume they are compromised
3. **Add .env to .gitignore** (it should never be committed)
4. **Use a secret manager** for production secrets (AWS Secrets Manager, HashiCorp Vault)

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-INFRA-003',
    path: '/.env.local',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/(?:DATABASE_URL|API_KEY|SECRET|PASSWORD|TOKEN)\s*=/i],
    severity: 'critical',
    title: 'Exposed .env.local File',
    description: 'The .env.local file is publicly accessible. This file contains local environment overrides that may include secrets.',
    fixPrompt: `Block access to .env.local files using the same approach as .env (see AL-INFRA-002).

Additionally, verify that .env.local is in .gitignore and that your web server blocks dotfiles.

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-INFRA-004',
    path: '/.env.production',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/(?:DATABASE_URL|API_KEY|SECRET|PASSWORD|TOKEN)\s*=/i],
    severity: 'critical',
    title: 'Exposed .env.production File',
    description: 'The .env.production file is publicly accessible. This file contains production environment variables, which are the most sensitive configuration.',
    fixPrompt: `Block access to .env.production files using the same approach as .env (see AL-INFRA-002).

Production secrets should use a secret manager, not files on the web server.

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-INFRA-005',
    path: '/api/debug',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/debug|django|flask|laravel|stacktrace/i],
    severity: 'high',
    title: 'Exposed Debug Endpoint',
    description: 'A debug endpoint is publicly accessible. Debug endpoints often expose internal application state, environment variables, database queries, and stack traces.',
    fixPrompt: `Disable or protect debug endpoints in production:

1. **Remove or disable** debug routes in production builds
2. **If needed for debugging**, require authentication:
   \`\`\`typescript
   // Only allow in development
   if (process.env.NODE_ENV === 'production') {
     app.disable('/api/debug');
   }
   \`\`\`
3. **Never deploy debug tools** to production (Django Debug Toolbar, Flask Debug, etc.)

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-INFRA-006',
    path: '/wp-admin',
    method: 'GET',
    vulnerableStatuses: [200, 301, 302],
    contentPatterns: [/wp-login\.php|wp-content\/|wp-includes\/|<meta[^>]+name=["']generator["'][^>]+wordpress|<form[^>]+id=["']loginform["']|name=["']wp-submit["']/i],
    severity: 'medium',
    title: 'WordPress Admin Panel Detected',
    description: 'A WordPress admin panel is accessible. If WordPress is not intentionally used, this may indicate a compromised server. If WordPress is used, the admin panel should be restricted.',
    fixPrompt: `If you don't use WordPress, this is suspicious — investigate potential compromise.

If you use WordPress:
1. **Restrict admin access** by IP:
   \`\`\`
   # Nginx
   location /wp-admin {
     allow 10.0.0.0/8;
     deny all;
   }
   \`\`\`
2. **Use two-factor authentication** on admin accounts
3. **Keep WordPress updated** to patch known vulnerabilities
4. **Install a security plugin** (Wordfence, Sucuri)

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-INFRA-007',
    path: '/swagger.json',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/["']swagger["']|openapi/i],
    severity: 'medium',
    title: 'Exposed Swagger/OpenAPI Documentation',
    description: 'Swagger/OpenAPI documentation is publicly accessible. This exposes your API structure, endpoints, parameters, and potentially authentication details.',
    fixPrompt: `Protect or disable Swagger/OpenAPI documentation in production:

1. **Disable in production**:
   \`\`\`typescript
   if (process.env.NODE_ENV === 'production') {
     app.disable('/swagger', '/api-docs');
   }
   \`\`\`
2. **Or require authentication** for documentation access
3. **Sanitize** any internal API details from the spec before exposing

This addresses APP 5.1 (Notification) and APP 11.1 (Security).`,
    appMappings: [app11Mapping, app51Mapping],
  },
  {
    id: 'AL-INFRA-008',
    path: '/api/docs',
    method: 'GET',
    vulnerableStatuses: [200],
    contentPatterns: [/swagger|openapi|redoc|api.?doc/i],
    severity: 'medium',
    title: 'Exposed API Documentation',
    description: 'API documentation is publicly accessible. This may expose internal API endpoints, parameters, and data structures that should not be public.',
    fixPrompt: `Protect API documentation in production — see AL-INFRA-007 for detailed instructions.

This addresses APP 5.1 (Notification) and APP 11.1 (Security).`,
    appMappings: [app11Mapping, app51Mapping],
  },
];
