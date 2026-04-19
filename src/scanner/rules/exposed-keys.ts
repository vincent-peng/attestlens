/**
 * AttestLens — Exposed Key Detection Patterns
 * 
 * Regex patterns for detecting exposed API keys, tokens, and secrets
 * in JavaScript bundles and HTML source.
 * 
 * Maps primarily to APP_11.1 (Security) and APP_6.1 (Use/Disclosure).
 */

import type { Severity } from '../../schema/index.js';
import type { APPMapping } from '../../schema/index.js';

export interface KeyPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
  fixPrompt: string;
  appMappings: APPMapping[];
  /** Exclude patterns that look like test/placeholder keys */
  excludePattern?: RegExp;
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

export const KEY_PATTERNS: KeyPattern[] = [
  {
    id: 'AL-KEY-001',
    name: 'OpenAI API Key',
    pattern: /sk-proj-[A-Za-z0-9_-]{80,}|sk-[A-Za-z0-9]{48}/g,
    excludePattern: /sk-test-|sk-example|YOUR_API_KEY|<your-api-key>/i,
    severity: 'critical',
    title: 'Exposed OpenAI API Key',
    description: 'An OpenAI API key was found in client-side code. Attackers can use this to make API calls, incur charges, and access any data the key has permissions for.',
    fixPrompt: `Move the OpenAI API key to a server-side environment variable immediately.

1. **Revoke the exposed key** at https://platform.openai.com/api-keys
2. **Move the key** to a server-side environment variable:
   \`\`\`bash
   # .env.local (server-side only, never committed)
   OPENAI_API_KEY=sk-proj-...
   \`\`\`
3. **Create a server-side API route** to proxy OpenAI calls:
   \`\`\`typescript
   // app/api/chat/route.ts (Next.js)
   import OpenAI from 'openai';
   
   const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
   
   export async function POST(req: Request) {
     const { message } = await req.json();
     const response = await openai.chat.completions.create({
       model: 'gpt-4',
       messages: [{ role: 'user', content: message }],
     });
     return Response.json(response);
   }
   \`\`\`
4. **Remove the key** from all client-side code and never commit it again.

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-002',
    name: 'Stripe Live Key',
    pattern: /sk_live_[A-Za-z0-9]{24,99}|pk_live_[A-Za-z0-9]{24}/g,
    excludePattern: /sk_test_|pk_test_|YOUR_STRIPE_KEY/i,
    severity: 'critical',
    title: 'Exposed Stripe Live Key',
    description: 'A Stripe live key was found in client-side code. This gives full access to your Stripe account, including the ability to issue refunds, create charges, and access customer data.',
    fixPrompt: `This is a CRITICAL security issue. Take these steps immediately:

1. **Revoke the key** at https://dashboard.stripe.com/apikeys
2. **Rotate** all related webhook endpoints
3. **Move the key** to a server-side environment variable
4. **Use Stripe server-side** for all payment operations:
   \`\`\`typescript
   import Stripe from 'stripe';
   const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
   \`\`\`
5. **Only use publishable keys** (pk_live_*) on the client side — these are designed to be public

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-003',
    name: 'Supabase Service Role Key',
    pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    excludePattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJzdXBhYmFzZS[^\n]*anon/i,
    severity: 'critical',
    title: 'Exposed Supabase Service Role Key',
    description: 'A Supabase JWT was found in client-side code. If this is a service_role key, it has full admin access to your database, bypassing all Row Level Security policies.',
    fixPrompt: `Check if this is a service_role key or anon key:

1. **If service_role (CRITICAL)**: This key bypasses ALL Row Level Security. Revoke it immediately at https://supabase.com/dashboard → Settings → API
2. **If anon key**: This is designed to be public, but verify RLS is enabled on all tables

For service_role keys:
\`\`\`typescript
// Move to server-side only
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
  auth: { persistSession: false }
});
\`\`\`

For anon keys (public is OK, but verify RLS):
\`\`\`sql
-- Verify RLS is enabled on all tables
SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';
\`\`\`

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-004',
    name: 'Firebase Admin SDK Key',
    pattern: /AIza[A-Za-z0-9_-]{35}/g,
    excludePattern: /YOUR_FIREBASE_KEY|firebase-demo/i,
    severity: 'high',
    title: 'Exposed Firebase API Key',
    description: 'A Firebase API key was found in client-side code. Firebase API keys are often designed to be public, but combined with misconfigured security rules they can expose your entire database.',
    fixPrompt: `Firebase API keys are often designed to be public, but you MUST verify security rules:

1. **Check Firebase Security Rules**:
   \`\`\`
   // Firebase Console → Firestore → Rules
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       match /{document=**} {
         allow read, write: if request.auth != null;
       }
     }
   }
   \`\`\`

2. **NEVER use these in client-side code**:
   - Firebase Admin SDK private key (JSON file)
   - Firebase Service Account credentials
   - Database secrets

3. **Restrict API key usage** in Google Cloud Console → API Keys → Application restrictions

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-KEY-005',
    name: 'Anthropic API Key',
    pattern: /sk-ant-api03-[A-Za-z0-9_-]{95}/g,
    excludePattern: /YOUR_ANTHROPIC_KEY|sk-ant-api03-test/i,
    severity: 'critical',
    title: 'Exposed Anthropic Claude API Key',
    description: 'An Anthropic Claude API key was found in client-side code. Attackers can use this to make API calls, incur significant charges, and access any data the key has permissions for.',
    fixPrompt: `Revoke and move the Anthropic API key to server-side environment variables:

1. **Revoke** at https://console.anthropic.com/settings/keys
2. **Move to .env.local** (server-side only):
   \`\`\`bash
   ANTHROPIC_API_KEY=sk-ant-api03-...
   \`\`\`
3. **Proxy through a server-side API route**:
   \`\`\`typescript
   // app/api/chat/route.ts
   const response = await fetch('https://api.anthropic.com/v1/messages', {
     headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY! },
     // ...
   });
   \`\`\`

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-006',
    name: 'AWS Access Key',
    pattern: /AKIA[A-Z0-9]{16}/g,
    excludePattern: /YOUR_AWS_KEY|AKIAIOSFODNN7EXAMPLE/i,
    severity: 'critical',
    title: 'Exposed AWS Access Key ID',
    description: 'An AWS Access Key ID was found in client-side code. This can be combined with a secret key to gain full access to your AWS resources.',
    fixPrompt: `This is a CRITICAL security issue:

1. **Disable the key** immediately at https://console.aws.amazon.com/iam → Access Keys
2. **Check CloudTrail** for any unauthorized usage since the key was exposed
3. **Generate a new key** and store it server-side only:
   \`\`\`bash
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   \`\`\`
4. **Use AWS SDK on server-side only**:
   \`\`\`typescript
   import { S3Client } from '@aws-sdk/client-s3';
   const s3 = new S3Client({ region: process.env.AWS_REGION });
   \`\`\`
5. **For client-side AWS usage**, use Cognito Identity Pools with limited IAM roles

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-007',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/g,
    excludePattern: /YOUR_GITHUB_TOKEN|ghp_example/i,
    severity: 'critical',
    title: 'Exposed GitHub Personal Access Token',
    description: 'A GitHub Personal Access Token was found in client-side code. This can be used to access private repositories, push malicious code, or modify GitHub Actions workflows.',
    fixPrompt: `Revoke and rotate the GitHub token immediately:

1. **Revoke** at https://github.com/settings/tokens
2. **Check access logs** at https://github.com/settings/security-log
3. **Move to server-side environment variable**:
   \`\`\`bash
   GITHUB_TOKEN=ghp_...
   \`\`\`
4. **Use GitHub API server-side only**:
   \`\`\`typescript
   import { Octokit } from '@octokit/rest';
   const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
   \`\`\`

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-008',
    name: 'SendGrid API Key',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    excludePattern: /YOUR_SENDGRID_KEY|SG\.example/i,
    severity: 'critical',
    title: 'Exposed SendGrid API Key',
    description: 'A SendGrid API key was found in client-side code. This can be used to send emails on behalf of your organization, access contact lists, and modify email templates.',
    fixPrompt: `Revoke and move the SendGrid API key to server-side:

1. **Revoke** at https://app.sendgrid.com/settings/api_keys
2. **Move to .env.local** (server-side only):
   \`\`\`bash
   SENDGRID_API_KEY=SG.xxx.yyy
   \`\`\`
3. **Send emails server-side only**:
   \`\`\`typescript
   import sgMail from '@sendgrid/mail';
   sgMail.setApiKey(process.env.SENDGRID_API_KEY!);
   \`\`\`

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-KEY-009',
    name: 'Twilio Account SID',
    pattern: /AC[a-z0-9]{32}/g,
    excludePattern: /YOUR_TWILIO_SID|AC00000000000000000000000000000000/i,
    severity: 'high',
    title: 'Exposed Twilio Account SID',
    description: 'A Twilio Account SID was found in client-side code. Combined with an auth token, this gives full access to your Twilio account including SMS, voice, and billing.',
    fixPrompt: `Twilio Account SIDs are semi-public (used in API URLs), but should not be hardcoded:

1. **Rotate your Auth Token** if it was also exposed at https://www.twilio.com/console/account/settings
2. **Move to server-side environment variable**:
   \`\`\`bash
   TWILIO_ACCOUNT_SID=AC...
   TWILIO_AUTH_TOKEN=...
   \`\`\`
3. **Use Twilio server-side only**:
   \`\`\`typescript
   import twilio from 'twilio';
   const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
   \`\`\`

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-KEY-010',
    name: 'Google API Key',
    pattern: /AIza[A-Za-z0-9_-]{35}/g,
    excludePattern: /YOUR_GOOGLE_KEY|AIzaSyDummyKeyForTesting/i,
    severity: 'high',
    title: 'Exposed Google API Key',
    description: 'A Google API key was found in client-side code. Without proper restrictions, this key can be used to access Google services on your behalf.',
    fixPrompt: `Google API keys can be public but MUST be restricted:

1. **Restrict the key** at https://console.cloud.google.com/apis/credentials:
   - Set Application Restrictions (HTTP referrers for web)
   - Set API Restrictions (only the APIs you use)
2. **Never use Service Account keys** in client-side code
3. **If this is a Service Account JSON key**, it's CRITICAL — rotate immediately

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-KEY-011',
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    excludePattern: /YOUR_PRIVATE_KEY|example\.com/i,
    severity: 'critical',
    title: 'Exposed Private Key',
    description: 'A private key was found in client-side code. This can be used to impersonate your server, decrypt traffic, or sign malicious requests.',
    fixPrompt: `This is a CRITICAL security issue:

1. **Revoke the key** immediately — generate a new one and deploy it
2. **Check logs** for any unauthorized usage since exposure
3. **Move all private keys to server-side** environment variables or secret managers:
   \`\`\`bash
   # Use environment variables, not files
   PRIVATE_KEY=$(cat private.key)
   # Or better: use a secret manager (AWS Secrets Manager, HashiCorp Vault)
   \`\`\`
4. **Add to .gitignore**:
   \`\`\`
   *.pem
   *.key
   *.p12
   \`\`\`

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-012',
    name: 'Database Connection String',
    pattern: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)(?::\/\/|\+srv:\/\/)[^\s'"`<>]+/gi,
    excludePattern: /localhost|127\.0\.0\.1|example\.com|YOUR_DB/i,
    severity: 'critical',
    title: 'Exposed Database Connection String',
    description: 'A database connection string was found in client-side code. This contains credentials that can be used to directly access your database.',
    fixPrompt: `This is a CRITICAL security issue:

1. **Rotate the database password** immediately
2. **Move to server-side environment variable**:
   \`\`\`bash
   DATABASE_URL=postgresql://user:pass@host:5432/db
   \`\`\`
3. **Use server-side ORM/DB client only**:
   \`\`\`typescript
   import { PrismaClient } from '@prisma/client';
   const prisma = new PrismaClient(); // reads DATABASE_URL from env
   \`\`\`
4. **Add IP restrictions** to the database server (only allow your app server)
5. **Check access logs** for unauthorized connections

This addresses APP 11.1 (Security) and APP 6.1 (Use/Disclosure).`,
    appMappings: [app11Mapping, app61Mapping],
  },
  {
    id: 'AL-KEY-013',
    name: 'Generic API Key/Secret',
    pattern: /['"](?:api[_-]?key|secret[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token)['"]\s*[:=]\s*['"][^'"]{8,}/gi,
    excludePattern: /process\.env|import\.meta\.env|YOUR_|example|placeholder|undefined|null/i,
    severity: 'medium',
    title: 'Potentially Exposed API Key or Secret',
    description: 'A variable that looks like an API key or secret was found in client-side code. While it may be a false positive, any hardcoded credentials in client code should be reviewed.',
    fixPrompt: `Review this finding carefully — it may be a false positive:

1. **Check if the value is an environment variable** — if it references \`process.env\` or \`import.meta.env\`, it's likely OK
2. **If it's a hardcoded value**, move it to a server-side environment variable:
   \`\`\`bash
   API_KEY=your-secret-value  # .env.local (server-side)
   \`\`\`
3. **Audit all hardcoded credentials** — even internal API keys should not be in client code

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-KEY-014',
    name: 'JWT Secret',
    pattern: /['"](?:jwt[_-]?secret|token[_-]?secret|session[_-]?secret|signing[_-]?key)['"]\s*[:=]\s*['"][^'"]{8,}/gi,
    excludePattern: /process\.env|import\.meta\.env|YOUR_|example|undefined|null/i,
    severity: 'high',
    title: 'Exposed JWT/Session Secret',
    description: 'A JWT or session secret was found in client-side code. This can be used to forge authentication tokens and impersonate any user.',
    fixPrompt: `This is a HIGH severity issue:

1. **Rotate the secret** immediately — generate a new one:
   \`\`\`bash
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   \`\`\`
2. **Move to server-side environment variable**:
   \`\`\`bash
   JWT_SECRET=your-new-secret-here
   \`\`\`
3. **Invalidate all existing sessions/tokens** — force all users to re-authenticate

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
  {
    id: 'AL-KEY-015',
    name: 'Cloudflare API Token',
    pattern: /(?:cloudflare[_-]?token|cf[_-]?api[_-]?token|cf[_-]?zone[_-]?id)\s*[:=]\s*['"][A-Za-z0-9_-]{20,}/gi,
    excludePattern: /process\.env|import\.meta\.env|YOUR_|undefined|null/i,
    severity: 'high',
    title: 'Exposed Cloudflare API Token',
    description: 'A Cloudflare API token was found in client-side code. This can be used to modify DNS records, SSL settings, or cache settings for your domain.',
    fixPrompt: `Revoke and rotate the Cloudflare API token:

1. **Revoke** at https://dash.cloudflare.com/profile/api-tokens
2. **Move to server-side environment variable**:
   \`\`\`bash
   CLOUDFLARE_API_TOKEN=...
   \`\`\`
3. **Use server-side only** — Cloudflare API should never be called from client code

This addresses APP 11.1 (Security).`,
    appMappings: [app11Mapping],
  },
];