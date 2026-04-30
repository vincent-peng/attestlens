import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { GuardVibeAdapter } from '../guardvibe.js';
import { scanRepoStackChecks } from './repo-stack-checks.js';

async function withTempProject(
  files: Record<string, string>,
  run: (projectDir: string) => Promise<void>,
): Promise<void> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-stack-checks-'));

  try {
    for (const [relativePath, content] of Object.entries(files)) {
      const fullPath = path.join(projectDir, relativePath);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, content, 'utf-8');
    }

    await run(projectDir);
  } finally {
    await fs.rm(projectDir, { recursive: true, force: true });
  }
}

describe('repo stack checks', () => {
  it('detects missing Supabase RLS when migrations exist without policies', async () => {
    await withTempProject({
      'src/supabase.ts': "import { createClient } from '@supabase/supabase-js';\nexport const client = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n",
      'supabase/migrations/001_create_profiles.sql': 'create table profiles (id uuid primary key, email text not null);',
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      expect(findings.some((finding) => finding.sourceRule === 'VS-SUPA-RLS-MISSING')).toBe(true);
    });
  });

  it('does not flag Supabase repos when RLS policies are present', async () => {
    await withTempProject({
      'src/supabase.ts': "import { createClient } from '@supabase/supabase-js';\n",
      'supabase/migrations/001_profiles.sql': `
        create table profiles (id uuid primary key);
        alter table profiles enable row level security;
        create policy "Users can read own profile" on profiles for select using (auth.uid() = id);
      `,
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      expect(findings.some((finding) => finding.sourceRule === 'VS-SUPA-RLS-MISSING')).toBe(false);
    });
  });

  it('detects committed Firebase service account credentials', async () => {
    await withTempProject({
      'config/firebase-admin.json': JSON.stringify({
        type: 'service_account',
        private_key_id: 'abc123',
        private_key: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n',
        client_email: 'firebase-adminsdk@example.iam.gserviceaccount.com',
      }, null, 2),
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      expect(findings.some((finding) => finding.sourceRule === 'VS-FB-SERVICE-ACCOUNT')).toBe(true);
    });
  });

  it('ignores Firebase service account material inside example content', async () => {
    await withTempProject({
      'examples/demo/firebase-admin.json': JSON.stringify({
        type: 'service_account',
        private_key_id: 'abc123',
        private_key: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n',
        client_email: 'firebase-adminsdk@example.iam.gserviceaccount.com',
      }, null, 2),
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      expect(findings.some((finding) => finding.sourceRule === 'VS-FB-SERVICE-ACCOUNT')).toBe(false);
    });
  });

  it('skips low-signal tests, fixtures, and hidden worktree paths', async () => {
    await withTempProject({
      'src/routes.ts': 'router.post("/account/delete", (req, res) => deleteAccount());',
      'src/routes.test.ts': 'router.post("/account/delete", (req, res) => deleteAccount());',
      '__tests__/secrets.test.ts': 'export const STRIPE_WEBHOOK_SECRET = "whsec_live_secret_value";',
      '.strands/worktrees/abc123/src/routes.ts': 'router.post("/account/delete", (req, res) => deleteAccount());',
      'fixtures/firebase-admin.json': JSON.stringify({
        type: 'service_account',
        private_key_id: 'abc123',
        private_key: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n',
        client_email: 'firebase-adminsdk@example.iam.gserviceaccount.com',
      }, null, 2),
      '__fixtures__/firebase-admin.json': JSON.stringify({
        type: 'service_account',
        private_key_id: 'abc123',
        private_key: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n',
        client_email: 'firebase-adminsdk@example.iam.gserviceaccount.com',
      }, null, 2),
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      const findingFiles = findings.map((finding) => finding.file || '');

      expect(findings.some((finding) => finding.sourceRule === 'VS-SAST-017' && finding.file === 'src/routes.ts')).toBe(true);
      expect(findingFiles.some((file) => file.includes('routes.test.ts'))).toBe(false);
      expect(findingFiles.some((file) => file.includes('__tests__'))).toBe(false);
      expect(findingFiles.some((file) => file.includes('.strands'))).toBe(false);
      expect(findingFiles.some((file) => file.includes('fixtures'))).toBe(false);
      expect(findingFiles.some((file) => file.includes('__fixtures__'))).toBe(false);
    });
  });

  it('scans real hidden config paths while skipping generated hidden paths', async () => {
    const serviceAccount = JSON.stringify({
      type: 'service_account',
      private_key_id: 'abc123',
      private_key: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n',
      client_email: 'firebase-adminsdk@example.iam.gserviceaccount.com',
    }, null, 2);

    await withTempProject({
      '.firebase/service-account.json': serviceAccount,
      '.config/.env': 'APIKEY=abcdefghijklmnop\n',
      '.strands/worktrees/abc123/.config/.env': 'APIKEY=abcdefghijklmnop\n',
    }, async (projectDir) => {
      const stackFindings = await scanRepoStackChecks(projectDir, '0.1.0');
      expect(stackFindings.some((finding) => finding.sourceRule === 'VS-FB-SERVICE-ACCOUNT' && finding.file === '.firebase/service-account.json')).toBe(true);

      const fallbackResult = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(projectDir);
      const hardKeyFiles = fallbackResult.findings
        .filter((finding) => finding.sourceRule === 'VS-HARDKEY')
        .map((finding) => finding.file);

      expect(hardKeyFiles).toContain('.config/.env');
      expect(hardKeyFiles.some((file) => file?.includes('.strands'))).toBe(false);
    });
  });

  it('detects public secret env prefixes and ignores safe public keys', async () => {
    await withTempProject({
      '.env': [
        'NEXT_PUBLIC_STRIPE_SECRET_KEY="sk_live_secret"',
        'NEXT_PUBLIC_SUPABASE_ANON_KEY="public-anon-value"',
        'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY="pk_live_publishable"',
      ].join('\n'),
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      const publicSecretFindings = findings.filter((finding) => finding.sourceRule === 'VS-PUBLIC-SECRET-ENV');

      expect(publicSecretFindings).toHaveLength(1);
      expect(publicSecretFindings[0]?.title).toContain('NEXT_PUBLIC_STRIPE_SECRET_KEY');
    });
  });

  it('detects hardcoded platform secrets and ignores env indirection', async () => {
    await withTempProject({
      'src/config.ts': [
        'export const STRIPE_WEBHOOK_SECRET = "whsec_live_secret_value";',
        'export const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;',
      ].join('\n'),
    }, async (projectDir) => {
      const findings = await scanRepoStackChecks(projectDir, '0.1.0');
      const platformFindings = findings.filter((finding) => finding.sourceRule === 'VS-PLATFORM-SECRET');

      expect(platformFindings).toHaveLength(1);
      expect(platformFindings[0]?.title).toContain('Stripe Webhook Secret');
    });
  });

  it('prefers stack-specific findings over generic duplicates in GuardVibe fallback', async () => {
    await withTempProject({
      '.env': 'NEXT_PUBLIC_STRIPE_SECRET_KEY="sk_live_secret_value"',
    }, async (projectDir) => {
      const result = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(projectDir);
      const relevant = result.findings.filter((finding) => finding.file === '.env');

      expect(relevant.some((finding) => finding.sourceRule === 'VS-PUBLIC-SECRET-ENV')).toBe(true);
      expect(relevant.some((finding) => finding.sourceRule === 'VS-HARDKEY')).toBe(false);
      expect(relevant.some((finding) => finding.sourceRule === 'VS-ENV')).toBe(false);
    });
  });

  it('includes SAST-lite findings in GuardVibe fallback output', async () => {
    await withTempProject({
      'src/routes.ts': 'router.post("/api/user", async (req, res) => db.query("select * from users where id=" + req.params.id));',
    }, async (projectDir) => {
      const result = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(projectDir);

      expect(result.findings.some((finding) => finding.sourceRule === 'VS-SAST-004')).toBe(true);
    });
  });

  it('keeps static fallback focused on production source paths', async () => {
    await withTempProject({
      'src/App.tsx': 'return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      'src/App.test.tsx': 'document.body.innerHTML = "";',
      '.strands/worktrees/abc123/src/App.tsx': 'return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      'examples/Example.tsx': 'return <div dangerouslySetInnerHTML={{ __html: html }} />;',
    }, async (projectDir) => {
      const result = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(projectDir);
      const xssFiles = result.findings
        .filter((finding) => finding.sourceRule === 'VS-XSS')
        .map((finding) => finding.file);

      expect(xssFiles).toEqual(['src/App.tsx']);
    });
  });

  it('does not flag safe ORM tagged templates as SQL injection', async () => {
    await withTempProject({
      'src/db.ts': [
        'const safe = sql`${table.status} <> "dismissed"`;',
        'db.query("select * from users where id=" + req.params.id);',
      ].join('\n'),
    }, async (projectDir) => {
      const result = await new GuardVibeAdapter('__attestlens_missing_guardvibe__').scan(projectDir);
      const sqlFindings = result.findings.filter((finding) => finding.sourceRule === 'VS-SQLI');

      expect(sqlFindings).toHaveLength(1);
      expect(sqlFindings[0]?.code).toContain('req.params.id');
    });
  });
});
