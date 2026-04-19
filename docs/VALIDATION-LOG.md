# Validation Log

Track each validation corpus run here after reviewing the generated artifacts.

| Date | Commit | Target | Expected Surface | Findings | False Positives | Misses | Remediation Quality (1-5) | Keep / Drop Notes |
|---|---|---|---|---:|---|---|---:|---|
| 2026-04-19 | pre-v0.2.0 working tree | Example | Baseline static marketing site for header and report sanity checks | 11 | 0 | 0 | 4 | Keep as header/caching baseline sanity check. |
| 2026-04-19 | pre-v0.2.0 working tree | Supabase | Supabase marketing site with vendor fingerprinting and client bundle checks | 0 | — | intermittent live-site fetch failure | 1 | Retry target later; final clean run hit a transient fetch failure after earlier successful passes. |
| 2026-04-19 | pre-v0.2.0 working tree | Firebase | Firebase marketing/docs surface with public bundle and header checks | 8 | 1 | 0 | 3 | Keep, but collapse duplicate Firebase/Google API-key semantics in a future cleanup pass. |
| 2026-04-19 | pre-v0.2.0 working tree | Vercel | Vercel marketing site for framework platform fingerprinting | 9 | 1 | 0 | 3 | Keep, but `AL-INFRA-006` still looks noisy on non-WordPress properties. |
| 2026-04-19 | pre-v0.2.0 working tree | Netlify | Netlify marketing site for platform fingerprinting and public asset checks | 11 | 0 | 0 | 3 | Keep; remaining findings are mostly header/source-map hygiene rather than obvious false positives. |
| 2026-04-19 | pre-v0.2.0 working tree | Clerk | Clerk auth vendor site to inspect auth-related public bundle signals | 0 | — | intermittent live-site fetch failure | 1 | Retry target later; earlier runs also showed `AL-KEY-011` noise that still needs tuning. |
| 2026-04-19 | pre-v0.2.0 working tree | Auth0 | Auth0 identity platform site for auth vendor fingerprinting | 9 | 1 | 0 | 3 | Keep, but framework-level DOM heuristics still need sharper filtering on marketing bundles. |
| 2026-04-19 | pre-v0.2.0 working tree | Stripe | Stripe marketing surface for payment vendor fingerprinting and key-rule sanity checks | 9 | 1 | 0 | 3 | Keep, but public API docs should not be treated as a medium-risk infra finding by default. |
| 2026-04-19 | pre-v0.2.0 working tree | OWASP Juice Shop | Intentionally vulnerable app for high-signal URL scanner findings and sample reports | 11 | 0 | 3 | 3 | Keep as sample-report target; note that passive URL scanning misses deeper exploit-class issues that a pentest tool would catch. |
