# Supply Chain Detection — AttestLens Design

## The Axios Attack (March 31, 2026)

### What Happened

On March 31, 2026, a North Korean state actor (Sapphire Sleet) compromised the npm account of the lead Axios maintainer (`jasonsaayman`). They published two malicious versions:

- **axios@1.14.1** (1.x branch)
- **axios@0.30.4** (0.x branch)

Axios has **100M+ weekly downloads**. The attacker targeted both major version branches to maximize blast radius.

### Attack Technique

The attacker **did not modify any Axios source code**. Instead:

1. **Pre-staged a decoy package**: Published `plain-crypto-js@4.2.0` (a clean copy of crypto-js) to establish publishing history and avoid new-package alerts
2. **Injected the payload 18 hours later**: Published `plain-crypto-js@4.2.1` with an obfuscated RAT dropper in the postinstall hook
3. **Modified only the manifest**: Added `plain-crypto-js@^4.2.1` as a dependency to axios — no Axios code was changed
4. **Auto-execution**: `npm install` automatically runs the postinstall script, downloading a platform-specific RAT from `sfrclak[.]com:8000`
5. **Self-destruct**: The dropper deletes itself after execution, leaving no trace in `node_modules`

### How They Got In

- Compromised the maintainer's npm credentials
- Changed the account email to `ifstap@proton.me` (attacker-controlled)
- Published manually via npm CLI, bypassing the project's GitHub Actions OIDC trusted publisher pipeline
- The project still had a long-lived npm access token that wasn't revoked after transitioning to OIDC
- The attacker also had GitHub access — they were deleting issues reporting the compromise

### Impact

- **Cross-platform RAT**: macOS, Windows, Linux all get platform-specific payloads
- **macOS**: AppleScript drops `/Library/Caches/com.apple.act.mond` (native binary)
- **Windows**: VBScript stager → PowerShell RAT with registry persistence
- **Auto-update hook**: The payload includes a hook to keep trying to update
- **Any project** using `axios@^1.14.0` or `axios@^0.30.0` that ran `npm install` during the ~3-hour exposure window was compromised

### Detection Gap

Socket.dev flagged the malicious dependency **6 minutes** after publication. But:
- Most projects don't use Socket or similar real-time supply chain monitors
- `npm audit` only catches known vulnerabilities — it doesn't detect novel supply chain attacks
- The attack was designed to evade automated scanners (pre-staged decoy, manifest-only change, self-destructing dropper)

---

## How AttestLens Should Detect Supply Chain Attacks

### Current AttestLens Capability

AttestLens currently scans for **code-level** security patterns (hardcoded secrets, XSS, SQLi, CORS). It does **not** scan for supply chain risks.

### What We Need to Add

Supply chain detection is a **critical gap** in APP 11 (Security) compliance. Under APP 11.1, entities must take "reasonable steps" to protect personal information — and that includes protecting your dependency chain.

#### Detection Categories

| Category | What to Detect | APP Principle | Severity |
|----------|----------------|---------------|----------|
| **Dependency integrity** | Modified manifests, unexpected dependencies, version anomalies | APP_11 | Critical |
| **Known vulnerabilities** | Packages with known CVEs | APP_11 | High |
| **Install-time scripts** | `postinstall`/`preinstall` hooks, `setup.js` patterns | APP_11 | Critical |
| **Suspicious packages** | New packages, typosquatting, empty packages with deps | APP_11 | Critical |
| **License compliance** | Copyleft licenses in commercial products | APP_6 | Medium |
| **Outdated dependencies** | Packages >2 major versions behind | APP_11 | Medium |

#### Proposed Scanner: `supply-chain`

```typescript
// src/scanner/supply-chain.ts

export class SupplyChainAdapter implements ScannerAdapter {
  readonly name = 'supply-chain';
  
  async scan(targetPath: string): Promise<ScannerResult> {
    const findings: AttestLensFinding[] = [];
    
    // 1. Parse package.json + package-lock.json
    // 2. Check for install scripts (postinstall, preinstall, etc.)
    // 3. Verify each dependency against npm registry (integrity hash)
    // 4. Flag new/unknown packages (<30 days old)
    // 5. Detect typosquatting against popular package names
    // 6. Check for manifest-only changes (deps added but no code changed)
    // 7. Run `npm audit` for known CVEs
    // 8. Check lockfile integrity (shasum mismatch)
    
    return { findings, ... };
  }
}
```

#### Detection Rules

| Rule ID | Pattern | Severity | Maps To |
|---------|---------|----------|---------|
| `VS-SC-001` | postinstall/preinstall scripts in deps | Critical | APP_11 |
| `VS-SC-002` | Dependency added with no code changes (manifest-only) | Critical | APP_11 |
| `VS-SC-003` | Package with <30 days publishing history | High | APP_11 |
| `VS-SC-004` | Typosquat of top-100 npm package | Critical | APP_11 |
| `VS-SC-005` | Lockfile integrity mismatch | Critical | APP_11 |
| `VS-SC-006` | Known CVE in dependency (npm audit) | High | APP_11 |
| `VS-SC-007` | Dependency with no repository field | Medium | APP_11 |
| `VS-SC-008` | Dependency with install scripts AND no source repo | Critical | APP_11 |
| `VS-SC-009` | Outdated major version (>2 behind latest) | Medium | APP_11 |
| `VS-SC-010` | Next.js/React dependency mismatch | Low | APP_11 |

#### Axios Attack Detection Matrix

| Attack Indicator | Rule | Would AttestLens Detect It? |
|------------------|------|-----------------------------|
| `plain-crypto-js@4.2.1` added as dependency with no code import | VS-SC-002 | ✅ Yes — manifest-only change |
| `postinstall` script in `plain-crypto-js` | VS-SC-001 | ✅ Yes — install-time script |
| `plain-crypto-js` published <24 hours before adoption | VS-SC-003 | ✅ Yes — new package |
| Typosquat of `crypto-js` | VS-SC-004 | ✅ Yes — typosquat detection |
| No source repository for `plain-crypto-js` | VS-SC-007 | ✅ Yes — no repo field |
| Install scripts + no source repo | VS-SC-008 | ✅ Yes — critical combo |
| Lockfile shasum mismatch | VS-SC-005 | ✅ Yes — integrity check |

**AttestLens would have caught 5-7 of the 7 indicators** of the Axios attack, depending on when the scan was run.

### Implementation Priority

1. **Phase 1.5** (now): Static supply chain scanner — parse `package.json`/`package-lock.json`, detect install scripts, flag new packages, typosquatting
2. **Phase 2**: Integration with `npm audit` + Socket.dev API for real-time vulnerability data
3. **Phase 3**: Lockfile integrity verification, manifest diff detection, continuous monitoring

### Staying Current

The Axios attack shows that **static rules aren't enough** — supply chain threats evolve fast. AttestLens needs:

1. **Rule versioning**: Each rule has a version and last-updated date
2. **Remote rule updates**: Pull updated detection rules from a central repo (like how GuardVibe's 335 rules stay current)
3. **npm audit integration**: Always run `npm audit` as part of the scan — it's the baseline
4. **Lockfile pinning**: Encourage `npm ci` over `npm install` (uses exact lockfile hashes)
5. **Socket.dev / OSV integration**: Real-time supply chain intelligence API

### APP 11 Mapping Rationale

Supply chain attacks directly violate **APP 11.1** (taking reasonable steps to protect personal information):

> "An APP entity must take reasonable steps to protect personal information it holds from:
> (a) misuse, interference and loss; and
> (b) unauthorised access, modification or disclosure."

A compromised dependency that installs a RAT on developer machines means:
- Developer machines can exfiltrate personal information
- CI/CD pipelines can inject malicious code into production
- Build artifacts can be tampered with

**Not scanning your dependency chain = not taking reasonable steps.**

---

## References

- Microsoft Security Blog: <https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/>
- Axios Post-Mortem: <https://github.com/axios/axios/issues/10636>
- Revaizor Analysis: <https://revaizor.com/blog/axios-npm-supply-chain-attack/>
- StepSecurity: <https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan>
- Socket.dev (flagged in 6 minutes): <https://socket.dev/blog/axios-npm-package-compromised>
- Wiz: <https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack>