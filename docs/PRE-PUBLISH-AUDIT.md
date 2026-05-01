# Pre-Publish Audit

Date: 2026-05-01
Package: `@attestlens/cli`
Target release: `0.4.0-beta`
Target dist-tag: `beta`

## Executive Summary

Status: NOT READY

This package should not be published yet. The current publish artifact is stale and materially inconsistent with `src/`: `npm pack --dry-run --json` currently prepares `@attestlens/cli@0.4.0`, ships 341 files, includes many compiled test artifacts, and omits newer runtime features that exist in source. There are also release-metadata gaps in `package.json`, `README.md`, and `server.json` that would make the first public release confusing or incorrect.

The two biggest categories of blockers are:

- Packaging/build integrity: the tarball is too large, contains test files, and the built runtime is behind source.
- Release metadata correctness: versioning, scoped publish settings, Node engine requirements, and MCP registry metadata are not ready for a first public beta.

## Critical Fixes

### 1. `package.json` is not publish-ready

- `version` is still `0.4.0`, not `0.4.0-beta`.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:3)
- `publishConfig.access` is missing. For a scoped first publish, npm defaults to private visibility unless `--access public` is supplied.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:1)
- `engines.node` is missing even though the dependency floor is effectively Node 20.12+ because `@inquirer/prompts@8.4.1` declares `>=23.5.0 || ^22.13.0 || ^21.7.0 || ^20.12.0`, and core dependencies like `commander` and `@modelcontextprotocol/sdk` require Node 18+.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:1), [node_modules/@inquirer/prompts/package.json](/Users/vincent/Developer/Github/personal/attestlens/node_modules/@inquirer/prompts/package.json:71), [node_modules/@modelcontextprotocol/sdk/package.json](/Users/vincent/Developer/Github/personal/attestlens/node_modules/@modelcontextprotocol/sdk/package.json:12), [node_modules/commander/package.json](/Users/vincent/Developer/Github/personal/attestlens/node_modules/commander/package.json:61)
- The `bin` map includes a generic `cli` executable name. That is a poor public binary name for a first npm release and should be removed unless there is a deliberate compatibility reason.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:7)
- `main` points to `dist/cli/index.js`, which is a command entrypoint with process side effects. If this package is intended to be CLI-only, either remove `main`/add a safe `exports` map or expose a non-executing library surface.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:6), [dist/cli/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/cli/index.js:1)

### 2. The built artifact is stale relative to `src/`

- `src` contains commands and modules that are missing from `dist`, including `install`, `uninstall`, `mcp`, `propose-rules`, `review-pack`, SARIF support, the jurisdiction registry, and SG PDPA support.
  Evidence: [src/cli/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/cli/index.ts:340), [src/schema/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/schema/index.ts:19), [src/mcp/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/mcp/index.ts:36)
- The shipped CLI help is older than source. Runtime help from `node dist/cli/index.js --help` shows no `install`, `uninstall`, `mcp`, `propose-rules`, or `review-pack` commands even though source defines them.
  Evidence: [src/cli/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/cli/index.ts:340)
- The shipped schema only supports 3 jurisdictions (`au-privacy-act`, `us-ccpa`, `eu-gdpr`) while source now includes a 4th (`sg-pdpa`).
  Evidence: [src/schema/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/schema/index.ts:19), [dist/schema/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/schema/index.js:12)

### 3. `npm pack --dry-run` shows the tarball is shipping test artifacts

- The tarball contains `dist/**/*.test.js`, `dist/**/*.test.d.ts`, and related maps.
- The tarball has 341 entries, far above the intended minimal release surface.
- This directly violates the goal of publishing only runtime assets plus top-level metadata.
  Evidence: `npm pack --dry-run --json` output on 2026-05-01 showed `entryCount: 341`, including files like `dist/cli/index.test.js`, `dist/mapping/engine.test.js`, `dist/mcp/index.test.js`, `dist/report/generator.test.js`, and many more.
- Root cause: `tsconfig.json` includes all `src/**/*`, so test files compile into `dist/`.
  Evidence: [tsconfig.json](/Users/vincent/Developer/Github/personal/attestlens/tsconfig.json:14)

### 4. Version consistency is broken

- Runtime CLI version is `0.4.0`, not `0.4.0-beta`.
  Evidence: `node dist/cli/index.js --version` returned `0.4.0`.
- `server.json` still says `0.4.0`.
  Evidence: [server.json](/Users/vincent/Developer/Github/personal/attestlens/server.json:3)
- MCP server code still hardcodes `0.2.0` in source and in built output.
  Evidence: [src/mcp/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/mcp/index.ts:52), [dist/mcp/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/mcp/index.js:22)
- Built report generator still hardcodes `0.2.0`, although source has already been fixed to read from package metadata dynamically.
  Evidence: [src/report/generator.ts](/Users/vincent/Developer/Github/personal/attestlens/src/report/generator.ts:46), [dist/report/generator.js](/Users/vincent/Developer/Github/personal/attestlens/dist/report/generator.js:15)

### 5. README is not aligned with the current product surface

- README still describes only AU, US CCPA/CPRA, and EU GDPR. It does not mention SG PDPA even though source and status docs now include it.
  Evidence: [README.md](/Users/vincent/Developer/Github/personal/attestlens/README.md:7), [src/schema/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/schema/index.ts:19), [docs/STATUS.md](/Users/vincent/Developer/Github/personal/attestlens/docs/STATUS.md:13)
- README does not give explicit install guidance for a beta release. For this release, users should be told to install `@beta` or an exact beta version, otherwise `npm install @attestlens/cli` will not resolve to the beta until `latest` is moved.
- The description/positioning is inconsistent across surfaces:
  - `package.json`: "Clearway — Privacy Compliance Deploy Gate for AI Agents"
  - README: "Deterministic compliance runtime for AI agents"
  - CLI help: "AI Compliance Scanner & Privacy Act Attestation Tool"
  This needs tightening before public launch.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:5), [README.md](/Users/vincent/Developer/Github/personal/attestlens/README.md:7), [src/cli/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/cli/index.ts:81)

### 6. `server.json` is not MCP registry-ready

- It uses an older flat shape and does not match the current MCP Registry package-based examples, which use `$schema`, a `repository` object, and `packages` entries with `registryType`, `identifier`, `version`, and `transport`.
- It does not describe execution/install instructions in registry-native form.
- It does not explicitly bind the package to the MCP binary beyond the package name; the current file does not tell the registry how to invoke `attestlens-mcp`.
- It does not include `$schema`.
- Its version is not aligned to the intended beta.
  Evidence: [server.json](/Users/vincent/Developer/Github/personal/attestlens/server.json:1), [src/mcp/index.ts](/Users/vincent/Developer/Github/personal/attestlens/src/mcp/index.ts:81)

### 7. `CHANGELOG.md` is behind the shipped product

- Changelog stops at `0.3.0` and phases 1-8.
- It does not cover phase 9, 10-lite, or the current package surface described in `docs/STATUS.md`.
- For a first public npm release, this is too stale.
  Evidence: [CHANGELOG.md](/Users/vincent/Developer/Github/personal/attestlens/CHANGELOG.md:1), [docs/STATUS.md](/Users/vincent/Developer/Github/personal/attestlens/docs/STATUS.md:13)

## Recommended Fixes

### Package metadata

- Add:
  ```json
  "publishConfig": {
    "access": "public"
  }
  ```
- Consider also adding:
  ```json
  "publishConfig": {
    "access": "public",
    "provenance": true
  }
  ```
  if publish happens from GitHub Actions.
- Add `engines.node`, ideally matching the real dependency floor, e.g. `>=20.12.0`.
- Add an explicit `exports` map or remove `main` if this package is not meant to be imported as a library.
- Consider `sideEffects: false` only if you intend to expose importable modules. It is not necessary for a CLI-only package.
- `funding` is optional. Leave it unset unless there is an actual sponsor URL.
- `author`, `repository`, `bugs`, and `homepage` are already present and acceptable.

### Packaging/build

- Split TypeScript build config so production build excludes tests:
  - exclude `src/**/*.test.ts`
  - optionally exclude authoring/dev-only surfaces if they are not intended for npm release yet
- Rebuild `dist/` from current `src/` before any publish attempt.
- Re-run `npm pack --dry-run --json` until the publish set is intentionally small.
- Decide whether to ship declaration files and source maps:
  - `.d.ts` files are fine if you want typed public modules.
  - `.js.map` and `.d.ts.map` are optional; they increase package size and expose source layout.

### CLI and binaries

- Keep `attestlens` and `attestlens-mcp`.
- Remove the `cli` binary alias unless it is required for compatibility.
- After rebuild, verify:
  - `node dist/cli/index.js --version`
  - `node dist/cli/index.js --help`
  - `node dist/mcp/index.js` boots cleanly in stdio mode

### README and docs

- Add an explicit beta install section, e.g. `npm install -g @attestlens/cli@beta` and `npx @attestlens/cli@beta ...`.
- Update jurisdiction coverage to include SG PDPA if you intend to ship it, or remove SG PDPA from source/status before release if it is not meant to be public yet.
- Add a short "first publish / beta caveats" note if CLI/API stability is still evolving.
- Update `CHANGELOG.md` to cover phase 9, 10-lite, and current release contents.

## Verified Items

### Already correct

- `type` is set to `module`, which matches the ESM build.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:5)
- `bin.attestlens` points to an existing file.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:8), [dist/cli/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/cli/index.js:1)
- `bin.attestlens-mcp` points to an existing file.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:10), [dist/mcp/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/mcp/index.js:1)
- Both built entrypoints have proper shebangs.
  Evidence: [dist/cli/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/cli/index.js:1), [dist/mcp/index.js](/Users/vincent/Developer/Github/personal/attestlens/dist/mcp/index.js:1)
- Both built entrypoints are executable.
  Evidence: `ls -l dist/cli/index.js dist/mcp/index.js` showed mode `-rwx------` for both.
- `README.md`, `CHANGELOG.md`, `LICENSE`, and `server.json` are included by the `files` whitelist.
  Evidence: [package.json](/Users/vincent/Developer/Github/personal/attestlens/package.json:55)
- No source `.ts` files, `.env` files, or obvious local config files were present in the dry-run tarball.
- No obvious hardcoded live secrets were found in `dist/`; matches were limited to scanner/test fixtures and environment variable names.
- `.npmignore` is absent. That is acceptable because `files` is present, but it means the `dist/` directory itself must be clean.
- `LICENSE` exists and is MIT.
  Evidence: [LICENSE](/Users/vincent/Developer/Github/personal/attestlens/LICENSE:1)
- `docs/INDEX.md` is current and references phase 10/11 work.
  Evidence: [docs/INDEX.md](/Users/vincent/Developer/Github/personal/attestlens/docs/INDEX.md:1)
- I did not find outstanding real TODO/FIXME comments in project source or docs. The only match was a regex in URL scanning that intentionally treats `TODO`/`FIXME` as placeholder indicators.
  Evidence: [src/scanner/url-scan.ts](/Users/vincent/Developer/Github/personal/attestlens/src/scanner/url-scan.ts:293)

### Command verification performed

- `node dist/cli/index.js --version` works, but returns `0.4.0`, which is wrong for the planned beta.
- `node dist/cli/index.js --help` works, but reflects an older command surface than `src/`.

## Research Findings

### npm publish and dist-tags

- For scoped public packages, npm’s official guidance is to publish with `--access public`.
- By default, `npm publish` applies the `latest` dist-tag. To avoid that, use `--tag beta`.
- For this release, the correct shape is `npm publish --access public --tag beta`.
- If you omit `--tag beta`, `npm install @attestlens/cli` will resolve to this beta as `latest`, which the team explicitly does not want.

Source:
- npm docs: Creating and publishing scoped public packages
  https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/
- npm docs: Adding dist-tags to packages
  https://docs.npmjs.com/adding-dist-tags-to-packages/

### Provenance and trusted publishing

- npm recommends provenance for supply-chain security.
- If publishing from GitHub Actions with a supported cloud-hosted runner, use `npm publish --provenance`.
- For a first publish of a scoped public package, the documented command is `npm publish --provenance --access public`.
- If using npm trusted publishing, provenance is generated automatically and you do not need a long-lived npm token for publish.
- Trusted publishing currently requires npm CLI `11.5.1+` and Node `22.14.0+`.

Source:
- npm docs: Generating provenance statements
  https://docs.npmjs.com/generating-provenance-statements/
- npm docs: Trusted publishing for npm packages
  https://docs.npmjs.com/trusted-publishers

### 2FA requirements

- Publishing now requires either:
  - 2FA enabled on the npm account, or
  - a granular access token with bypass 2FA enabled
- For CI/CD, npm recommends trusted publishing instead of long-lived tokens.

Source:
- npm docs: Requiring 2FA for package publishing and settings modification
  https://docs.npmjs.com/requiring-2fa-for-package-publishing-and-settings-modification
- npm docs: Configuring two-factor authentication
  https://docs.npmjs.com/configuring-two-factor-authentication/

### `publishConfig.registry`

- Do not set `publishConfig.registry` unless you intentionally want to force publish to a non-default registry or you regularly work across multiple registries and want a safety rail.
- If your team sometimes uses GitHub Packages or another registry, setting `publishConfig.registry` to `https://registry.npmjs.org/` can be a practical guard against accidental publishes to the wrong place.
- It is not required for a normal npmjs publish.

Inference based on npm publish docs and standard npm registry behavior:
- npm docs: `npm publish`
  https://docs.npmjs.com/cli/v8/commands/npm-publish

### npm organization / scope prerequisites

- If `@attestlens` is intended to be an organization scope, that organization must already exist on npm before publish.
- npm’s docs state organization-scoped packages require creating an npm organization first.
- I did not independently verify `@attestlens` existence from the workspace; that should be checked in the npm UI before release.

Source:
- npm docs: Creating an organization
  https://docs.npmjs.com/creating-an-organization
- npm docs: Creating and publishing scoped public packages
  https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/

### GitHub Actions considerations

- If publish is automated, configure:
  - `permissions: id-token: write`
  - a GitHub-hosted runner
  - `actions/setup-node` with the npm registry URL
  - provenance or trusted publishing
- Keep first publish manual if you have not yet validated:
  - the package name/scope ownership
  - access level
  - dist-tag behavior
  - tarball contents

Source:
- npm docs: Generating provenance statements
  https://docs.npmjs.com/generating-provenance-statements/
- npm docs: Trusted publishing for npm packages
  https://docs.npmjs.com/trusted-publishers

### MCP distribution / registry

- The MCP Registry is the official metadata registry for public MCP servers.
- Registry metadata is stored in `server.json`.
- Current official examples for package-based servers use a richer schema than the file currently in this repo.
- For npm-backed MCP publication, package metadata and `server.json` should align:
  - `mcpName` in `package.json`
  - matching `name` in `server.json`
  - matching versions
  - registry-native package/install metadata

Source:
- MCP Registry overview
  https://modelcontextprotocol.io/registry/about
- Official registry tracking issue summarizing package-based `server.json` requirements and examples
  https://github.com/modelcontextprotocol/servers/issues/3047

## Recommended Publish Command

Do not publish until the critical fixes above are complete and `npm pack --dry-run --json` is clean.

For a manual first beta publish from a local machine:

```bash
npm publish --access public --tag beta
```

For a GitHub Actions publish with provenance:

```bash
npm publish --provenance --access public --tag beta
```

Recommended final preflight sequence:

```bash
npm test
npm run build
node dist/cli/index.js --version
node dist/cli/index.js --help
npm pack --dry-run --json
```
