import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  detectInstalledClients,
  getDefaultClientDefinitions,
  installClients,
  removeServerConfig,
  uninstallClients,
  upsertServerConfig,
} from './install.js';

describe('CLI installer helpers', () => {
  const cleanup: string[] = [];

  afterEach(async () => {
    await Promise.all(cleanup.splice(0).map((target) => fs.rm(target, { recursive: true, force: true })));
  });

  it('detects supported clients from config files and parent directories', async () => {
    const homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-install-detect-'));
    cleanup.push(homeDir);

    const continueDir = path.join(homeDir, '.continue');
    await fs.mkdir(continueDir, { recursive: true });
    await fs.writeFile(path.join(continueDir, 'config.json'), '{}', 'utf-8');

    const detected = await detectInstalledClients({ homeDir, platform: 'darwin', env: {} as NodeJS.ProcessEnv });
    expect(detected.map((client) => client.name)).toContain('continue');
  });

  it('installs Clearway config idempotently and creates a backup before changing an existing config', async () => {
    const homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-install-'));
    cleanup.push(homeDir);

    const continueDir = path.join(homeDir, '.continue');
    const configPath = path.join(continueDir, 'config.json');
    await fs.mkdir(continueDir, { recursive: true });
    await fs.writeFile(configPath, JSON.stringify({ mcpServers: { existing: { command: 'echo' } } }, null, 2), 'utf-8');

    const firstRun = await installClients({
      client: 'continue',
      env: { homeDir, platform: 'darwin', env: {} as NodeJS.ProcessEnv },
    });
    const secondRun = await installClients({
      client: 'continue',
      env: { homeDir, platform: 'darwin', env: {} as NodeJS.ProcessEnv },
    });

    const config = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(firstRun[0]!.changed).toBe(true);
    expect(firstRun[0]!.backupPath).toMatch(/config\.json\.bak-/);
    expect(secondRun[0]!.changed).toBe(false);
    expect(config.mcpServers.clearway).toEqual({
      command: 'npx',
      args: ['-y', '@attestlens/cli', 'mcp'],
      transport: 'stdio',
    });
    expect(config.mcpServers.existing).toEqual({ command: 'echo' });
  });

  it('supports dry-run installs without writing files', async () => {
    const homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-install-dry-'));
    cleanup.push(homeDir);

    const result = await installClients({
      client: 'cursor',
      dryRun: true,
      env: { homeDir, platform: 'darwin', env: {} as NodeJS.ProcessEnv },
    });

    const definitions = getDefaultClientDefinitions({ homeDir, platform: 'darwin', env: {} as NodeJS.ProcessEnv });
    const cursorConfigPath = definitions.find((definition) => definition.name === 'cursor')!.configPath;
    expect(result[0]!.changed).toBe(true);
    await expect(fs.readFile(cursorConfigPath, 'utf-8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('uninstalls Clearway config and restores the original JSON shape', async () => {
    const homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-uninstall-'));
    cleanup.push(homeDir);

    const cursorDir = path.join(homeDir, '.cursor');
    const configPath = path.join(cursorDir, 'mcp.json');
    await fs.mkdir(cursorDir, { recursive: true });
    await fs.writeFile(configPath, JSON.stringify({
      mcpServers: {
        clearway: { command: 'npx', args: ['-y', '@attestlens/cli', 'mcp'], transport: 'stdio' },
        existing: { command: 'echo' },
      },
    }, null, 2), 'utf-8');

    const result = await uninstallClients({
      client: 'cursor',
      env: { homeDir, platform: 'darwin', env: {} as NodeJS.ProcessEnv },
    });

    const config = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(result[0]!.changed).toBe(true);
    expect(config).toEqual({
      mcpServers: {
        existing: { command: 'echo' },
      },
    });
  });

  it('keeps the shared container key when uninstalling the last Clearway server entry', () => {
    const definition = {
      name: 'cline' as const,
      label: 'Cline',
      configPath: '/tmp/cline/settings.json',
      serverKey: 'cline.mcpServers',
    };

    const { changed, nextConfig } = removeServerConfig({
      'cline.mcpServers': {
        clearway: {
          command: 'npx',
          args: ['-y', '@attestlens/cli', 'mcp'],
          transport: 'stdio',
        },
      },
    }, definition);

    expect(changed).toBe(true);
    expect(nextConfig).toEqual({
      'cline.mcpServers': {},
    });
  });

  it('merges into empty configs gracefully', () => {
    const definition = {
      name: 'continue' as const,
      label: 'Continue',
      configPath: '/tmp/continue/config.json',
      serverKey: 'mcpServers',
    };
    const { nextConfig } = upsertServerConfig({}, definition);
    expect(nextConfig).toEqual({
      mcpServers: {
        clearway: {
          command: 'npx',
          args: ['-y', '@attestlens/cli', 'mcp'],
          transport: 'stdio',
        },
      },
    });
  });
});
