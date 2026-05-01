import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export type SupportedClient = 'claude-desktop' | 'cline' | 'continue' | 'cursor';
type ConfigShape = Record<string, unknown>;

export interface ClientDefinition {
  name: SupportedClient;
  label: string;
  configPath: string;
  serverKey: string;
}

export interface InstallEnvironment {
  homeDir?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}

export interface ClientMutationResult {
  client: SupportedClient;
  configPath: string;
  changed: boolean;
  backupPath?: string;
  action: 'install' | 'uninstall';
  dryRun: boolean;
}

const CLEARWAY_SERVER_NAME = 'clearway';
const CLEARWAY_SERVER_CONFIG = {
  command: 'npx',
  args: ['-y', '@attestlens/cli', 'mcp'],
  transport: 'stdio',
};

export function getDefaultClientDefinitions(overrides: InstallEnvironment = {}): ClientDefinition[] {
  const homeDir = overrides.homeDir ?? os.homedir();
  const platform = overrides.platform ?? process.platform;
  const env = overrides.env ?? process.env;
  const appData = env.APPDATA || path.join(homeDir, 'AppData', 'Roaming');
  const supportDir = platform === 'darwin'
    ? path.join(homeDir, 'Library', 'Application Support')
    : platform === 'win32'
      ? appData
      : path.join(homeDir, '.config');

  return [
    {
      name: 'claude-desktop',
      label: 'Claude Desktop',
      configPath: platform === 'win32'
        ? path.join(appData, 'Claude', 'claude_desktop_config.json')
        : path.join(supportDir, 'Claude', 'claude_desktop_config.json'),
      serverKey: 'mcpServers',
    },
    {
      name: 'cline',
      label: 'Cline',
      configPath: platform === 'win32'
        ? path.join(appData, 'Code', 'User', 'settings.json')
        : platform === 'darwin'
          ? path.join(supportDir, 'Code', 'User', 'settings.json')
          : path.join(supportDir, 'Code', 'User', 'settings.json'),
      serverKey: 'cline.mcpServers',
    },
    {
      name: 'continue',
      label: 'Continue',
      configPath: path.join(homeDir, '.continue', 'config.json'),
      serverKey: 'mcpServers',
    },
    {
      name: 'cursor',
      label: 'Cursor',
      configPath: platform === 'win32'
        ? path.join(appData, 'Cursor', 'mcp.json')
        : path.join(homeDir, '.cursor', 'mcp.json'),
      serverKey: 'mcpServers',
    },
  ];
}

export async function detectInstalledClients(
  overrides: InstallEnvironment = {},
): Promise<ClientDefinition[]> {
  const definitions = getDefaultClientDefinitions(overrides);
  const detected: ClientDefinition[] = [];

  for (const definition of definitions) {
    if (await pathExists(definition.configPath) || await pathExists(path.dirname(definition.configPath))) {
      detected.push(definition);
    }
  }

  return detected;
}

export async function installClients(options: {
  client?: SupportedClient;
  dryRun?: boolean;
  env?: InstallEnvironment;
} = {}): Promise<ClientMutationResult[]> {
  const targets = await resolveTargetClients(options.client, options.env);
  const results: ClientMutationResult[] = [];

  for (const client of targets) {
    results.push(await mutateClientConfig(client, 'install', options.dryRun === true));
  }

  return results;
}

export async function uninstallClients(options: {
  client?: SupportedClient;
  dryRun?: boolean;
  env?: InstallEnvironment;
} = {}): Promise<ClientMutationResult[]> {
  const targets = await resolveTargetClients(options.client, options.env);
  const results: ClientMutationResult[] = [];

  for (const client of targets) {
    results.push(await mutateClientConfig(client, 'uninstall', options.dryRun === true));
  }

  return results;
}

export function upsertServerConfig(config: ConfigShape, definition: ClientDefinition): { changed: boolean; nextConfig: ConfigShape } {
  const nextConfig = structuredClone(config);
  const container = ensureServerContainer(nextConfig, definition.serverKey);
  const current = container[CLEARWAY_SERVER_NAME];
  const serializedCurrent = JSON.stringify(current ?? null);
  const serializedExpected = JSON.stringify(CLEARWAY_SERVER_CONFIG);
  if (serializedCurrent === serializedExpected) {
    return { changed: false, nextConfig };
  }
  container[CLEARWAY_SERVER_NAME] = structuredClone(CLEARWAY_SERVER_CONFIG);
  return { changed: true, nextConfig };
}

export function removeServerConfig(config: ConfigShape, definition: ClientDefinition): { changed: boolean; nextConfig: ConfigShape } {
  const nextConfig = structuredClone(config);
  const container = getServerContainer(nextConfig, definition.serverKey);
  if (!container || !(CLEARWAY_SERVER_NAME in container)) {
    return { changed: false, nextConfig };
  }

  delete container[CLEARWAY_SERVER_NAME];
  return { changed: true, nextConfig };
}

async function resolveTargetClients(
  client: SupportedClient | undefined,
  env: InstallEnvironment | undefined,
): Promise<ClientDefinition[]> {
  const definitions = getDefaultClientDefinitions(env);
  if (client) {
    const selected = definitions.find((definition) => definition.name === client);
    if (!selected) {
      throw new Error(`Unsupported client: ${client}`);
    }
    return [selected];
  }

  const detected = await detectInstalledClients(env);
  if (detected.length > 0) {
    return detected;
  }

  throw new Error('No supported MCP client config directories were detected. Re-run with --client <name> to target one explicitly.');
}

async function mutateClientConfig(
  definition: ClientDefinition,
  action: 'install' | 'uninstall',
  dryRun: boolean,
): Promise<ClientMutationResult> {
  const existing = await loadJsonConfig(definition.configPath);
  const mutation = action === 'install'
    ? upsertServerConfig(existing, definition)
    : removeServerConfig(existing, definition);

  let backupPath: string | undefined;
  if (!dryRun && mutation.changed) {
    await fs.mkdir(path.dirname(definition.configPath), { recursive: true });
    if (await pathExists(definition.configPath)) {
      backupPath = await createBackup(definition.configPath);
    }
    await fs.writeFile(definition.configPath, `${JSON.stringify(mutation.nextConfig, null, 2)}\n`, 'utf-8');
  }

  return {
    client: definition.name,
    configPath: definition.configPath,
    changed: mutation.changed,
    backupPath,
    action,
    dryRun,
  };
}

async function loadJsonConfig(configPath: string): Promise<ConfigShape> {
  try {
    const raw = await fs.readFile(configPath, 'utf-8');
    if (raw.trim().length === 0) {
      return {};
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`Config at ${configPath} must be a JSON object`);
    }
    return parsed as ConfigShape;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      return {};
    }
    if (error.name === 'SyntaxError') {
      throw new Error(`Config at ${configPath} contains invalid JSON`);
    }
    throw error;
  }
}

function getServerContainer(config: ConfigShape, serverKey: string): Record<string, unknown> | undefined {
  const value = config[serverKey];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function ensureServerContainer(config: ConfigShape, serverKey: string): Record<string, unknown> {
  const existing = getServerContainer(config, serverKey);
  if (existing) {
    return existing;
  }
  const container: Record<string, unknown> = {};
  config[serverKey] = container;
  return container;
}

async function createBackup(configPath: string): Promise<string> {
  const backupPath = `${configPath}.bak-${Date.now()}`;
  await fs.copyFile(configPath, backupPath);
  return backupPath;
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}
