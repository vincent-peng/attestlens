import path from 'node:path';

export function sanitizeTargetUrlForOutput(targetUrl?: string): string | undefined {
  if (!targetUrl) {
    return undefined;
  }

  try {
    const parsed = new URL(targetUrl);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return targetUrl.split('#', 1)[0]?.split('?', 1)[0] || targetUrl;
  }
}

export function sanitizeTargetPathForOutput(targetPath?: string): string | undefined {
  if (!targetPath) {
    return undefined;
  }

  const normalized = path.normalize(targetPath);
  return path.basename(normalized) || normalized;
}

export function getHostnameFromTargetUrl(targetUrl?: string): string | undefined {
  if (!targetUrl) {
    return undefined;
  }

  try {
    return new URL(targetUrl).hostname || undefined;
  } catch {
    return undefined;
  }
}
