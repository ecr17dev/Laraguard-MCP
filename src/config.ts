import path from 'node:path';

export interface McpConfig {
  basePaths: string[];
  maxFiles: number;
  maxFileSizeBytes: number;
  excludedDirs: string[];
  excludedExtensions: string[];
  timeoutSeconds: number;
}

function normalizePath(input: string): string {
  return path.resolve(input);
}

function readInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function readBasePaths(): string[] {
  const list = process.env.MCP_BASE_PATHS?.trim();
  if (list) {
    const paths = list
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)
      .map(normalizePath);

    if (paths.length > 0) return paths;
  }

  const single = process.env.MCP_BASE_PATH?.trim();
  if (single) return [normalizePath(single)];

  return [process.cwd()];
}

export function loadConfig(): McpConfig {
  return {
    basePaths: readBasePaths(),
    maxFiles: readInt('MCP_MAX_FILES', 5000),
    maxFileSizeBytes: readInt('MCP_MAX_FILE_SIZE_BYTES', 300000),
    excludedDirs: ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git'],
    excludedExtensions: ['png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'zip', 'tar', 'gz'],
    timeoutSeconds: readInt('MCP_TIMEOUT_SECONDS', 30),
  };
}
