import fs from 'node:fs/promises';
import type { Dirent } from 'node:fs';
import path from 'node:path';
import type { McpConfig } from './config.js';

export interface FileEntry {
  absolutePath: string;
  relativePath: string;
  content: string;
}

function shouldSkipDir(relativeDir: string, config: McpConfig): boolean {
  const normalized = relativeDir.replace(/\\/g, '/');
  return config.excludedDirs.some((excluded) => {
    const normalizedExcluded = excluded.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    return normalized === normalizedExcluded || normalized.startsWith(`${normalizedExcluded}/`);
  });
}

function shouldSkipFile(filePath: string, config: McpConfig): boolean {
  const ext = path.extname(filePath).replace('.', '').toLowerCase();
  return config.excludedExtensions.includes(ext);
}

async function walk(
  rootPath: string,
  currentDir: string,
  config: McpConfig,
  acc: string[],
): Promise<void> {
  if (acc.length >= config.maxFiles) return;

  let entries: Dirent[];
  try {
    entries = (await fs.readdir(currentDir, { withFileTypes: true })) as unknown as Dirent[];
  } catch {
    return;
  }

  for (const entry of entries) {
    if (acc.length >= config.maxFiles) return;

    const abs = path.join(currentDir, entry.name);
    const rel = path.relative(rootPath, abs);

    if (entry.isDirectory()) {
      if (shouldSkipDir(rel, config)) continue;
      await walk(rootPath, abs, config, acc);
      continue;
    }

    if (!entry.isFile()) continue;
    if (shouldSkipFile(abs, config)) continue;

    const stat = await fs.stat(abs);
    if (stat.size > config.maxFileSizeBytes) continue;

    acc.push(abs);
  }
}

export async function enumerateFiles(basePath: string, config: McpConfig): Promise<string[]> {
  const files: string[] = [];
  await walk(basePath, basePath, config, files);
  return files;
}

export async function readPhpFiles(basePath: string, config: McpConfig): Promise<FileEntry[]> {
  const files = await enumerateFiles(basePath, config);
  const phpFiles = files.filter((file) => file.endsWith('.php'));

  const results: FileEntry[] = [];
  for (const file of phpFiles) {
    const content = await fs.readFile(file, 'utf8');
    results.push({
      absolutePath: file,
      relativePath: path.relative(basePath, file),
      content,
    });
  }

  return results;
}

/**
 * Reads all Blade template files (.blade.php) from resources/views/.
 * Used by bladeScanTool to detect XSS patterns in templates.
 */
export async function readBladeFiles(basePath: string, config: McpConfig): Promise<FileEntry[]> {
  const viewsDir = path.join(basePath, 'resources', 'views');

  try {
    await fs.access(viewsDir);
  } catch {
    return [];
  }

  const acc: string[] = [];
  await walk(viewsDir, viewsDir, config, acc);
  const bladeFiles = acc.filter((f) => f.endsWith('.blade.php') || f.endsWith('.php'));

  const results: FileEntry[] = [];
  for (const file of bladeFiles) {
    try {
      const content = await fs.readFile(file, 'utf8');
      results.push({
        absolutePath: file,
        relativePath: path.relative(basePath, file),
        content,
      });
    } catch {
      // skip unreadable files
    }
  }

  return results;
}

/**
 * Reads a list of specific files by their relative paths within basePath.
 * Used by routeAuditTool to read known Laravel files (routes/, VerifyCsrfToken, etc.).
 */
export async function readSpecificFiles(
  basePath: string,
  relativePaths: string[],
  config: McpConfig,
): Promise<FileEntry[]> {
  const results: FileEntry[] = [];

  for (const rel of relativePaths) {
    const abs = path.join(basePath, rel);
    try {
      const stat = await fs.stat(abs);
      if (stat.size > config.maxFileSizeBytes) continue;
      const content = await fs.readFile(abs, 'utf8');
      results.push({ absolutePath: abs, relativePath: rel, content });
    } catch {
      // file does not exist or is unreadable — skip silently
    }
  }

  return results;
}
