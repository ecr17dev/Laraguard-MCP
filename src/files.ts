import fs from 'node:fs/promises';
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

  const entries = await fs.readdir(currentDir, { withFileTypes: true });

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
