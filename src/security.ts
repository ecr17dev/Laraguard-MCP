import path from 'node:path';
import type { McpConfig } from './config.js';

export function ensureAllowedPath(inputPath: string, config: McpConfig): string {
  const resolved = path.resolve(inputPath);

  for (const basePath of config.basePaths) {
    const normalizedBase = path.resolve(basePath);
    if (resolved === normalizedBase || resolved.startsWith(`${normalizedBase}${path.sep}`)) {
      return resolved;
    }
  }

  throw new Error('Path is outside allowed MCP base paths.');
}

export function redactSecrets(input: string): string {
  const patterns = [
    /(api[_-]?key\s*[=:]\s*)([^\s]+)/gi,
    /(token\s*[=:]\s*)([^\s]+)/gi,
    /(password\s*[=:]\s*)([^\s]+)/gi,
    /(secret\s*[=:]\s*)([^\s]+)/gi,
  ];

  let output = input;
  for (const pattern of patterns) {
    output = output.replace(pattern, '$1[REDACTED]');
  }

  return output;
}
