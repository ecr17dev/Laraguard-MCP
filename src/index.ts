#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { loadConfig } from './config.js';
import { redactSecrets } from './security.js';
import {
  codeScanTool,
  configAuditTool,
  dependencyAuditTool,
  fullAuditTool,
  projectInfoTool,
} from './tools.js';

const config = loadConfig();

const server = new McpServer({
  name: 'laraguard-mcp',
  version: '2.0.0',
});

const pathSchema = { path: z.string().min(1).describe('Absolute path of the target Laravel project') };

function asToolResult(data: unknown) {
  const text = redactSecrets(JSON.stringify(data, null, 2));
  const structuredContent =
    typeof data === 'object' && data !== null ? (data as { [key: string]: unknown }) : undefined;
  return {
    content: [{ type: 'text' as const, text }],
    structuredContent,
  };
}

server.registerTool(
  'project_info',
  {
    description: 'Return metadata for a Laravel project (composer constraints, framework detection).',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await projectInfoTool(path, config)),
);

server.registerTool(
  'dependency_audit',
  {
    description: 'Inspect dependency state using composer.lock presence and report dependency audit status.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await dependencyAuditTool(path, config)),
);

server.registerTool(
  'config_audit',
  {
    description: 'Audit risky Laravel and environment configuration settings.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await configAuditTool(path, config)),
);

server.registerTool(
  'code_scan',
  {
    description: 'Run static pattern scan for risky PHP security constructs.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await codeScanTool(path, config)),
);

server.registerTool(
  'full_audit',
  {
    description: 'Run dependency, config, and code scans and return a consolidated security report.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await fullAuditTool(path, config)),
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  process.stderr.write(`Laraguard MCP server error: ${String(error)}\n`);
  process.exit(1);
});
