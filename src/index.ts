#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { loadConfig } from './config.js';
import { redactSecrets } from './security.js';
import {
  attackSimulateTool,
  bladeScanTool,
  codeScanTool,
  configAuditTool,
  dependencyAuditTool,
  fullAuditTool,
  projectInfoTool,
  routeAuditTool,
} from './tools.js';

const config = loadConfig();

const server = new McpServer({
  name: 'laraguard-mcp',
  version: '3.0.0',
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

// ---------------------------------------------------------------------------
// project_info
// ---------------------------------------------------------------------------
server.registerTool(
  'project_info',
  {
    description: 'Return metadata for a Laravel project: composer constraints, framework detection, PHP version.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await projectInfoTool(path, config)),
);

// ---------------------------------------------------------------------------
// dependency_audit  (now queries OSV.dev for real CVEs)
// ---------------------------------------------------------------------------
server.registerTool(
  'dependency_audit',
  {
    description:
      'Audit Composer dependencies against the OSV.dev vulnerability advisory database. ' +
      'Parses composer.lock and reports CVEs with severity and fix versions.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await dependencyAuditTool(path, config)),
);

// ---------------------------------------------------------------------------
// config_audit
// ---------------------------------------------------------------------------
server.registerTool(
  'config_audit',
  {
    description:
      'Audit risky Laravel environment and configuration settings: APP_DEBUG, APP_ENV, ' +
      'APP_KEY, SESSION_SECURE_COOKIE, and CORS wildcard origins.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await configAuditTool(path, config)),
);

// ---------------------------------------------------------------------------
// code_scan  (expanded: +10 rules including hardcoded secrets, weak crypto, mass assignment, LFI)
// ---------------------------------------------------------------------------
server.registerTool(
  'code_scan',
  {
    description:
      'Run static pattern analysis across all PHP source files. Detects SQL injection, ' +
      'RCE risks (eval/shell_exec/exec/system), unsafe unserialize, hardcoded credentials, ' +
      'weak cryptography (MD5/SHA1), mass assignment, path traversal, and LFI risks.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await codeScanTool(path, config)),
);

// ---------------------------------------------------------------------------
// blade_scan  (NEW)
// ---------------------------------------------------------------------------
server.registerTool(
  'blade_scan',
  {
    description:
      'Scan Laravel Blade templates in resources/views/ for XSS vulnerabilities. ' +
      'Detects unescaped output ({!! !!}), raw user input rendering, and unsafe PHP echo in templates.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await bladeScanTool(path, config)),
);

// ---------------------------------------------------------------------------
// route_audit  (NEW)
// ---------------------------------------------------------------------------
server.registerTool(
  'route_audit',
  {
    description:
      'Audit Laravel route files (routes/web.php, routes/api.php) for security misconfigurations. ' +
      'Detects admin routes without auth middleware, API routes without authentication, ' +
      'login routes without throttle, and CSRF exception wildcards in VerifyCsrfToken.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await routeAuditTool(path, config)),
);

// ---------------------------------------------------------------------------
// attack_simulate  (NEW)
// ---------------------------------------------------------------------------
server.registerTool(
  'attack_simulate',
  {
    description:
      'Run active HTTP security probes against a running Laravel application. ' +
      'Probes: error/debug disclosure, SQL injection on /login, reflected XSS, ' +
      'CSRF enforcement, auth bypass on /api/user, and brute-force rate limiting. ' +
      'WARNING: only use against local or staging environments — never production.',
    inputSchema: {
      path: z.string().min(1).describe('Absolute path of the target Laravel project'),
      baseUrl: z
        .string()
        .url()
        .describe('Base URL of the running Laravel application (e.g. http://localhost:8000)'),
    },
  },
  async ({ path, baseUrl }) => asToolResult(await attackSimulateTool(path, baseUrl, config)),
);

// ---------------------------------------------------------------------------
// full_audit  (now runs 5 audits in parallel: deps, config, code, blade, routes)
// ---------------------------------------------------------------------------
server.registerTool(
  'full_audit',
  {
    description:
      'Run all static audits in parallel: dependency CVE check (OSV.dev), environment config, ' +
      'PHP code scan, Blade XSS scan, and route/middleware audit. ' +
      'Returns a single consolidated report with per-section summaries.',
    inputSchema: pathSchema,
  },
  async ({ path }) => asToolResult(await fullAuditTool(path, config)),
);

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  process.stderr.write(`Laraguard MCP server error: ${String(error)}\n`);
  process.exit(1);
});
