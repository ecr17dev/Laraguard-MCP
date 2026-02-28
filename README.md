# Laraguard MCP

> **A security audit MCP server for Laravel projects — built with TypeScript and stdio transport.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg)](https://www.typescriptlang.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-%40modelcontextprotocol%2Fsdk-orange)](https://github.com/modelcontextprotocol/sdk)

---

## Overview

**Laraguard MCP** is a standalone [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that performs security audits on Laravel projects. It is implemented in pure TypeScript using the official `@modelcontextprotocol/sdk` and communicates over **stdio**, making it natively compatible with any MCP-capable IDE or client (Cursor, Claude Desktop, VS Code MCP extensions, etc.).

The server analyses a Laravel project as an **external target** — it does not require Laravel to be running. It returns structured JSON findings categorised by severity, covering configuration issues, risky code patterns, and dependency hygiene.

---

## Features

- 🔍 **Static code scanning** — detects dangerous PHP patterns (`eval`, `shell_exec`, `unserialize`, raw SQL, etc.)
- ⚙️ **Configuration audit** — inspects `.env` and `config/cors.php` for insecure settings
- 📦 **Dependency audit** — verifies the presence of `composer.lock` and guides CI integration
- 🗂️ **Project metadata** — reads `composer.json` to identify Laravel version constraints
- 🔒 **Path traversal prevention** — strict allowlist enforcement for all file operations
- ✂️ **Secret redaction** — sensitive values are masked in textual output
- 🚀 **stdio transport** — zero-config network; works inside any IDE that supports MCP

---

## MCP Tools

The server exposes five tools, all accepting a single `path` parameter (absolute path to the Laravel project root).

| Tool | Description |
|------|-------------|
| `project_info` | Returns metadata from `composer.json`: project name, Laravel version constraint, PHP constraint, and engine info. |
| `dependency_audit` | Verifies the existence of `composer.lock` and advises on integrating advisory feeds in CI. |
| `config_audit` | Inspects `.env` (DEBUG flag, APP_ENV, secure cookies) and `config/cors.php` (wildcard origins). |
| `code_scan` | Runs static pattern matching across all PHP source files to flag high-risk constructs. |
| `full_audit` | Executes all three audits (`dependency_audit` + `config_audit` + `code_scan`) and returns a consolidated report. |

### Code Scan — Detected Patterns

| Pattern | Severity | Finding Type |
|---------|----------|--------------|
| `->whereRaw(` | High | `SQL_INJECTION` |
| `DB::raw(` | Medium | `RAW_SQL_USAGE` |
| `unserialize(` | Critical | `UNSAFE_UNSERIALIZE` |
| `shell_exec(` | Critical | `RCE_RISK` |
| `eval(` | Critical | `EVAL_USAGE` |

### Audit Report Schema

Every tool returns a structured JSON report:

```json
{
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 1
  },
  "findings": [
    {
      "severity": "high",
      "type": "SQL_INJECTION",
      "title": "Potential SQL injection via whereRaw",
      "file": "app/Http/Controllers/UserController.php",
      "line": 42,
      "evidence": "->whereRaw('email = ' . $email)",
      "recommendation": "Avoid raw SQL with user input. Use parameter binding/query builder."
    }
  ],
  "metadata": {
    "scannedPath": "/absolute/path/to/laravel-project",
    "engine": "Laraguard MCP",
    "version": "2.0.0",
    "timestamp": "2025-01-01T00:00:00.000Z",
    "durationMs": 312
  }
}
```

---

## Architecture

```
src/
├── index.ts      — MCP server bootstrap and tool registration
├── config.ts     — Environment variable loading and validation
├── security.ts   — Path allowlist enforcement and secret redaction
├── files.ts      — Safe file enumeration and reading
├── tools.ts      — Audit tool implementations
├── reports.ts    — Report aggregation and severity summarization
└── types.ts      — Domain types (Finding, AuditReport, Severity, etc.)
```

**Runtime stack:**

| Component | Technology |
|-----------|------------|
| Runtime | Node.js 20+ |
| Language | TypeScript 5.x |
| Protocol | Model Context Protocol (MCP) |
| Transport | `stdio` |
| Schema validation | Zod |
| MCP SDK | `@modelcontextprotocol/sdk` |

---

## Requirements

- **Node.js** 20 or higher
- **npm** 10 or higher

Verify your environment:

```bash
node -v
npm -v
```

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-org/laraguard-mcp.git
cd "Laraguard MCP"
npm install
```

---

## Configuration

Copy the example environment file and customise it:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_BASE_PATH` | — | Single allowed root path for project scanning. |
| `MCP_BASE_PATHS` | — | Comma-separated list of allowed root paths. **Takes precedence** over `MCP_BASE_PATH`. |
| `MCP_MAX_FILES` | `5000` | Maximum number of files to enumerate per scan. |
| `MCP_MAX_FILE_SIZE_BYTES` | `300000` | Maximum file size (in bytes) to read per file. |
| `MCP_TIMEOUT_SECONDS` | `30` | Logical timeout for audit operations. |

> **Priority order:** `MCP_BASE_PATHS` → `MCP_BASE_PATH` → current working directory.

### Example `.env`

```env
# Allow scanning two project roots
MCP_BASE_PATHS="/Users/yourname/projects/my-laravel-app,/srv/workspaces/api"

# Scan limits
MCP_MAX_FILES=5000
MCP_MAX_FILE_SIZE_BYTES=300000
MCP_TIMEOUT_SECONDS=30
```

---

## Development

### Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Runs the MCP server directly from TypeScript source using `tsx` (recommended for development) |
| `npm run build` | Compiles TypeScript to `dist/` |
| `npm run start` | Runs the compiled server from `dist/index.js` |
| `npm run check` | Type-checks the project without emitting output |

### Running in Development Mode

```bash
npm run dev
```

### Building for Production

```bash
npm run check   # Validate types first
npm run build   # Emit to dist/
npm run start   # Run compiled output
```

---

## Integration with MCP Clients

### Generic MCP Configuration (JSON)

Add the following to your MCP client's configuration file, replacing the path with the absolute path to your installation:

```json
{
  "mcpServers": {
    "laraguard": {
      "command": "node",
      "args": ["/absolute/path/to/Laraguard MCP/dist/index.js"],
      "env": {
        "MCP_BASE_PATHS": "/absolute/path/to/your-laravel-project"
      }
    }
  }
}
```

### Using Development Mode (tsx)

If you prefer to run without building first:

```json
{
  "mcpServers": {
    "laraguard": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/Laraguard MCP/src/index.ts"],
      "env": {
        "MCP_BASE_PATHS": "/absolute/path/to/your-laravel-project"
      }
    }
  }
}
```

### Cursor IDE

Open **Settings → MCP** and paste the JSON block above. Cursor will detect the server on the next reload.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) and add the `laraguard` entry under `mcpServers`.

---

## Tool Usage Reference

All tools accept a single JSON argument:

```json
{ "path": "/absolute/path/to/laravel-project" }
```

### `project_info`

Returns basic project metadata without performing any security checks.

**Use when you need to:**
- Confirm the target is a valid Laravel project
- Inspect framework and PHP version constraints before auditing

### `dependency_audit`

Checks for the presence of `composer.lock` and reports whether a dependency advisory lookup was executed.

> ⚠️ Laraguard MCP does not shell out to `composer audit` by default to maintain security portability. For full advisory feeds, integrate `composer audit` in your CI pipeline or connect an external advisory provider.

### `config_audit`

Inspects the following:

| Check | File | Severity |
|-------|------|----------|
| `APP_DEBUG=true` | `.env` | High |
| `APP_ENV=local` | `.env` | Medium |
| `SESSION_SECURE_COOKIE=false` | `.env` | Medium |
| Wildcard CORS origin (`'*'`) | `config/cors.php` | Medium |

### `code_scan`

Performs line-by-line static analysis across all PHP files within the allowed paths. Returns a finding for every matching pattern, including the file path and line number.

### `full_audit`

Runs `dependency_audit`, `config_audit`, and `code_scan` in parallel and merges all findings into a single consolidated report containing per-section summaries.

---

## Security Design

Laraguard MCP implements the following controls to ensure it operates safely even when handling untrusted project paths:

- **Strict path allowlisting** — all file access is validated against `MCP_BASE_PATHS` / `MCP_BASE_PATH`; path traversal attempts are rejected immediately.
- **File count limit** — configurable cap (`MCP_MAX_FILES`) prevents runaway enumeration on large monorepos.
- **File size limit** — configurable cap (`MCP_MAX_FILE_SIZE_BYTES`) prevents memory exhaustion from binary or generated files.
- **Directory and extension exclusions** — `vendor/`, `node_modules/`, `.git/`, and non-PHP files are excluded from scans.
- **Basic secret redaction** — sensitive values (passwords, tokens, keys) are masked in textual output before being returned to the client.

---

## Important Notes

- Laraguard MCP analyses a Laravel project **as an external auditor** — the Laravel application itself does not need to be running.
- The server is **framework-agnostic at the transport level**: any client that supports MCP stdio can use it.
- For enterprise-grade dependency vulnerability feeds, integrate `composer audit` in your CI/CD pipeline or subscribe to an external advisory service.
- All findings are informational. Always combine automated scanning with manual code review and DAST/SAST tooling for production security assessments.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](./LICENSE) for details.
