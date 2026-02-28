# Laraguard MCP

> **A security audit MCP server for Laravel projects — built with TypeScript and stdio transport.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg)](https://www.typescriptlang.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-%40modelcontextprotocol%2Fsdk-orange)](https://github.com/modelcontextprotocol/sdk)
[![Version](https://img.shields.io/badge/version-3.0.0-blueviolet.svg)](./package.json)

---

## Overview

**Laraguard MCP** is a standalone [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that performs security audits on Laravel projects. It is implemented in pure TypeScript using the official `@modelcontextprotocol/sdk` and communicates over **stdio**, making it natively compatible with any MCP-capable IDE or client (Cursor, Claude Desktop, VS Code MCP extensions, etc.).

The server analyses a Laravel project as an **external target** — it does not require Laravel to be running. It returns structured JSON findings categorised by severity, covering configuration issues, risky code patterns, and dependency hygiene.

---

## Features

- 🔍 **Static code scanning** — 15+ rules covering SQL injection, RCE, hardcoded credentials, weak crypto, mass assignment, and LFI
- 🎭 **Blade XSS scanner** — detects unescaped `{!! !!}` output and raw input rendering in templates
- 🛣️ **Route & middleware audit** — flags admin routes without auth, API routes without auth:sanctum, login routes without throttle, and CSRF exceptions
- 📦 **Dependency CVE feed** — queries the [OSV.dev](https://osv.dev/) API for real CVEs across all `composer.lock` packages
- ⚙️ **Configuration audit** — inspects `.env` (DEBUG, APP_KEY, APP_ENV, secure cookies) and `config/cors.php`
- 🗂️ **Project metadata** — reads `composer.json` to identify Laravel and PHP version constraints
- � **Active attack simulation** — fires HTTP probes (SQL injection, XSS, CSRF, auth bypass, rate limiting) against a running app
- �🔒 **Path traversal prevention** — strict allowlist enforcement for all file operations
- ✂️ **Secret redaction** — sensitive values are masked in textual output before reaching the MCP client
- 🚀 **stdio transport** — zero-config network; works inside any IDE that supports MCP

---

## MCP Tools

The server exposes **8 tools**. All static tools accept a single `path` parameter. `attack_simulate` additionally requires a `baseUrl`.

| Tool | Input | Description |
|------|-------|-------------|
| `project_info` | `path` | Returns metadata from `composer.json`: project name, Laravel/PHP version constraints, engine info. |
| `dependency_audit` | `path` | Parses `composer.lock` and queries **OSV.dev** for real CVEs with severity and fix versions. |
| `config_audit` | `path` | Inspects `.env` (DEBUG, APP_KEY, APP_ENV, session cookies) and `config/cors.php` (wildcard origins). |
| `code_scan` | `path` | 15+ static pattern rules across all PHP files — credentials, weak crypto, mass assignment, RCE, LFI, SQL injection. |
| `blade_scan` | `path` | Scans `resources/views/` Blade templates for unescaped output (`{!! !!}`) and XSS-prone patterns. |
| `route_audit` | `path` | Audits route files and middleware for missing auth, missing throttle, and CSRF exception wildcards. |
| `attack_simulate` | `path` + `baseUrl` | Fires 6 live HTTP probes against a running app: SQL injection, XSS, CSRF, auth bypass, rate limiting, error disclosure. |
| `full_audit` | `path` | Runs `dependency_audit` + `config_audit` + `code_scan` + `blade_scan` + `route_audit` in parallel and returns a consolidated report. |

### Code Scan — Detected Patterns

| Pattern | Severity | Finding Type |
|---------|----------|--------------|
| `->whereRaw(` | High | `SQL_INJECTION` |
| `DB::raw(` | Medium | `RAW_SQL_USAGE` |
| `unserialize(` | Critical | `UNSAFE_UNSERIALIZE` |
| `shell_exec(` / `exec(` / `system(` / `passthru(` | Critical | `RCE_RISK` |
| `eval(` | Critical | `EVAL_USAGE` |
| `password = 'literal'` | Critical | `HARDCODED_PASSWORD` |
| `api_key = 'literal'` | Critical | `HARDCODED_API_KEY` |
| Long hardcoded tokens/secrets | High | `HARDCODED_SECRET` |
| `md5(` | High | `WEAK_HASH_MD5` |
| `sha1(` | Medium | `WEAK_HASH_SHA1` |
| `protected $guarded = []` | High | `MASS_ASSIGNMENT_UNGUARDED` |
| `file_get_contents($request…)` | Critical | `PATH_TRAVERSAL_RISK` |
| `include/require($request…)` | Critical | `LFI_RISK` |

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
git clone https://github.com/ecr17dev/Laraguard-MCP.git
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

### `project_info`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

Returns basic project metadata without performing any security checks. Use it to confirm the target is a valid Laravel project and inspect framework and PHP version constraints before auditing.

---

### `dependency_audit`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

Parses `composer.lock`, extracts all locked package names and versions, and queries the **[OSV.dev](https://osv.dev/) batch API** for known CVEs. Each vulnerability is returned as a finding with:

- CVE/GHSA identifier and summary
- Severity (mapped from CVSS score)
- Affected package version and recommended fix version
- Direct link to the advisory page

---

### `config_audit`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

| Check | File | Severity |
|-------|------|----------|
| `APP_DEBUG=true` | `.env` | High |
| `APP_ENV=local` | `.env` | Medium |
| `APP_KEY=` (empty) | `.env` | Critical |
| `SESSION_SECURE_COOKIE=false` | `.env` | Medium |
| Wildcard CORS origin (`'*'`) | `config/cors.php` | Medium |

---

### `code_scan`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

Performs line-by-line static analysis across all PHP files. Returns every matching finding with file path, line number, and evidence snippet. See the [Code Scan — Detected Patterns](#code-scan--detected-patterns) table above for the full rule set.

---

### `blade_scan`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

Scans all `.blade.php` files under `resources/views/` for XSS-prone output patterns:

| Check | Severity |
|-------|----------|
| `{!! $variable !!}` — unescaped variable | High |
| `{!! request( !!}` / `{!! old( !!}` — raw user input | Critical |
| `echo $_GET` / `echo $_POST` in blade PHP blocks | High |

---

### `route_audit`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

Reads `routes/web.php`, `routes/api.php`, and `app/Http/Middleware/VerifyCsrfToken.php`:

| Check | File | Severity |
|-------|------|----------|
| Admin/dashboard route without `auth` middleware | `routes/web.php` | Critical |
| API route without `auth:sanctum` / `auth:api` | `routes/api.php` | High |
| Login/register route without `throttle` middleware | Route files | Medium |
| Wildcard pattern in `VerifyCsrfToken::$except` | `VerifyCsrfToken.php` | High |

---

### `attack_simulate`

```json
{
  "path": "/absolute/path/to/laravel-project",
  "baseUrl": "http://localhost:8000"
}
```

> ⚠️ **Only use against local or staging environments. Never run against production.**

Fires 6 live HTTP probes against the running application:

| Probe | Method & Endpoint | What it Tests |
|-------|------------------|---------------|
| `error_disclosure` | `GET /__invalid_route__` | Framework/stack-trace info leakage |
| `sql_injection_login` | `POST /login` with SQLi payload | SQL injection in login form |
| `reflected_xss` | `GET /search?q=<script>…` | Reflected XSS in search/query params |
| `csrf_not_enforced` | `POST /login` without CSRF token | CSRF token enforcement (expects HTTP 419) |
| `auth_bypass` | `GET /api/user` without auth header | Unauthenticated access to protected API |
| `rate_limit` | 10× rapid `POST /login` | Brute-force rate limiting (expects HTTP 429) |

The report includes a `probes` metadata array with the status code, duration, and triggered state for every probe.

---

### `full_audit`

```json
{ "path": "/absolute/path/to/laravel-project" }
```

Runs `dependency_audit`, `config_audit`, `code_scan`, `blade_scan`, and `route_audit` **in parallel** and merges all findings into a single consolidated report. The metadata includes per-section summaries.

---

## Security Design

Laraguard MCP implements the following controls to ensure it operates safely even when handling untrusted project paths:

- **Strict path allowlisting** — all file access is validated against `MCP_BASE_PATHS` / `MCP_BASE_PATH`; path traversal attempts are rejected immediately.
- **File count limit** — configurable cap (`MCP_MAX_FILES`) prevents runaway enumeration on large monorepos.
- **File size limit** — configurable cap (`MCP_MAX_FILE_SIZE_BYTES`) prevents memory exhaustion from binary or generated files.
- **Directory and extension exclusions** — `vendor/`, `node_modules/`, `.git/`, and binary file types are excluded from scans.
- **Secret redaction** — sensitive values (passwords, tokens, keys) are masked in textual output before being returned to the MCP client.
- **Attack simulation guard** — `attack_simulate` always targets only the explicitly provided `baseUrl`; no automated discovery or production detection is performed.

---

## Important Notes

- Laraguard MCP analyses a Laravel project **as an external auditor** — the Laravel application itself does not need to be running for static tools.
- `attack_simulate` **requires** the application to be running and should never target production.
- The server is **framework-agnostic at the transport level**: any client that supports MCP stdio can use it.
- All findings are informational. Always combine automated scanning with manual code review and dedicated DAST/SAST tooling (OWASP ZAP, Burp Suite) for production security assessments.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](./LICENSE) for details.
