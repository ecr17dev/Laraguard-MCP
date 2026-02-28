import fs from 'node:fs/promises';
import path from 'node:path';
import type { McpConfig } from './config.js';
import { readBladeFiles, readPhpFiles, readSpecificFiles } from './files.js';
import { buildReport, summarizeFindings } from './reports.js';
import { ensureAllowedPath } from './security.js';
import type { AuditReport, Finding, Severity } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function safeLine(content: string, pattern: RegExp): number | null {
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if (pattern.test(lines[i])) return i + 1;
  }
  return null;
}

function recommendationForType(type: string): string {
  switch (type) {
    // Code scan
    case 'SQL_INJECTION':
      return 'Avoid raw SQL with user input. Use Eloquent query builder with parameter binding.';
    case 'RAW_SQL_USAGE':
      return 'Prefer Eloquent or the query builder over DB::raw(). If raw SQL is necessary, use parameterised bindings.';
    case 'UNSAFE_UNSERIALIZE':
      return 'Never unserialize untrusted data. Use JSON encoding/decoding instead.';
    case 'RCE_RISK':
      return 'Avoid shell_exec with user-controlled input. Use strict allowlists if system calls are required.';
    case 'EVAL_USAGE':
      return 'Remove eval(). Dynamic code execution is almost always avoidable and is a severe security risk.';
    case 'HARDCODED_PASSWORD':
      return 'Remove hardcoded passwords. Use environment variables and Laravel config() helpers.';
    case 'HARDCODED_API_KEY':
      return 'Move API keys to .env and reference them via config(). Never commit credentials to source control.';
    case 'HARDCODED_SECRET':
      return 'Move secrets/tokens to .env. Rotate any credentials that may have been exposed in version control.';
    case 'WEAK_HASH_MD5':
      return 'Do not use MD5 for security-sensitive hashing. Use Hash::make() (bcrypt) for passwords.';
    case 'WEAK_HASH_SHA1':
      return 'SHA1 is cryptographically broken for security purposes. Use Hash::make() or hash(\'sha256\', ...) at minimum.';
    case 'MASS_ASSIGNMENT_UNGUARDED':
      return 'Set explicit $fillable fields on the model. An empty $guarded array exposes all columns to mass assignment.';
    case 'PATH_TRAVERSAL_RISK':
      return 'Never pass user-controlled input directly to file functions. Validate and resolve paths against an allowlist.';
    case 'LFI_RISK':
      return 'Avoid dynamic includes with user input. Hardcode all include paths or use a strict allowlist.';
    // Blade scan
    case 'XSS_UNESCAPED_BLADE':
      return 'Replace {!! !!} with {{ }} to enable Blade\'s automatic HTML escaping, unless the content is explicitly trusted and sanitised.';
    // Route audit
    case 'ADMIN_ROUTE_NO_AUTH':
      return 'Protect admin routes with auth middleware. Use Route::middleware([\'auth\']) or a dedicated gate/policy.';
    case 'API_ROUTE_NO_AUTH':
      return 'Protect API routes with auth:sanctum or auth:api middleware to prevent unauthorised access.';
    case 'LOGIN_NO_THROTTLE':
      return 'Add throttle middleware to login/register routes (e.g. throttle:5,1) to prevent brute-force attacks.';
    case 'CSRF_EXCEPTION_WILDCARD':
      return 'Avoid wildcard patterns in VerifyCsrfToken::$except. Exclude only specific, explicitly safe routes.';
    // Attack simulation
    case 'SQL_INJECTION_PROBE':
      return 'The login endpoint appears to be vulnerable to SQL injection. Review controller query logic and enforce parameterised queries.';
    case 'XSS_REFLECTED_PROBE':
      return 'Reflected XSS was detected. Ensure all user input is escaped before being rendered in HTML responses.';
    case 'AUTH_BYPASS_PROBE':
      return 'A protected endpoint returned a successful response without authentication credentials. Verify middleware coverage.';
    case 'RATE_LIMIT_MISSING':
      return 'The endpoint did not enforce rate limiting. Add throttle middleware to prevent brute-force and DoS attacks.';
    case 'CSRF_NOT_ENFORCED':
      return 'The endpoint accepted a state-changing POST request without a valid CSRF token. Ensure VerifyCsrfToken middleware is active.';
    case 'ERROR_DISCLOSURE':
      return 'The application is leaking sensitive framework or stack-trace information in error responses. Set APP_DEBUG=false in production.';
    default:
      return 'Review this code path and apply secure coding controls.';
  }
}

// ---------------------------------------------------------------------------
// project_info
// ---------------------------------------------------------------------------

export async function projectInfoTool(
  targetPath: string,
  config: McpConfig,
): Promise<Record<string, unknown>> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);

  const composerPath = path.join(safePath, 'composer.json');
  let composer: any = null;

  try {
    composer = JSON.parse(await fs.readFile(composerPath, 'utf8'));
  } catch {
    composer = null;
  }

  const isLaravel = Boolean(composer?.require?.['laravel/framework']);

  return {
    project: {
      path: safePath,
      name: composer?.name ?? path.basename(safePath),
      isLaravel,
      phpVersionConstraint: composer?.require?.php ?? null,
      laravelConstraint: composer?.require?.['laravel/framework'] ?? null,
    },
    metadata: {
      engine: 'Laraguard MCP',
      version: '3.0.0',
      timestamp: new Date().toISOString(),
      durationMs: Math.round(performance.now() - startedAt),
      basePaths: config.basePaths,
    },
  };
}

// ---------------------------------------------------------------------------
// config_audit
// ---------------------------------------------------------------------------

export async function configAuditTool(
  targetPath: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const findings: Finding[] = [];

  // --- .env checks ---
  const envPath = path.join(safePath, '.env');
  try {
    const envContent = await fs.readFile(envPath, 'utf8');

    if (/^APP_DEBUG\s*=\s*true$/im.test(envContent)) {
      findings.push({
        severity: 'high',
        type: 'DEBUG_ENABLED',
        title: 'APP_DEBUG is enabled',
        file: '.env',
        line: safeLine(envContent, /^APP_DEBUG\s*=\s*true$/im),
        evidence: 'APP_DEBUG=true',
        recommendation: 'Set APP_DEBUG=false in production.',
      });
    }

    if (/^APP_ENV\s*=\s*local$/im.test(envContent)) {
      findings.push({
        severity: 'medium',
        type: 'LOCAL_ENV_CONFIG',
        title: 'APP_ENV is set to local',
        file: '.env',
        line: safeLine(envContent, /^APP_ENV\s*=\s*local$/im),
        evidence: 'APP_ENV=local',
        recommendation: 'Set APP_ENV=production in production environments.',
      });
    }

    if (/^SESSION_SECURE_COOKIE\s*=\s*false$/im.test(envContent)) {
      findings.push({
        severity: 'medium',
        type: 'INSECURE_SESSION_COOKIE',
        title: 'SESSION_SECURE_COOKIE is disabled',
        file: '.env',
        line: safeLine(envContent, /^SESSION_SECURE_COOKIE\s*=\s*false$/im),
        evidence: 'SESSION_SECURE_COOKIE=false',
        recommendation: 'Set SESSION_SECURE_COOKIE=true in HTTPS environments.',
      });
    }

    if (/^APP_KEY\s*=\s*$/im.test(envContent)) {
      findings.push({
        severity: 'critical',
        type: 'MISSING_APP_KEY',
        title: 'APP_KEY is empty',
        file: '.env',
        line: safeLine(envContent, /^APP_KEY\s*=\s*$/im),
        evidence: 'APP_KEY=',
        recommendation: 'Run php artisan key:generate. An empty APP_KEY disables encryption.',
      });
    }
  } catch {
    findings.push({
      severity: 'low',
      type: 'ENV_FILE_MISSING',
      title: '.env file not found',
      file: '.env',
      line: null,
      evidence: '.env was not found in project root.',
      recommendation: 'Ensure a secure environment configuration file exists outside source control.',
    });
  }

  // --- config/cors.php checks ---
  try {
    const corsPath = path.join(safePath, 'config', 'cors.php');
    const corsContent = await fs.readFile(corsPath, 'utf8');

    if (corsContent.includes("'*'")) {
      findings.push({
        severity: 'medium',
        type: 'PERMISSIVE_CORS',
        title: 'CORS may allow all origins',
        file: 'config/cors.php',
        line: null,
        evidence: 'Wildcard CORS origin detected.',
        recommendation: 'Restrict CORS allowed_origins to trusted domains only.',
      });
    }
  } catch {
    // ignore missing cors.php
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_CONFIG_ISSUES_FOUND',
      title: 'No obvious high-risk configuration issues found',
      file: 'config',
      line: null,
      evidence: 'Configuration checks completed.',
      recommendation: 'Keep hardening checks in CI and baseline your environment values.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

// ---------------------------------------------------------------------------
// code_scan  (Tier 1 expanded rules)
// ---------------------------------------------------------------------------

export async function codeScanTool(
  targetPath: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const files = await readPhpFiles(safePath, config);

  const rules: Array<{ pattern: RegExp; severity: Severity; type: string; title: string }> = [
    // --- original rules ---
    { pattern: /->whereRaw\s*\(/, severity: 'high', type: 'SQL_INJECTION', title: 'Potential SQL injection via whereRaw' },
    { pattern: /DB::raw\s*\(/, severity: 'medium', type: 'RAW_SQL_USAGE', title: 'Raw SQL usage detected' },
    { pattern: /unserialize\s*\(/, severity: 'critical', type: 'UNSAFE_UNSERIALIZE', title: 'Unsafe unserialize usage' },
    { pattern: /shell_exec\s*\(/, severity: 'critical', type: 'RCE_RISK', title: 'shell_exec usage detected' },
    { pattern: /\beval\s*\(/, severity: 'critical', type: 'EVAL_USAGE', title: 'eval() usage detected' },

    // --- Tier 1: hardcoded credentials ---
    {
      pattern: /(?:password|passwd|pwd)\s*=\s*['"][^'"]{4,}['"]/i,
      severity: 'critical',
      type: 'HARDCODED_PASSWORD',
      title: 'Hardcoded password detected',
    },
    {
      pattern: /(?:api_?key|apikey|access_?key)\s*=\s*['"][^'"]{8,}['"]/i,
      severity: 'critical',
      type: 'HARDCODED_API_KEY',
      title: 'Hardcoded API key detected',
    },
    {
      pattern: /(?:secret|token)\s*=\s*['"][A-Za-z0-9\/+]{16,}['"]/i,
      severity: 'high',
      type: 'HARDCODED_SECRET',
      title: 'Potential hardcoded secret or token detected',
    },

    // --- Tier 1: weak cryptography ---
    {
      pattern: /\bmd5\s*\(/,
      severity: 'high',
      type: 'WEAK_HASH_MD5',
      title: 'MD5 hash function used — not safe for security-sensitive operations',
    },
    {
      pattern: /\bsha1\s*\(/,
      severity: 'medium',
      type: 'WEAK_HASH_SHA1',
      title: 'SHA1 hash function used — cryptographically weak',
    },

    // --- Tier 1: mass assignment ---
    {
      pattern: /protected\s+\$guarded\s*=\s*\[\s*\]/,
      severity: 'high',
      type: 'MASS_ASSIGNMENT_UNGUARDED',
      title: 'Model has $guarded = [] — all columns exposed to mass assignment',
    },

    // --- Tier 1: path traversal / LFI ---
    {
      pattern: /file_get_contents\s*\(\s*\$(?:request|_GET|_POST|_REQUEST)/,
      severity: 'critical',
      type: 'PATH_TRAVERSAL_RISK',
      title: 'Potential path traversal: file_get_contents() with user-controlled input',
    },
    {
      pattern: /\b(?:include|require)(?:_once)?\s*\(\s*\$(?:request|_GET|_POST|_REQUEST)/,
      severity: 'critical',
      type: 'LFI_RISK',
      title: 'Local File Inclusion risk: include/require with user-controlled input',
    },

    // --- Tier 1: additional dangerous functions ---
    {
      pattern: /\bexec\s*\(/,
      severity: 'critical',
      type: 'RCE_RISK',
      title: 'exec() usage detected — potential Remote Code Execution',
    },
    {
      pattern: /\bsystem\s*\(/,
      severity: 'critical',
      type: 'RCE_RISK',
      title: 'system() usage detected — potential Remote Code Execution',
    },
    {
      pattern: /\bpassthru\s*\(/,
      severity: 'critical',
      type: 'RCE_RISK',
      title: 'passthru() usage detected — potential Remote Code Execution',
    },
    {
      pattern: /\bproc_open\s*\(/,
      severity: 'high',
      type: 'RCE_RISK',
      title: 'proc_open() usage detected — potential command execution',
    },
  ];

  const findings: Finding[] = [];

  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      for (const rule of rules) {
        if (rule.pattern.test(lines[i])) {
          findings.push({
            severity: rule.severity,
            type: rule.type,
            title: rule.title,
            file: file.relativePath,
            line: i + 1,
            evidence: lines[i].trim(),
            recommendation: recommendationForType(rule.type),
          });
        }
      }
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_CODE_PATTERNS_FOUND',
      title: 'No risky patterns found by static rule set',
      file: 'n/a',
      line: null,
      evidence: 'Static scan completed without matches.',
      recommendation: 'Complement with SAST/DAST tools and manual code review.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

// ---------------------------------------------------------------------------
// blade_scan  (NEW — Tier 1: XSS detection in Blade templates)
// ---------------------------------------------------------------------------

export async function bladeScanTool(
  targetPath: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const files = await readBladeFiles(safePath, config);
  const findings: Finding[] = [];

  if (files.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_BLADE_FILES',
      title: 'No Blade templates found',
      file: 'resources/views/',
      line: null,
      evidence: 'resources/views/ directory is missing or empty.',
      recommendation: 'Nothing to scan — this may not be a standard Laravel project structure.',
    });
    return buildReport(safePath, findings, startedAt);
  }

  const bladeRules: Array<{ pattern: RegExp; severity: Severity; type: string; title: string }> = [
    {
      // {!! $variable !!} — unescaped variable output
      pattern: /\{!!\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*/,
      severity: 'high',
      type: 'XSS_UNESCAPED_BLADE',
      title: 'Unescaped variable output in Blade template — potential XSS',
    },
    {
      // {!! request()  or {!! Input::  etc.
      pattern: /\{!!\s*(?:request\(|Input::|old\()/,
      severity: 'critical',
      type: 'XSS_UNESCAPED_BLADE',
      title: 'Unescaped user input rendered directly — high-confidence XSS risk',
    },
    {
      // echo without escaping in PHP blocks inside blade
      pattern: /echo\s+\$(?:request|_GET|_POST|_REQUEST)/,
      severity: 'high',
      type: 'XSS_UNESCAPED_BLADE',
      title: 'Raw PHP echo with user-controlled variable in Blade template',
    },
  ];

  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      for (const rule of bladeRules) {
        if (rule.pattern.test(lines[i])) {
          findings.push({
            severity: rule.severity,
            type: rule.type,
            title: rule.title,
            file: file.relativePath,
            line: i + 1,
            evidence: lines[i].trim(),
            recommendation: recommendationForType(rule.type),
          });
        }
      }
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_BLADE_XSS_FOUND',
      title: 'No unescaped output patterns detected in Blade templates',
      file: 'resources/views/',
      line: null,
      evidence: `Scanned ${files.length} Blade template file(s).`,
      recommendation: 'Continue using {{ }} (escaped) output. Audit {!! !!} usages manually if they exist.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

// ---------------------------------------------------------------------------
// route_audit  (NEW — Tier 2: Laravel route and middleware analysis)
// ---------------------------------------------------------------------------

export async function routeAuditTool(
  targetPath: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const findings: Finding[] = [];

  const candidateFiles = [
    'routes/web.php',
    'routes/api.php',
    'routes/auth.php',
    'app/Http/Middleware/VerifyCsrfToken.php',
    'app/Http/Kernel.php',
  ];

  const files = await readSpecificFiles(safePath, candidateFiles, config);

  if (files.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_ROUTE_FILES',
      title: 'No Laravel route files found',
      file: 'routes/',
      line: null,
      evidence: 'routes/web.php and routes/api.php were not found.',
      recommendation: 'Ensure this is a standard Laravel project layout.',
    });
    return buildReport(safePath, findings, startedAt);
  }

  for (const file of files) {
    const lines = file.content.split(/\r?\n/);

    // ---- CSRF exception wildcard ----
    if (file.relativePath.includes('VerifyCsrfToken')) {
      const exceptBlockMatch = file.content.match(/\$except\s*=\s*\[([\s\S]*?)\]/);
      if (exceptBlockMatch) {
        const exceptBlock = exceptBlockMatch[1];
        const wildcardPatterns = [/'\*'/, /"\*"/, /'[^']*\*[^']*'/, /"[^"]*\*[^"]*"/];
        for (const wp of wildcardPatterns) {
          if (wp.test(exceptBlock)) {
            findings.push({
              severity: 'high',
              type: 'CSRF_EXCEPTION_WILDCARD',
              title: 'Wildcard pattern found in VerifyCsrfToken::$except',
              file: file.relativePath,
              line: null,
              evidence: exceptBlock.trim().slice(0, 120),
              recommendation: recommendationForType('CSRF_EXCEPTION_WILDCARD'),
            });
            break;
          }
        }
      }
    }

    // ---- Route-level checks (web.php / api.php) ----
    if (file.relativePath.startsWith('routes/')) {
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];

        // Admin / sensitive routes without auth middleware
        const isAdminRoute =
          /Route::[a-z]+\s*\(\s*['"][^'"]*(?:admin|dashboard|management|backoffice|cms|staff)[^'"]*['"]/i.test(line);

        if (isAdminRoute) {
          // Look for middleware in the same line or next 3 lines
          const context = lines.slice(i, Math.min(i + 4, lines.length)).join(' ');
          const hasAuth = /middleware\s*\(\s*['"]\s*auth/i.test(context)
            || /->middleware\(['"]auth/i.test(context);

          if (!hasAuth) {
            findings.push({
              severity: 'critical',
              type: 'ADMIN_ROUTE_NO_AUTH',
              title: 'Admin/sensitive route registered without visible auth middleware',
              file: file.relativePath,
              line: i + 1,
              evidence: line.trim(),
              recommendation: recommendationForType('ADMIN_ROUTE_NO_AUTH'),
            });
          }
        }

        // API routes without auth in api.php
        if (file.relativePath === 'routes/api.php') {
          const isRoute = /Route::[a-z]+\s*\(\s*['"]/.test(line);
          if (isRoute) {
            const context = lines.slice(Math.max(0, i - 5), Math.min(i + 3, lines.length)).join(' ');
            const hasAuth = /middleware\s*\(\s*['"](auth|sanctum|api)/i.test(context)
              || /auth:sanctum|auth:api/i.test(context)
              || /->middleware/i.test(context);

            if (!hasAuth) {
              findings.push({
                severity: 'high',
                type: 'API_ROUTE_NO_AUTH',
                title: 'API route registered without visible authentication middleware',
                file: file.relativePath,
                line: i + 1,
                evidence: line.trim(),
                recommendation: recommendationForType('API_ROUTE_NO_AUTH'),
              });
            }
          }
        }

        // Login / register / password routes without throttle
        const isAuthRoute =
          /Route::[a-z]+\s*\(\s*['"][^'"]*(?:login|register|password\/reset|password\/email)[^'"]*['"]/i.test(line);

        if (isAuthRoute) {
          const context = lines.slice(i, Math.min(i + 4, lines.length)).join(' ');
          const hasThrottle = /throttle/i.test(context);

          if (!hasThrottle) {
            findings.push({
              severity: 'medium',
              type: 'LOGIN_NO_THROTTLE',
              title: 'Authentication route missing throttle middleware',
              file: file.relativePath,
              line: i + 1,
              evidence: line.trim(),
              recommendation: recommendationForType('LOGIN_NO_THROTTLE'),
            });
          }
        }
      }
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_ROUTE_ISSUES_FOUND',
      title: 'No obvious route or middleware issues detected',
      file: 'routes/',
      line: null,
      evidence: 'Route audit completed.',
      recommendation: 'Review route middleware coverage manually and enforce auth policies at the controller/policy layer.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

// ---------------------------------------------------------------------------
// dependency_audit  (IMPROVED — Tier 5: OSV.dev advisory feed)
// ---------------------------------------------------------------------------

interface OsvVulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{ ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }> }>;
}

interface OsvBatchResult {
  vulns?: OsvVulnerability[];
}

function mapCvssToSeverity(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

async function queryOsvBatch(
  packages: Array<{ name: string; version: string }>,
): Promise<OsvBatchResult[]> {
  const body = {
    queries: packages.map((pkg) => ({
      version: pkg.version,
      package: { name: pkg.name, ecosystem: 'Packagist' },
    })),
  };

  const response = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    throw new Error(`OSV API returned HTTP ${response.status}`);
  }

  const data = (await response.json()) as { results?: OsvBatchResult[] };
  return data.results ?? [];
}

export async function dependencyAuditTool(
  targetPath: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const findings: Finding[] = [];

  const lockPath = path.join(safePath, 'composer.lock');

  // Check composer.lock exists
  let lockContent: string;
  try {
    lockContent = await fs.readFile(lockPath, 'utf8');
  } catch {
    findings.push({
      severity: 'info',
      type: 'NO_COMPOSER_LOCK',
      title: 'composer.lock not found',
      file: 'composer.lock',
      line: null,
      evidence: 'Dependency audit skipped — composer.lock was not found.',
      recommendation: 'Run composer install and commit the lock file.',
    });
    return buildReport(safePath, findings, startedAt);
  }

  // Parse packages
  let lockData: { packages?: Array<{ name: string; version: string }> };
  try {
    lockData = JSON.parse(lockContent);
  } catch {
    findings.push({
      severity: 'low',
      type: 'LOCK_PARSE_ERROR',
      title: 'composer.lock could not be parsed',
      file: 'composer.lock',
      line: null,
      evidence: 'JSON parse failed.',
      recommendation: 'Regenerate composer.lock by running composer install.',
    });
    return buildReport(safePath, findings, startedAt);
  }

  const packages = (lockData.packages ?? []).map((p) => ({
    name: p.name,
    version: p.version.replace(/^v/, ''),
  }));

  if (packages.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_PACKAGES',
      title: 'No packages found in composer.lock',
      file: 'composer.lock',
      line: null,
      evidence: 'packages array is empty.',
      recommendation: 'Run composer install to populate dependencies.',
    });
    return buildReport(safePath, findings, startedAt);
  }

  // Query OSV.dev in batches of 50
  const BATCH_SIZE = 50;
  const osvResults: OsvBatchResult[] = [];

  try {
    for (let i = 0; i < packages.length; i += BATCH_SIZE) {
      const batch = packages.slice(i, i + BATCH_SIZE);
      const results = await queryOsvBatch(batch);
      osvResults.push(...results);
    }
  } catch (err) {
    findings.push({
      severity: 'info',
      type: 'OSV_API_UNAVAILABLE',
      title: 'OSV advisory feed could not be reached',
      file: 'composer.lock',
      line: null,
      evidence: String(err),
      recommendation: 'Retry with network access, or run composer audit locally as a fallback.',
    });
    return buildReport(safePath, findings, startedAt);
  }

  // Map OSV results to findings
  let vulnCount = 0;

  for (let i = 0; i < packages.length; i += 1) {
    const pkg = packages[i];
    const result = osvResults[i];
    const vulns = result?.vulns ?? [];

    for (const vuln of vulns) {
      vulnCount += 1;

      // Determine severity from CVSS score if available
      let severity: Severity = 'medium';
      for (const s of vuln.severity ?? []) {
        const score = parseFloat(s.score);
        if (!Number.isNaN(score)) {
          severity = mapCvssToSeverity(score);
          break;
        }
      }

      // Extract fix version
      let fixVersion = 'unknown — check advisory';
      for (const affected of vuln.affected ?? []) {
        for (const range of affected.ranges ?? []) {
          for (const event of range.events ?? []) {
            if (event.fixed) {
              fixVersion = event.fixed;
              break;
            }
          }
        }
      }

      findings.push({
        severity,
        type: 'CVE_FOUND',
        title: `${vuln.id}: ${vuln.summary ?? 'Known vulnerability'}`,
        file: 'composer.lock',
        line: null,
        evidence: `${pkg.name}@${pkg.version} — fix: ${fixVersion}`,
        recommendation: `Update ${pkg.name} to >= ${fixVersion}. See https://osv.dev/vulnerability/${vuln.id}`,
      });
    }
  }

  if (vulnCount === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_CVE_FOUND',
      title: `No known vulnerabilities found across ${packages.length} dependency package(s)`,
      file: 'composer.lock',
      line: null,
      evidence: `Queried OSV.dev for ${packages.length} packages. No advisories matched.`,
      recommendation: 'Re-run dependency audit regularly and after each composer update.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

// ---------------------------------------------------------------------------
// attack_simulate  (NEW — Tier 4: live HTTP probe engine)
// ---------------------------------------------------------------------------

interface ProbeResult {
  probe: string;
  url: string;
  status: number | null;
  durationMs: number;
  finding: Finding | null;
}

async function httpProbe(
  url: string,
  options: RequestInit,
  timeoutMs = 8000,
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  const response = await fetch(url, {
    ...options,
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
  });

  const body = await response.text().catch(() => '');
  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => { headers[k] = v; });

  return { status: response.status, body, headers };
}

export async function attackSimulateTool(
  targetPath: string,
  baseUrl: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const findings: Finding[] = [];
  const normalizedBaseUrl = baseUrl.replace(/\/+$/, '');

  // Helper to record probe metadata
  const probeResults: ProbeResult[] = [];

  async function runProbe(
    name: string,
    url: string,
    options: RequestInit,
    evaluate: (res: { status: number; body: string; headers: Record<string, string> }) => Finding | null,
  ): Promise<void> {
    const t = performance.now();
    try {
      const res = await httpProbe(url, options);
      const finding = evaluate(res);
      probeResults.push({ probe: name, url, status: res.status, durationMs: Math.round(performance.now() - t), finding });
      if (finding) findings.push(finding);
    } catch {
      probeResults.push({ probe: name, url, status: null, durationMs: Math.round(performance.now() - t), finding: null });
    }
  }

  // ---- Probe 1: Error/debug information disclosure ----
  await runProbe(
    'error_disclosure',
    `${normalizedBaseUrl}/__laraguard_nonexistent_route_probe__`,
    { method: 'GET' },
    ({ status, body }) => {
      const leaksFramework = /laravel|illuminate|whoops|symfony|stack trace/i.test(body);
      if (leaksFramework && status !== 404) {
        return {
          severity: 'high',
          type: 'ERROR_DISCLOSURE',
          title: 'Framework/stack-trace information leaked in error response',
          file: 'n/a (HTTP probe)',
          line: null,
          evidence: `HTTP ${status} — body contains Laravel/framework identifiers`,
          recommendation: recommendationForType('ERROR_DISCLOSURE'),
        };
      }
      return null;
    },
  );

  // ---- Probe 2: SQL injection on login endpoint ----
  await runProbe(
    'sql_injection_login',
    `${normalizedBaseUrl}/login`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-XSRF-TOKEN': 'probe' },
      body: "email=' OR '1'='1'--&password=laraguard_probe",
    },
    ({ status, body }) => {
      const sqlError = /sql|syntax error|pdo|query|mysql|sqlite|postgresql/i.test(body);
      // 200 with SQL error keywords = likely vulnerable; 500 = may leak DB info
      if (sqlError || (status === 500 && /error|exception/i.test(body))) {
        return {
          severity: 'critical',
          type: 'SQL_INJECTION_PROBE',
          title: 'Possible SQL injection vulnerability on /login endpoint',
          file: 'n/a (HTTP probe)',
          line: null,
          evidence: `HTTP ${status} — response contains SQL-related error strings`,
          recommendation: recommendationForType('SQL_INJECTION_PROBE'),
        };
      }
      return null;
    },
  );

  // ---- Probe 3: Reflected XSS ----
  const xssPayload = '<script>alert("laraguard-xss-probe")</script>';
  await runProbe(
    'reflected_xss',
    `${normalizedBaseUrl}/search?q=${encodeURIComponent(xssPayload)}`,
    { method: 'GET' },
    ({ status, body }) => {
      if (status < 500 && body.includes(xssPayload)) {
        return {
          severity: 'critical',
          type: 'XSS_REFLECTED_PROBE',
          title: 'Reflected XSS — unescaped input returned in response',
          file: 'n/a (HTTP probe)',
          line: null,
          evidence: `Payload "${xssPayload}" was reflected unescaped in HTTP ${status} response`,
          recommendation: recommendationForType('XSS_REFLECTED_PROBE'),
        };
      }
      return null;
    },
  );

  // ---- Probe 4: CSRF not enforced ----
  await runProbe(
    'csrf_not_enforced',
    `${normalizedBaseUrl}/login`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      // No CSRF token — deliberately omitted
      body: 'email=laraguard@probe.test&password=laraguard_probe',
    },
    ({ status, body }) => {
      // 419 = CSRF token mismatch (expected/good). 200 or 302 without CSRF = bad.
      const csrfEnforced = status === 419 || /csrf|token mismatch/i.test(body);
      if (!csrfEnforced && (status === 200 || status === 302 || status === 422)) {
        return {
          severity: 'high',
          type: 'CSRF_NOT_ENFORCED',
          title: 'CSRF protection does not appear to be enforced on POST /login',
          file: 'n/a (HTTP probe)',
          line: null,
          evidence: `POST /login without CSRF token returned HTTP ${status} (expected 419)`,
          recommendation: recommendationForType('CSRF_NOT_ENFORCED'),
        };
      }
      return null;
    },
  );

  // ---- Probe 5: Auth bypass on protected API route ----
  await runProbe(
    'auth_bypass',
    `${normalizedBaseUrl}/api/user`,
    { method: 'GET', headers: { 'Accept': 'application/json' } },
    ({ status, body }) => {
      // 200 without any auth header = likely exposed
      const isExposed = status === 200 && body.length > 0 && !/<html/i.test(body);
      if (isExposed) {
        return {
          severity: 'critical',
          type: 'AUTH_BYPASS_PROBE',
          title: 'GET /api/user returned data without authentication credentials',
          file: 'n/a (HTTP probe)',
          line: null,
          evidence: `HTTP 200 returned ${body.length} bytes without Authorization header`,
          recommendation: recommendationForType('AUTH_BYPASS_PROBE'),
        };
      }
      return null;
    },
  );

  // ---- Probe 6: Rate limiting on login ----
  {
    const rateT = performance.now();
    let lastStatus = 0;
    let throttled = false;
    try {
      const attempts = Array.from({ length: 10 }, (_, i) =>
        httpProbe(`${normalizedBaseUrl}/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `email=probe${i}@laraguard.test&password=wrong_password_probe`,
        }, 5000),
      );
      const results = await Promise.all(attempts);
      lastStatus = results[results.length - 1]?.status ?? 0;
      throttled = results.some((r) => r.status === 429);
    } catch { /* ignore */ }

    const finding: Finding | null = throttled ? null : {
      severity: 'medium',
      type: 'RATE_LIMIT_MISSING',
      title: 'Login endpoint does not appear to enforce rate limiting',
      file: 'n/a (HTTP probe)',
      line: null,
      evidence: `10 rapid POST requests to /login — last response: HTTP ${lastStatus} (expected 429 on at least one)`,
      recommendation: recommendationForType('RATE_LIMIT_MISSING'),
    };

    probeResults.push({
      probe: 'rate_limit',
      url: `${normalizedBaseUrl}/login`,
      status: lastStatus,
      durationMs: Math.round(performance.now() - rateT),
      finding,
    });
    if (finding) findings.push(finding);
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_ATTACK_PROBES_TRIGGERED',
      title: 'No vulnerabilities detected by active HTTP probes',
      file: 'n/a (HTTP probe)',
      line: null,
      evidence: `${probeResults.length} probes executed against ${normalizedBaseUrl}`,
      recommendation: 'Continue manual penetration testing and complement with a dedicated DAST tool (OWASP ZAP, Burp Suite).',
    });
  }

  const report = buildReport(safePath, findings, startedAt);

  // Attach probe summary to metadata
  (report.metadata as any).probes = probeResults.map((p) => ({
    probe: p.probe,
    url: p.url,
    status: p.status,
    durationMs: p.durationMs,
    triggered: p.finding !== null,
  }));

  return report;
}

// ---------------------------------------------------------------------------
// full_audit  (UPDATED — includes blade_scan, route_audit, OSV-backed deps)
// ---------------------------------------------------------------------------

export async function fullAuditTool(
  targetPath: string,
  config: McpConfig,
): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);

  const [deps, conf, code, blade, routes] = await Promise.all([
    dependencyAuditTool(safePath, config),
    configAuditTool(safePath, config),
    codeScanTool(safePath, config),
    bladeScanTool(safePath, config),
    routeAuditTool(safePath, config),
  ]);

  const findings = [
    ...deps.findings,
    ...conf.findings,
    ...code.findings,
    ...blade.findings,
    ...routes.findings,
  ];

  return buildReport(safePath, findings, startedAt, {
    dependency_audit: summarizeFindings(deps.findings),
    config_audit: summarizeFindings(conf.findings),
    code_scan: summarizeFindings(code.findings),
    blade_scan: summarizeFindings(blade.findings),
    route_audit: summarizeFindings(routes.findings),
  });
}
