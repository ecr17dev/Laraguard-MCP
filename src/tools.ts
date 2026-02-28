import fs from 'node:fs/promises';
import path from 'node:path';
import type { McpConfig } from './config.js';
import { readPhpFiles } from './files.js';
import { buildReport, summarizeFindings } from './reports.js';
import { ensureAllowedPath } from './security.js';
import type { AuditReport, Finding, Severity } from './types.js';

function safeLine(content: string, pattern: RegExp): number | null {
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if (pattern.test(lines[i])) return i + 1;
  }
  return null;
}

export async function projectInfoTool(targetPath: string, config: McpConfig): Promise<Record<string, unknown>> {
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
      version: '2.0.0',
      timestamp: new Date().toISOString(),
      durationMs: Math.round(performance.now() - startedAt),
      basePaths: config.basePaths,
    },
  };
}

export async function configAuditTool(targetPath: string, config: McpConfig): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const findings: Finding[] = [];

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
  } catch {
    findings.push({
      severity: 'low',
      type: 'ENV_FILE_MISSING',
      title: '.env file not found',
      file: '.env',
      line: null,
      evidence: '.env was not found in project root.',
      recommendation: 'Ensure secure environment configuration exists outside source control.',
    });
  }

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
        recommendation: 'Restrict CORS allowed origins to trusted domains.',
      });
    }
  } catch {
    // Ignore missing CORS config.
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'info',
      type: 'NO_CONFIG_ISSUES_FOUND',
      title: 'No obvious high-risk configuration issues found',
      file: 'config',
      line: null,
      evidence: 'Configuration checks completed.',
      recommendation: 'Keep hardening checks in CI and environment baselines.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

function recommendationForType(type: string): string {
  switch (type) {
    case 'SQL_INJECTION':
      return 'Avoid raw SQL with user input. Use parameter binding/query builder.';
    case 'UNSAFE_UNSERIALIZE':
      return 'Avoid unserialize on untrusted data.';
    case 'RCE_RISK':
    case 'EVAL_USAGE':
      return 'Avoid dynamic command/code execution or enforce strict allowlists.';
    default:
      return 'Review this code path and apply secure coding controls.';
  }
}

export async function codeScanTool(targetPath: string, config: McpConfig): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const files = await readPhpFiles(safePath, config);

  const rules: Array<{ pattern: RegExp; severity: Severity; type: string; title: string }> = [
    { pattern: /->whereRaw\s*\(/, severity: 'high', type: 'SQL_INJECTION', title: 'Potential SQL injection via whereRaw' },
    { pattern: /DB::raw\s*\(/, severity: 'medium', type: 'RAW_SQL_USAGE', title: 'Raw SQL usage detected' },
    { pattern: /unserialize\s*\(/, severity: 'critical', type: 'UNSAFE_UNSERIALIZE', title: 'Unsafe unserialize usage' },
    { pattern: /shell_exec\s*\(/, severity: 'critical', type: 'RCE_RISK', title: 'shell_exec usage detected' },
    { pattern: /eval\s*\(/, severity: 'critical', type: 'EVAL_USAGE', title: 'eval usage detected' },
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
      recommendation: 'Complement this with SAST/DAST and manual review.',
    });
  }

  return buildReport(safePath, findings, startedAt);
}

export async function dependencyAuditTool(targetPath: string, config: McpConfig): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);
  const findings: Finding[] = [];

  const lockPath = path.join(safePath, 'composer.lock');

  try {
    await fs.access(lockPath);
  } catch {
    findings.push({
      severity: 'info',
      type: 'NO_COMPOSER_LOCK',
      title: 'composer.lock not found',
      file: 'composer.lock',
      line: null,
      evidence: 'Dependency audit skipped because composer.lock was not found.',
      recommendation: 'Run composer install and retry.',
    });

    return buildReport(safePath, findings, startedAt);
  }

  findings.push({
    severity: 'info',
    type: 'DEPENDENCY_AUDIT_NOT_EXECUTED',
    title: 'Dependency advisory lookup not executed by default',
    file: 'composer.lock',
    line: null,
    evidence: 'Standalone MCP server does not spawn composer by default for security portability.',
    recommendation: 'Integrate an external advisory provider or run composer audit in CI.',
  });

  return buildReport(safePath, findings, startedAt);
}

export async function fullAuditTool(targetPath: string, config: McpConfig): Promise<AuditReport> {
  const startedAt = performance.now();
  const safePath = ensureAllowedPath(targetPath, config);

  const [deps, conf, code] = await Promise.all([
    dependencyAuditTool(safePath, config),
    configAuditTool(safePath, config),
    codeScanTool(safePath, config),
  ]);

  const findings = [...deps.findings, ...conf.findings, ...code.findings];

  return buildReport(safePath, findings, startedAt, {
    dependency_audit: summarizeFindings(deps.findings),
    config_audit: summarizeFindings(conf.findings),
    code_scan: summarizeFindings(code.findings),
  });
}
