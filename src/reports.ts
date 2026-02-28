import type { AuditReport, AuditSummary, Finding, Severity } from './types.js';

export function summarizeFindings(findings: Finding[]): AuditSummary {
  const summary: AuditSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    const key = finding.severity as Severity;
    if (summary[key] !== undefined) summary[key] += 1;
  }

  return summary;
}

export function buildReport(
  scannedPath: string,
  findings: Finding[],
  startedAt: number,
  sections?: Record<string, AuditSummary | null>,
): AuditReport {
  return {
    summary: summarizeFindings(findings),
    findings,
    metadata: {
      scannedPath,
      engine: 'Laraguard MCP',
      version: '2.0.0',
      timestamp: new Date().toISOString(),
      durationMs: Math.round(performance.now() - startedAt),
      sections,
    },
  };
}
