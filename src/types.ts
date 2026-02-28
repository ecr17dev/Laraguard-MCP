export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: Severity;
  type: string;
  title: string;
  file: string;
  line: number | null;
  evidence: string;
  recommendation: string;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AuditMetadata {
  scannedPath: string;
  engine: string;
  version: string;
  timestamp: string;
  durationMs: number;
  sections?: Record<string, AuditSummary | null>;
}

export interface AuditReport {
  summary: AuditSummary;
  findings: Finding[];
  metadata: AuditMetadata;
}
