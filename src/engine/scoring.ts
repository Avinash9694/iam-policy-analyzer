import type { Finding, RiskScore, Severity, Verdict } from './types';
import { SEVERITIES } from './types';

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 4,
  info: 0,
};

const SEVERITY_FLOOR: Partial<Record<Severity, number>> = {
  critical: 75,
  high: 40,
  medium: 15,
  low: 5,
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  clean: 'No issues found',
  low: 'Low risk',
  moderate: 'Moderate risk',
  high: 'High risk',
  critical: 'Critical risk',
};

export function verdictFor(score: number): Verdict {
  if (score === 0) return 'clean';
  if (score < 20) return 'low';
  if (score < 45) return 'moderate';
  if (score < 75) return 'high';
  return 'critical';
}

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function scoreFindings(findings: readonly Finding[]): RiskScore {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let mitigated = 0;
  let raw = 0;
  for (const f of findings) {
    if (f.mitigatedBy) {
      mitigated += 1;
      continue;
    }
    counts[f.severity] += 1;
    raw += SEVERITY_WEIGHT[f.severity];
  }
  // Diminishing returns: the second critical matters less than the first.
  let score = raw === 0 ? 0 : Math.round(100 * (1 - Math.exp(-raw / 45)));
  for (const severity of SEVERITIES) {
    if (counts[severity] > 0) {
      score = Math.max(score, SEVERITY_FLOOR[severity] ?? 0);
      break;
    }
  }
  score = Math.min(100, score);
  const verdict = verdictFor(score);
  return { score, verdict, label: VERDICT_LABEL[verdict], counts, mitigated };
}
