import { applyDenyMitigation } from './mitigation';
import { parsePolicy } from './parse';
import { RULES } from './rules';
import { scoreFindings, severityRank } from './scoring';
import type { AnalysisResult, Finding, ParseError, Policy } from './types';

export function runRules(policy: Policy): Finding[] {
  const findings = RULES.flatMap((rule) => rule.check({ policy }));
  const mitigated = applyDenyMitigation(findings, policy);
  return mitigated.sort((a, b) => {
    if (Boolean(a.mitigatedBy) !== Boolean(b.mitigatedBy)) return a.mitigatedBy ? 1 : -1;
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    return (a.statementIndex ?? -1) - (b.statementIndex ?? -1);
  });
}

export function analyzePolicy(policy: Policy, warnings: string[] = []): AnalysisResult {
  const findings = runRules(policy);
  return { policy, findings, score: scoreFindings(findings), warnings };
}

export type AnalyzeTextResult =
  { ok: true; result: AnalysisResult } | { ok: false; errors: ParseError[] };

export function analyzePolicyText(text: string): AnalyzeTextResult {
  const parsed = parsePolicy(text);
  if (!parsed.ok) return { ok: false, errors: parsed.errors };
  return { ok: true, result: analyzePolicy(parsed.policy, parsed.warnings) };
}
