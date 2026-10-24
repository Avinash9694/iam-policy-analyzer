import { scoreFindings, verdictFor } from '../scoring';
import type { Finding, Severity } from '../types';
import { ALLOW_ALL, allFindings } from '@/test/helpers';
import { SAMPLES } from '@/data/samples';
import { analyzePolicyText } from '../analyze';

function fake(severity: Severity, mitigated = false): Finding {
  return {
    id: `${severity}-${Math.random()}`,
    ruleId: 'x',
    severity,
    title: '',
    message: '',
    explanation: '',
    remediation: '',
    references: [],
    statementIndex: 0,
    sid: undefined,
    path: '',
    span: { startLine: 1, endLine: 1 },
    fix: undefined,
    actions: [],
    mitigatedBy: mitigated ? { statementIndex: 1, sid: undefined, reason: '' } : undefined,
  };
}

describe('scoring', () => {
  it('scores an empty list as clean', () => {
    expect(scoreFindings([])).toMatchObject({
      score: 0,
      verdict: 'clean',
      label: 'No issues found',
    });
  });

  it('applies severity floors and diminishing returns', () => {
    expect(scoreFindings([fake('critical')]).score).toBeGreaterThanOrEqual(75);
    expect(scoreFindings([fake('high')]).score).toBeGreaterThanOrEqual(40);
    expect(scoreFindings([fake('medium')]).score).toBeGreaterThanOrEqual(15);
    expect(scoreFindings([fake('low')]).verdict).toBe('low');
    expect(scoreFindings([fake('info')]).score).toBe(0);
    const three = scoreFindings([fake('critical'), fake('critical'), fake('critical')]).score;
    const six = scoreFindings(Array.from({ length: 6 }, () => fake('critical'))).score;
    expect(six).toBeGreaterThan(three);
    expect(six).toBeLessThanOrEqual(100);
  });

  it('excludes mitigated findings from the score and counts them separately', () => {
    const result = scoreFindings([fake('critical', true), fake('low')]);
    expect(result).toMatchObject({ mitigated: 1, counts: { critical: 0, low: 1 } });
    expect(result.verdict).toBe('low');
  });

  it('maps scores to verdicts at the documented thresholds', () => {
    expect(verdictFor(0)).toBe('clean');
    expect(verdictFor(19)).toBe('low');
    expect(verdictFor(20)).toBe('moderate');
    expect(verdictFor(44)).toBe('moderate');
    expect(verdictFor(45)).toBe('high');
    expect(verdictFor(75)).toBe('critical');
  });

  it('rates the full-admin policy as critical and the least-privilege sample as clean', () => {
    expect(scoreFindings(allFindings(ALLOW_ALL)).verdict).toBe('critical');
    const clean = analyzePolicyText(SAMPLES.find((s) => s.id === 'least-privilege')!.text);
    expect(clean.ok && clean.result.score).toMatchObject({ score: 0, verdict: 'clean' });
  });

  it('every bundled sample parses and the risky ones score above zero', () => {
    for (const sample of SAMPLES) {
      const result = analyzePolicyText(sample.text);
      expect(result.ok, sample.id).toBe(true);
      if (!result.ok) continue;
      if (sample.id !== 'least-privilege' && sample.id !== 'mitigated') {
        expect(result.result.score.score, sample.id).toBeGreaterThan(0);
      }
    }
  });
});
