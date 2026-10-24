import type { RiskScore as RiskScoreModel, Verdict } from '@/engine';

const VERDICT_CLASS: Record<Verdict, string> = {
  clean: 'text-sev-mitigated',
  low: 'text-sev-low',
  moderate: 'text-sev-medium',
  high: 'text-sev-high',
  critical: 'text-sev-critical',
};

const VERDICT_BAR_CLASS: Record<Verdict, string> = {
  clean: 'bg-sev-mitigated',
  low: 'bg-sev-low',
  moderate: 'bg-sev-medium',
  high: 'bg-sev-high',
  critical: 'bg-sev-critical',
};

interface Props {
  score: RiskScoreModel;
  policyKind: 'identity' | 'resource';
  statementCount: number;
}

export function RiskScore({ score, policyKind, statementCount }: Props) {
  const active = Object.values(score.counts).reduce((a, b) => a + b, 0);
  return (
    <div className="flex items-center gap-4 px-4 py-4">
      <div
        className="relative grid size-16 shrink-0 place-items-center rounded-full border-4 border-surface-3"
        role="img"
        aria-label={`Risk score ${score.score} out of 100`}
      >
        <svg className="absolute inset-[-4px]" viewBox="0 0 36 36" aria-hidden="true">
          <circle
            cx="18"
            cy="18"
            r="16"
            fill="none"
            strokeWidth="4"
            className={`${VERDICT_CLASS[score.verdict]} [stroke:currentColor]`}
            strokeDasharray={`${(score.score / 100) * 100.5} 100.5`}
            strokeLinecap="round"
            transform="rotate(-90 18 18)"
          />
        </svg>
        <span className="font-mono text-xl font-semibold tabular-nums">{score.score}</span>
      </div>
      <div className="min-w-0">
        <p className={`text-lg font-semibold leading-tight ${VERDICT_CLASS[score.verdict]}`}>
          {score.verdict === 'clean' && score.mitigated > 0 ? 'No active issues' : score.label}
        </p>
        <p className="mt-0.5 text-sm text-fg-muted">
          {active} {active === 1 ? 'finding' : 'findings'}
          {score.mitigated > 0 ? `, ${score.mitigated} mitigated by Deny` : ''} · {policyKind}{' '}
          policy · {statementCount} {statementCount === 1 ? 'statement' : 'statements'}
        </p>
        <div
          className="mt-2 h-1.5 w-40 max-w-full overflow-hidden rounded-full bg-surface-3"
          aria-hidden="true"
        >
          <div
            className={`h-full rounded-full transition-[width] duration-300 ${VERDICT_BAR_CLASS[score.verdict]}`}
            style={{ width: `${score.score}%` }}
          />
        </div>
      </div>
    </div>
  );
}
