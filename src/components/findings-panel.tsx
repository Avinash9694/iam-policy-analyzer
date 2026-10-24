import { useMemo, useState } from 'react';
import { SAMPLES } from '@/data/samples';
import { RULES, SEVERITIES } from '@/engine';
import type { Finding, ParseError, Severity } from '@/engine';
import type { AnalysisState } from '@/hooks/use-analysis';
import { FindingCard } from './finding-card';
import { AlertIcon, ShieldIcon } from './icons';
import { RiskScore } from './risk-score';
import { SeverityDot } from './severity-badge';
import { SEVERITY_LABEL } from './severity-meta';

interface Props {
  state: AnalysisState;
  selectedId: string | null;
  onSelect: (finding: Finding | null) => void;
  onPickSample: (text: string) => void;
}

function EmptyState({ onPickSample }: { onPickSample: (text: string) => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-6 py-12 text-center">
      <span className="grid size-14 place-items-center rounded-2xl bg-accent-soft text-accent">
        <ShieldIcon size={28} />
      </span>
      <h2 className="mt-4 text-lg font-semibold">Paste a policy to analyse it</h2>
      <p className="mt-2 max-w-md text-sm leading-relaxed text-fg-muted">
        Identity policies, bucket policies, trust policies — the analyser parses the JSON,
        normalises every statement and runs {RULES.length} rules covering wildcards,
        privilege-escalation paths, public principals, missing MFA and TLS conditions, data-read
        actions on <code className="font-mono">*</code>, unknown actions and malformed conditions.
        Explicit Deny statements are used to mark findings they neutralise.
      </p>
      <p className="mt-4 text-xs font-medium uppercase tracking-wide text-fg-subtle">
        Or try a sample
      </p>
      <ul className="mt-2 flex flex-wrap justify-center gap-2">
        {SAMPLES.map((s) => (
          <li key={s.id}>
            <button
              type="button"
              onClick={() => {
                onPickSample(s.text);
              }}
              className="h-10 rounded-xl border border-border bg-surface px-3 text-sm font-medium transition-colors hover:border-accent/60 hover:bg-surface-2"
              title={s.description}
            >
              {s.label}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ParseErrorState({ errors }: { errors: ParseError[] }) {
  return (
    <div className="px-4 py-4" role="alert">
      <div className="rounded-xl border border-sev-critical/40 bg-sev-critical/10 p-4">
        <div className="flex items-center gap-2 text-sev-critical">
          <AlertIcon size={18} />
          <h2 className="font-semibold">
            {errors.length === 1
              ? 'The policy could not be parsed'
              : `${errors.length} problems in the policy`}
          </h2>
        </div>
        <ul className="mt-3 space-y-2 text-sm">
          {errors.map((e, i) => (
            <li key={`${e.message}-${i}`} className="flex flex-wrap gap-x-3 gap-y-1">
              {e.line !== undefined && (
                <span className="shrink-0 font-mono text-xs text-fg-muted">
                  line {e.line}
                  {e.column !== undefined ? `:${e.column}` : ''}
                </span>
              )}
              <span className="min-w-0 flex-1 leading-relaxed">{e.message}</span>
              {e.path && <span className="w-full font-mono text-xs text-fg-subtle">{e.path}</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function FindingsPanel({ state, selectedId, onSelect, onPickSample }: Props) {
  const [hidden, setHidden] = useState<Set<Severity>>(() => new Set());
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  const findings = useMemo(
    () => (state.kind === 'done' && state.ok ? state.result.findings : []),
    [state],
  );
  const groups = useMemo(() => {
    const active = findings.filter((f) => !f.mitigatedBy);
    const bySeverity = SEVERITIES.map((severity) => ({
      key: severity,
      label: SEVERITY_LABEL[severity],
      items: active.filter((f) => f.severity === severity),
    })).filter((g) => g.items.length > 0 && !hidden.has(g.key));
    const mitigated = findings.filter((f) => f.mitigatedBy);
    return {
      bySeverity,
      mitigated,
      visibleCount: bySeverity.reduce((n, g) => n + g.items.length, 0),
    };
  }, [findings, hidden]);

  const toggle = (finding: Finding): void => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(finding.id)) next.delete(finding.id);
      else next.add(finding.id);
      return next;
    });
    onSelect(selectedId === finding.id && expanded.has(finding.id) ? null : finding);
  };

  const liveText =
    state.kind === 'empty'
      ? 'No policy entered.'
      : state.ok
        ? `${findings.length} findings, risk score ${state.result.score.score}: ${state.result.score.label}.`
        : `Policy could not be parsed: ${state.errors[0]?.message ?? ''}`;

  return (
    <section
      aria-label="Findings"
      className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-border bg-surface-2 shadow-card"
    >
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {liveText}
      </p>

      {state.kind === 'empty' && <EmptyState onPickSample={onPickSample} />}
      {state.kind === 'done' && !state.ok && <ParseErrorState errors={state.errors} />}

      {state.kind === 'done' && state.ok && (
        <>
          <div className="border-b border-border bg-surface">
            <RiskScore
              score={state.result.score}
              policyKind={state.result.policy.kind}
              statementCount={state.result.policy.statements.length}
            />
            <div
              className="flex flex-wrap items-center gap-2 px-4 pb-3"
              role="group"
              aria-label="Filter by severity"
            >
              {SEVERITIES.map((severity) => {
                const count = state.result.score.counts[severity];
                const isHidden = hidden.has(severity);
                return (
                  <button
                    key={severity}
                    type="button"
                    aria-pressed={!isHidden}
                    disabled={count === 0}
                    onClick={() => {
                      setHidden((prev) => {
                        const next = new Set(prev);
                        if (next.has(severity)) next.delete(severity);
                        else next.add(severity);
                        return next;
                      });
                    }}
                    className={`inline-flex h-8 items-center gap-1.5 rounded-full border px-2.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                      isHidden
                        ? 'border-border text-fg-subtle line-through'
                        : 'border-border-strong bg-surface-2 text-fg'
                    }`}
                  >
                    <SeverityDot severity={severity} />
                    {SEVERITY_LABEL[severity]}
                    <span className="font-mono tabular-nums text-fg-muted">{count}</span>
                  </button>
                );
              })}
            </div>
            {state.result.warnings.length > 0 && (
              <ul className="space-y-1 border-t border-border px-4 py-2 text-xs text-fg-muted">
                {state.result.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
            {findings.length === 0 && (
              <div className="flex flex-col items-center py-12 text-center">
                <span className="grid size-12 place-items-center rounded-2xl bg-sev-mitigated/15 text-sev-mitigated">
                  <ShieldIcon size={24} />
                </span>
                <p className="mt-3 font-semibold">Nothing to report</p>
                <p className="mt-1 max-w-sm text-sm text-fg-muted">
                  Every statement passed all {RULES.length} rules. That does not prove the policy is
                  minimal — review the actions and ARNs against what the workload actually calls.
                </p>
              </div>
            )}
            {findings.length > 0 && groups.visibleCount === 0 && groups.mitigated.length === 0 && (
              <p className="py-8 text-center text-sm text-fg-muted">
                All severities are filtered out.
              </p>
            )}
            <div className="space-y-6">
              {groups.bySeverity.map((group) => (
                <div key={group.key}>
                  <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                    <SeverityDot severity={group.key} /> {group.label}
                    <span className="font-mono">{group.items.length}</span>
                  </h3>
                  <ul className="space-y-2">
                    {group.items.map((f) => (
                      <FindingCard
                        key={f.id}
                        finding={f}
                        expanded={expanded.has(f.id)}
                        selected={selectedId === f.id}
                        onToggle={() => {
                          toggle(f);
                        }}
                      />
                    ))}
                  </ul>
                </div>
              ))}
              {groups.mitigated.length > 0 && (
                <div>
                  <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                    <SeverityDot severity="info" mitigated /> Mitigated by Deny
                    <span className="font-mono">{groups.mitigated.length}</span>
                  </h3>
                  <ul className="space-y-2">
                    {groups.mitigated.map((f) => (
                      <FindingCard
                        key={f.id}
                        finding={f}
                        expanded={expanded.has(f.id)}
                        selected={selectedId === f.id}
                        onToggle={() => {
                          toggle(f);
                        }}
                      />
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
