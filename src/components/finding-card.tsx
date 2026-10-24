import type { Finding } from '@/engine';
import { useCopy } from '@/hooks/use-copy';
import { CheckIcon, ChevronIcon, CopyIcon, ExternalIcon } from './icons';
import { SeverityBadge } from './severity-badge';

interface Props {
  finding: Finding;
  expanded: boolean;
  selected: boolean;
  onToggle: () => void;
}

function docLabel(url: string): string {
  try {
    const u = new URL(url);
    const last = u.pathname.split('/').filter(Boolean).pop() ?? u.hostname;
    return last.replace(/\.html?$/, '').replace(/[_-]+/g, ' ');
  } catch {
    return url;
  }
}

export function FindingCard({ finding, expanded, selected, onToggle }: Props) {
  const copy = useCopy();
  const panelId = `finding-${finding.id.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  const fixJson = finding.fix ? JSON.stringify(finding.fix.statement, null, 2) : null;
  const location =
    finding.statementIndex === null
      ? 'Policy'
      : finding.sid
        ? `${finding.sid} · Statement[${finding.statementIndex}]`
        : `Statement[${finding.statementIndex}]`;

  return (
    <li
      className={`rounded-xl border bg-surface shadow-card transition-colors ${
        selected ? 'border-accent/60 ring-1 ring-accent/40' : 'border-border'
      } ${finding.mitigatedBy ? 'opacity-80' : ''}`}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={panelId}
        className="flex w-full items-start gap-3 rounded-xl px-4 py-3 text-left transition-colors hover:bg-surface-2"
      >
        <ChevronIcon
          size={16}
          className={`mt-1 shrink-0 text-fg-subtle transition-transform ${expanded ? 'rotate-90' : ''}`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} mitigated={Boolean(finding.mitigatedBy)} />
            <span className="truncate font-mono text-xs text-fg-muted">{location}</span>
          </div>
          <p className="mt-1.5 text-sm font-semibold leading-snug">{finding.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-fg-muted">{finding.message}</p>
        </div>
      </button>

      {expanded && (
        <div id={panelId} className="space-y-4 border-t border-border px-4 py-4 text-sm">
          {finding.mitigatedBy && (
            <div className="rounded-lg border border-sev-mitigated/40 bg-sev-mitigated/10 px-3 py-2 text-sev-mitigated">
              <span className="font-medium">Mitigated.</span> {finding.mitigatedBy.reason}
            </div>
          )}
          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              Why it matters
            </h4>
            <p className="mt-1 leading-relaxed">{finding.explanation}</p>
          </section>
          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">
              How to fix
            </h4>
            <p className="mt-1 leading-relaxed">{finding.remediation}</p>
          </section>
          {finding.fix && fixJson && (
            <section>
              <div className="flex items-center justify-between gap-2">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">
                  Suggested statement
                </h4>
                <button
                  type="button"
                  onClick={() => void copy.copy(fixJson)}
                  className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-surface-2 px-2.5 text-xs font-medium transition-colors hover:border-border-strong hover:bg-surface-3"
                >
                  {copy.status === 'copied' ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
                  {copy.status === 'copied'
                    ? 'Copied'
                    : copy.status === 'failed'
                      ? 'Copy failed'
                      : 'Copy fixed statement'}
                </button>
              </div>
              <p className="mt-1 text-fg-muted">{finding.fix.description}</p>
              <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed">
                {fixJson}
              </pre>
            </section>
          )}
          <section className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-muted">
            <span className="font-mono">{finding.path}</span>
            <span className="font-mono">
              lines {finding.span.startLine}
              {finding.span.endLine !== finding.span.startLine ? `–${finding.span.endLine}` : ''}
            </span>
            <span className="font-mono">rule: {finding.ruleId}</span>
            {finding.references.map((url) => (
              <a
                key={url}
                href={url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-accent underline-offset-2 hover:underline"
              >
                AWS docs: {docLabel(url)}
                <ExternalIcon size={12} />
              </a>
            ))}
          </section>
        </div>
      )}
    </li>
  );
}
