import type { Severity } from '@/engine';
import { SEVERITY_COLOR_CLASS, SEVERITY_LABEL, SEVERITY_TEXT_CLASS } from './severity-meta';

export function SeverityDot({
  severity,
  mitigated = false,
}: {
  severity: Severity;
  mitigated?: boolean;
}) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block size-2.5 shrink-0 rounded-full ${mitigated ? 'bg-sev-mitigated' : SEVERITY_COLOR_CLASS[severity]}`}
    />
  );
}

export function SeverityBadge({
  severity,
  mitigated = false,
}: {
  severity: Severity;
  mitigated?: boolean;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-0.5 text-xs font-medium ${mitigated ? 'text-sev-mitigated' : SEVERITY_TEXT_CLASS[severity]}`}
    >
      <SeverityDot severity={severity} mitigated={mitigated} />
      {mitigated ? 'Mitigated' : SEVERITY_LABEL[severity]}
    </span>
  );
}
