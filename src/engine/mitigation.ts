import { actionPatternsMayOverlap, resourceCovers, resourcesCover } from './matching';
import type { Finding, Policy, Statement } from './types';
import { hasCondition } from './rules/helpers';

/** Rules whose findings an explicit Deny can neutralise. */
const MITIGABLE_RULES = new Set([
  'admin-wildcard',
  'service-wildcard',
  'resource-wildcard-on-mutating-action',
  'privilege-escalation',
  'data-exfil-actions',
  'missing-mfa-condition',
]);

/** Whether a Deny statement denies everything an Allow action pattern could grant. */
export function denyCoversActionPattern(deny: Statement, pattern: string): boolean {
  if (deny.notActions.length > 0) {
    // "Deny everything except X" covers a pattern no X could overlap with.
    return !deny.notActions.some((n) => actionPatternsMayOverlap(n, pattern));
  }
  return deny.actions.some((d) => resourceCovers(d, pattern));
}

export function denyNeutralises(
  deny: Statement,
  allow: Statement,
  actions: readonly string[],
): boolean {
  if (deny.effect !== 'Deny' || hasCondition(deny)) return false;
  if (actions.length === 0) return false;
  if (!actions.every((a) => denyCoversActionPattern(deny, a))) return false;
  if (allow.notResources.length > 0) return deny.resources.includes('*');
  if (deny.notResources.length > 0) return false;
  // Resource policies may omit Resource (e.g. trust policies); treat as "the resource itself".
  if (allow.resources.length === 0 && deny.resources.length === 0) return true;
  return resourcesCover(deny.resources, allow.resources);
}

export function applyDenyMitigation(findings: Finding[], policy: Policy): Finding[] {
  const denies = policy.statements.filter((s) => s.effect === 'Deny');
  if (denies.length === 0) return findings;
  return findings.map((finding) => {
    if (!MITIGABLE_RULES.has(finding.ruleId) || finding.statementIndex === null) return finding;
    const allow = policy.statements.find((s) => s.index === finding.statementIndex);
    if (!allow) return finding;
    const deny = denies.find((d) => denyNeutralises(d, allow, finding.actions));
    if (!deny) return finding;
    return {
      ...finding,
      mitigatedBy: {
        statementIndex: deny.index,
        sid: deny.sid,
        reason: `An unconditional Deny in ${deny.sid ? `"${deny.sid}" (Statement[${deny.index}])` : `Statement[${deny.index}]`} covers the same actions on the same or a broader resource, so this Allow has no effect for them.`,
      },
    };
  });
}
