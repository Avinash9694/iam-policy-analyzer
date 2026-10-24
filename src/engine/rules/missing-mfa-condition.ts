import { MFA_SENSITIVE_ACTIONS } from '../data/action-catalog';
import { actionMatches, isFullWildcard } from '../matching';
import type { Rule, Statement } from '../types';
import {
  DOCS,
  describeTarget,
  hasConditionKey,
  makeFinding,
  rewriteStatement,
  statementCoversAction,
  withCondition,
} from './helpers';

export function hasMfaCondition(statement: Statement): boolean {
  return (
    hasConditionKey(statement, 'aws:MultiFactorAuthPresent') ||
    hasConditionKey(statement, 'aws:MultiFactorAuthAge')
  );
}

/** Sensitive actions this statement grants, named concretely where possible. */
function sensitiveActionsIn(statement: Statement): string[] {
  const hits = new Set<string>();
  for (const pattern of statement.actions) {
    if (isFullWildcard(pattern)) {
      hits.add('*');
      continue;
    }
    for (const sensitive of MFA_SENSITIVE_ACTIONS) {
      if (sensitive.endsWith('*')) {
        // iam:* style catalogue entry: the statement is sensitive if it grants
        // anything under that prefix.
        const prefix = sensitive.slice(0, -1).toLowerCase();
        if (pattern.toLowerCase().startsWith(prefix)) hits.add(pattern);
      } else if (actionMatches(pattern, sensitive)) {
        hits.add(sensitive);
      }
    }
  }
  if (statement.notActions.length > 0) {
    for (const sensitive of MFA_SENSITIVE_ACTIONS) {
      if (!sensitive.endsWith('*') && statementCoversAction(statement, sensitive))
        hits.add(sensitive);
    }
  }
  return [...hits];
}

export const missingMfaCondition: Rule = {
  id: 'missing-mfa-condition',
  severity: 'medium',
  title: 'Sensitive action without MFA condition',
  explanation:
    'Actions that change identities, delete data stores or disable logging are the ones an attacker with stolen long-lived credentials reaches for first. Requiring `aws:MultiFactorAuthPresent` means a leaked access key alone is not enough to use them.',
  remediation:
    'Add `"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}` to the statement (for human users), or move these actions to a role that can only be assumed with MFA. Workload roles that cannot use MFA should not hold these actions at all.',
  references: [DOCS.mfa, DOCS.conditionKeys],
  check({ policy }) {
    if (policy.kind !== 'identity') return [];
    return policy.statements
      .filter((s) => s.effect === 'Allow' && !hasMfaCondition(s))
      .flatMap((s) => {
        const sensitive = sensitiveActionsIn(s);
        if (sensitive.length === 0) return [];
        const shown =
          sensitive.slice(0, 3).join(', ') +
          (sensitive.length > 3 ? ` and ${sensitive.length - 3} more` : '');
        return [
          makeFinding(missingMfaCondition, {
            statement: s,
            element: 'Action',
            actions: sensitive,
            message: `${describeTarget(s)} grants ${shown} without requiring MFA.`,
            fix: {
              description: 'Require an MFA-authenticated session for these actions.',
              statement: rewriteStatement(s, {
                Condition: withCondition(s, 'Bool', 'aws:MultiFactorAuthPresent', 'true'),
              }),
            },
          }),
        ];
      });
  },
};
