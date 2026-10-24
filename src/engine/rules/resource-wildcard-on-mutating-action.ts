import { MUTATING_VERBS } from '../data/action-catalog';
import { isFullWildcard, isServiceWildcard, splitAction } from '../matching';
import type { Rule } from '../types';
import {
  DOCS,
  describeTarget,
  hasWildcardResource,
  makeFinding,
  rewriteStatement,
} from './helpers';

export function isMutatingAction(action: string): boolean {
  const parts = splitAction(action);
  if (!parts) return false;
  const name = parts.name.replace(/\*.*$/, '');
  if (name.length === 0) return false;
  return MUTATING_VERBS.some((verb) => name.toLowerCase().startsWith(verb.toLowerCase()));
}

export const resourceWildcardOnMutatingAction: Rule = {
  id: 'resource-wildcard-on-mutating-action',
  severity: 'high',
  title: 'Write action on every resource',
  explanation:
    'Create, Put, Delete, Update and similar actions on `Resource: "*"` let the principal modify or destroy any matching resource in the account, not just the ones the workload owns. A compromised credential turns this into account-wide blast radius.',
  remediation:
    'Scope Resource to the specific ARNs (or ARN patterns with a predictable prefix, such as `arn:aws:s3:::my-app-*`) the workload manages. Where a service action genuinely requires `*`, isolate it in its own statement with a Condition such as `aws:RequestTag` or `aws:ResourceTag`.',
  references: [DOCS.leastPrivilege, DOCS.actionsList],
  check({ policy }) {
    return policy.statements
      .filter((s) => s.effect === 'Allow' && hasWildcardResource(s))
      .flatMap((s) => {
        const mutating = s.actions.filter(
          (a) => !isFullWildcard(a) && !isServiceWildcard(a) && isMutatingAction(a),
        );
        if (mutating.length === 0) return [];
        const shown =
          mutating.slice(0, 3).join(', ') +
          (mutating.length > 3 ? ` and ${mutating.length - 3} more` : '');
        const service = splitAction(mutating[0] ?? '')?.service ?? 'service';
        return [
          makeFinding(resourceWildcardOnMutatingAction, {
            statement: s,
            element: 'Resource',
            actions: mutating,
            message: `${describeTarget(s)} allows ${shown} on every resource ("*").`,
            fix: {
              description: 'Scope the statement to the ARNs it manages.',
              statement: rewriteStatement(s, {
                Resource: [`arn:aws:${service}:us-east-1:123456789012:RESOURCE-TYPE/my-app-*`],
              }),
            },
          }),
        ];
      });
  },
};
