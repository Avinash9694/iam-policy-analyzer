import { ESCALATION_PATHS } from '../data/action-catalog';
import type { EscalationPath } from '../data/action-catalog';
import type { Rule, Statement } from '../types';
import {
  DOCS,
  describeTarget,
  hasWildcardResource,
  makeFinding,
  rewriteStatement,
  statementsAllowing,
} from './helpers';

/** Paths whose action list is "any one of" rather than "all of". */
const ANY_OF_PATHS = new Set(['attach-policy', 'put-inline-policy', 'login-profile']);

interface Match {
  path: EscalationPath;
  anchor: Statement;
  actions: string[];
}

function findMatches(policy: Parameters<Rule['check']>[0]['policy']): Match[] {
  const matches: Match[] = [];
  for (const path of ESCALATION_PATHS) {
    if (path.id === 'assume-role-any') {
      const grants = statementsAllowing(policy, 'sts:AssumeRole').filter(hasWildcardResource);
      const anchor = grants[0];
      if (anchor) matches.push({ path, anchor, actions: ['sts:AssumeRole'] });
      continue;
    }
    const granted = path.actions.map((a) => ({ action: a, by: statementsAllowing(policy, a) }));
    const present = granted.filter((g) => g.by.length > 0);
    const satisfied = ANY_OF_PATHS.has(path.id)
      ? present.length > 0
      : present.length === granted.length;
    if (!satisfied) continue;
    const anchor = present[0]?.by[0];
    if (!anchor) continue;
    matches.push({ path, anchor, actions: present.map((g) => g.action) });
  }
  return matches;
}

export const privilegeEscalation: Rule = {
  id: 'privilege-escalation',
  severity: 'critical',
  title: 'Privilege-escalation path',
  explanation:
    'Some combinations of IAM, STS and compute permissions let a principal grant itself more access than the policy appears to give. These paths are well documented and routinely exploited after an initial credential compromise, turning a limited foothold into account administration.',
  remediation:
    'Remove the escalation-capable actions, or constrain them: scope `iam:PassRole` with `iam:PassedToService` and a specific role ARN, restrict policy-editing actions to named policy ARNs, and never grant `sts:AssumeRole` on `*`. Use permissions boundaries on roles that can create or modify other principals.',
  references: [DOCS.passRole, DOCS.leastPrivilege],
  check({ policy }) {
    const matches = findMatches(policy);
    const byStatement = new Map<number, Match[]>();
    for (const m of matches) {
      const list = byStatement.get(m.anchor.index) ?? [];
      list.push(m);
      byStatement.set(m.anchor.index, list);
    }
    return [...byStatement.values()].flatMap((group) => {
      const first = group[0];
      if (!first) return [];
      const { anchor } = first;
      const titles = group.map((g) => g.path.title);
      const actions = [...new Set(group.flatMap((g) => g.actions))];
      const message =
        group.length === 1
          ? `${describeTarget(anchor)} enables "${first.path.title}" via ${actions.join(' + ')}. ${first.path.description}`
          : `${describeTarget(anchor)} enables ${group.length} escalation paths: ${titles.join('; ')}.`;
      const usesPassRole = actions.includes('iam:PassRole');
      return [
        makeFinding(privilegeEscalation, {
          statement: anchor,
          element: 'Action',
          actions,
          message,
          fix: {
            description: usesPassRole
              ? 'Constrain iam:PassRole to one role and the service that will use it.'
              : 'Drop the escalation-capable actions, or restrict them to specific ARNs.',
            statement: usesPassRole
              ? rewriteStatement(anchor, {
                  Action: 'iam:PassRole',
                  Resource: 'arn:aws:iam::123456789012:role/my-app-execution-role',
                  Condition: {
                    StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' },
                  },
                })
              : rewriteStatement(anchor, {
                  Action: anchor.actions.filter(
                    (a) => !actions.some((x) => x.toLowerCase() === a.toLowerCase()),
                  ),
                  Resource: anchor.resources.length > 0 ? anchor.resources : undefined,
                }),
          },
        }),
      ];
    });
  },
};
