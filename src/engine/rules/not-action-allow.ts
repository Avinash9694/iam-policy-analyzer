import type { Rule } from '../types';
import { DOCS, describeTarget, makeFinding, rewriteStatement } from './helpers';

export const notActionAllow: Rule = {
  id: 'not-action-allow',
  severity: 'high',
  title: 'Allow with NotAction',
  explanation:
    '`NotAction` in an Allow statement grants every action except the listed ones — including every action AWS adds in the future. It is almost impossible to reason about what such a statement permits, and it silently widens as services launch new APIs.',
  remediation:
    'Invert the statement: list the actions that are needed under `Action`. If the intent is to block a few dangerous actions, keep the explicit Allow and add a separate Deny statement for them.',
  references: [DOCS.notAction, DOCS.leastPrivilege],
  check({ policy }) {
    return policy.statements
      .filter((s) => s.effect === 'Allow' && s.notActions.length > 0)
      .map((s) =>
        makeFinding(notActionAllow, {
          statement: s,
          element: 'NotAction',
          message: `${describeTarget(s)} allows everything except ${s.notActions.length} action pattern${s.notActions.length === 1 ? '' : 's'} (${s.notActions.slice(0, 3).join(', ')}${s.notActions.length > 3 ? ', …' : ''}).`,
          fix: {
            description: 'Replace NotAction with an explicit Action list.',
            statement: rewriteStatement(s, {
              NotAction: undefined,
              Action: ['s3:GetObject', 's3:ListBucket'],
            }),
          },
        }),
      );
  },
};
