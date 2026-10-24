import { DATA_EXFIL_ACTIONS } from '../data/action-catalog';
import { isFullWildcard, isServiceWildcard } from '../matching';
import type { Rule } from '../types';
import {
  DOCS,
  describeTarget,
  hasWildcardResource,
  makeFinding,
  rewriteStatement,
  statementCoversAction,
} from './helpers';

export const dataExfilActions: Rule = {
  id: 'data-exfil-actions',
  severity: 'high',
  title: 'Data-read action on every resource',
  explanation:
    'Reading objects, table items, secrets or parameters from `Resource: "*"` means every bucket, table, secret and parameter in the account is readable with this credential. These are the permissions used to exfiltrate data after a compromise, and they rarely need to span the whole account.',
  remediation:
    'Scope the statement to the bucket, table, secret or parameter-path ARNs the workload reads. For Secrets Manager and SSM, a hierarchical prefix (`arn:aws:ssm:…:parameter/my-app/*`) keeps the list short.',
  references: [DOCS.leastPrivilege, DOCS.actionsList],
  check({ policy }) {
    return policy.statements
      .filter((s) => s.effect === 'Allow' && hasWildcardResource(s))
      .flatMap((s) => {
        // Full and service-level wildcards are reported by their own rules.
        if (s.actions.some(isFullWildcard) || s.notActions.length > 0) return [];
        const hits = DATA_EXFIL_ACTIONS.filter((a) => statementCoversAction(s, a));
        if (hits.length === 0) return [];
        const wildcardServices = new Set(
          s.actions.filter(isServiceWildcard).map((a) => a.split(':')[0]?.toLowerCase()),
        );
        const concrete = hits.filter((a) => !wildcardServices.has(a.split(':')[0]?.toLowerCase()));
        if (concrete.length === 0) return [];
        const shown =
          concrete.slice(0, 3).join(', ') +
          (concrete.length > 3 ? ` and ${concrete.length - 3} more` : '');
        return [
          makeFinding(dataExfilActions, {
            statement: s,
            element: 'Resource',
            actions: concrete,
            message: `${describeTarget(s)} allows ${shown} on every resource ("*").`,
            fix: {
              description: 'Limit reads to the data stores the workload owns.',
              statement: rewriteStatement(s, {
                Resource: ['arn:aws:s3:::my-app-bucket', 'arn:aws:s3:::my-app-bucket/*'],
              }),
            },
          }),
        ];
      });
  },
};
