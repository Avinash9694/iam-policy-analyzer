import { isFullWildcard } from '../matching';
import type { Rule } from '../types';
import {
  DOCS,
  describeTarget,
  hasWildcardResource,
  makeFinding,
  rewriteStatement,
} from './helpers';

export const adminWildcard: Rule = {
  id: 'admin-wildcard',
  severity: 'critical',
  title: 'Full administrative access',
  explanation:
    'Allowing every action on every resource is equivalent to the AdministratorAccess managed policy. Anyone (or any workload) holding these credentials can read or destroy anything in the account, create new identities and disable logging.',
  remediation:
    'List the specific actions the workload needs and scope Resource to the ARNs it operates on. If genuine admin access is required, attach the AdministratorAccess managed policy to a dedicated role protected by MFA and short session durations instead of embedding it inline.',
  references: [DOCS.leastPrivilege, DOCS.wildcards],
  check({ policy }) {
    return policy.statements
      .filter(
        (s) =>
          s.effect === 'Allow' &&
          s.actions.some(isFullWildcard) &&
          (hasWildcardResource(s) || s.notResources.length > 0),
      )
      .map((s) =>
        makeFinding(adminWildcard, {
          statement: s,
          element: 'Action',
          actions: ['*'],
          message: `${describeTarget(s)} allows "*" on ${hasWildcardResource(s) ? '"*"' : 'everything except its NotResource list'} — this is unrestricted admin.`,
          fix: {
            description:
              'Replace the wildcard with the actions and ARNs the workload actually uses.',
            statement: rewriteStatement(s, {
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: 'arn:aws:s3:::my-app-bucket/*',
              NotResource: undefined,
            }),
          },
        }),
      );
  },
};
