import { actionMatches } from '../matching';
import type { Rule } from '../types';
import {
  DOCS,
  describeTarget,
  hasConditionKey,
  makeFinding,
  rewriteStatement,
  withCondition,
} from './helpers';
import { hasMfaCondition } from './missing-mfa-condition';
import { hasRestrictingCondition } from './public-principal';

const ACCOUNT_ROOT = /^(arn:aws[a-z-]*:iam::)?(\d{12})(:root)?$/;

export const crossAccountTrust: Rule = {
  id: 'cross-account-trust',
  severity: 'medium',
  title: 'Cross-account trust without ExternalId or MFA',
  explanation:
    "A trust policy that lets another account's root (and therefore every principal in it) assume this role, with no `sts:ExternalId`, MFA or organisation condition, is open to the confused-deputy problem: any identity in that account — or anyone who can convince a service there to call AssumeRole — gets this role.",
  remediation:
    'Trust a specific role ARN rather than the account root, and add `"StringEquals": {"sts:ExternalId": "<unique value>"}` for third parties or `"Bool": {"aws:MultiFactorAuthPresent": "true"}` for human users. Inside one organisation, `aws:PrincipalOrgID` scopes the trust to your own accounts.',
  references: [DOCS.trustPolicy, DOCS.confusedDeputy],
  check({ policy }) {
    if (policy.kind !== 'resource') return [];
    return policy.statements
      .filter(
        (s) =>
          s.effect === 'Allow' &&
          s.actions.some((a) => actionMatches(a, 'sts:AssumeRole')) &&
          s.principal !== undefined &&
          !s.principal.any,
      )
      .flatMap((s) => {
        const roots = (s.principal?.entries ?? [])
          .filter((e) => e.type === 'AWS')
          .flatMap((e) => e.values)
          .filter((v) => ACCOUNT_ROOT.test(v));
        if (roots.length === 0) return [];
        if (
          hasConditionKey(s, 'sts:ExternalId') ||
          hasMfaCondition(s) ||
          hasRestrictingCondition(s)
        )
          return [];
        return [
          makeFinding(crossAccountTrust, {
            statement: s,
            element: 'Principal',
            message: `${describeTarget(s)} trusts the whole account ${roots.join(', ')} with no sts:ExternalId, MFA or aws:PrincipalOrgID condition.`,
            fix: {
              description: 'Require an ExternalId agreed with the trusted account.',
              statement: rewriteStatement(s, {
                Condition: withCondition(
                  s,
                  'StringEquals',
                  'sts:ExternalId',
                  'REPLACE-WITH-UNIQUE-ID',
                ),
              }),
            },
          }),
        ];
      });
  },
};
