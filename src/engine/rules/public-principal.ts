import { PRINCIPAL_RESTRICTING_KEYS } from '../data/action-catalog';
import type { Principal, Rule, Statement } from '../types';
import {
  DOCS,
  describeTarget,
  hasConditionKey,
  makeFinding,
  rewriteStatement,
  withCondition,
} from './helpers';

export function isPublicPrincipal(principal: Principal | undefined): boolean {
  if (!principal) return false;
  if (principal.any) return true;
  return principal.entries.some((e) => e.type === 'AWS' && e.values.some((v) => v.trim() === '*'));
}

export function hasRestrictingCondition(statement: Statement): boolean {
  return PRINCIPAL_RESTRICTING_KEYS.some((key) => hasConditionKey(statement, key));
}

export const publicPrincipal: Rule = {
  id: 'public-principal',
  severity: 'critical',
  title: 'Public principal without restriction',
  explanation:
    'A resource policy that allows `Principal: "*"` (or `{"AWS": "*"}`) with no condition narrowing who the caller is grants access to every AWS account and, for many services, to anonymous internet users. This is how public S3 buckets, open SQS queues and world-invokable Lambdas happen.',
  remediation:
    'Name the principals explicitly, or keep the wildcard only together with a restricting condition: `aws:PrincipalOrgID` for organisation-wide sharing, `aws:SourceArn`/`aws:SourceAccount` when an AWS service calls on your behalf, or `aws:SourceVpce` for VPC-endpoint-only access.',
  references: [DOCS.principal, DOCS.confusedDeputy],
  check({ policy }) {
    return policy.statements
      .filter((s) => s.effect === 'Allow')
      .flatMap((s) => {
        if (s.notPrincipal) {
          return [
            makeFinding(publicPrincipal, {
              statement: s,
              element: 'NotPrincipal',
              message: `${describeTarget(s)} uses NotPrincipal with Allow — it grants access to every principal not listed, which is effectively public.`,
              fix: {
                description: 'Name the allowed principals instead of excluding a few.',
                statement: rewriteStatement(s, {
                  NotPrincipal: undefined,
                  Principal: { AWS: 'arn:aws:iam::123456789012:role/my-app-role' },
                }),
              },
            }),
          ];
        }
        if (!isPublicPrincipal(s.principal) || hasRestrictingCondition(s)) return [];
        return [
          makeFinding(publicPrincipal, {
            statement: s,
            element: 'Principal',
            message: `${describeTarget(s)} allows any principal ("*") with no aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID or aws:SourceVpce condition.`,
            fix: {
              description: 'Keep the wildcard but restrict callers to your organisation.',
              statement: rewriteStatement(s, {
                Condition: withCondition(s, 'StringEquals', 'aws:PrincipalOrgID', 'o-xxxxxxxxxx'),
              }),
            },
          }),
        ];
      });
  },
};
