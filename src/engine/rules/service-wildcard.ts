import { CRITICAL_WILDCARD_SERVICES } from '../data/service-prefixes';
import { isServiceWildcard, splitAction } from '../matching';
import type { Rule } from '../types';
import { DOCS, describeTarget, makeFinding, rewriteStatement } from './helpers';

const SERVICE_EXAMPLES: Record<string, string[]> = {
  s3: ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
  iam: ['iam:GetRole', 'iam:ListRoles'],
  ec2: ['ec2:DescribeInstances', 'ec2:StartInstances', 'ec2:StopInstances'],
  kms: ['kms:Decrypt', 'kms:GenerateDataKey'],
  dynamodb: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'],
  lambda: ['lambda:InvokeFunction', 'lambda:GetFunction'],
  sts: ['sts:AssumeRole'],
  organizations: ['organizations:DescribeOrganization', 'organizations:ListAccounts'],
};

export const serviceWildcard: Rule = {
  id: 'service-wildcard',
  severity: 'high',
  title: 'Service-wide action wildcard',
  explanation:
    'A `service:*` wildcard grants every current and future action of that service, including destructive and administrative ones you may not know exist. For IAM, STS, Organizations and KMS it is effectively account takeover, since those services control identities, trust and encryption keys.',
  remediation:
    'Enumerate the actions actually called (CloudTrail or IAM Access Analyzer policy generation can produce the list) and replace the wildcard with them. Group read-only actions with `Get*`/`List*`/`Describe*` prefixes if a shorter list is needed.',
  references: [DOCS.wildcards, DOCS.actionsList],
  check({ policy }) {
    return policy.statements
      .filter((s) => s.effect === 'Allow')
      .flatMap((s) =>
        s.actions.filter(isServiceWildcard).map((action) => {
          const service = splitAction(action)?.service ?? '';
          const critical = CRITICAL_WILDCARD_SERVICES.has(service);
          return makeFinding(serviceWildcard, {
            statement: s,
            element: 'Action',
            key: action.toLowerCase(),
            actions: [action],
            severity: critical ? 'critical' : 'high',
            message: `${describeTarget(s)} allows "${action}" — every ${service} action${critical ? ', which controls identities, trust or keys' : ''}.`,
            fix: {
              description: `Replace "${action}" with the specific ${service} actions in use.`,
              statement: rewriteStatement(s, {
                Action: s.actions.flatMap((a) =>
                  a === action
                    ? (SERVICE_EXAMPLES[service] ?? [
                        `${service}:Describe*`,
                        `${service}:Get*`,
                        `${service}:List*`,
                      ])
                    : [a],
                ),
              }),
            },
          });
        }),
      );
  },
};
