export interface SamplePolicy {
  id: string;
  label: string;
  description: string;
  text: string;
}

const pretty = (value: unknown): string => JSON.stringify(value, null, 2);

export const SAMPLES: readonly SamplePolicy[] = [
  {
    id: 'admin',
    label: 'Full admin (inline)',
    description: 'The classic "just make it work" policy.',
    text: pretty({
      Version: '2012-10-17',
      Statement: [{ Sid: 'AllowEverything', Effect: 'Allow', Action: '*', Resource: '*' }],
    }),
  },
  {
    id: 'broad-s3',
    label: 'Overly broad S3 access',
    description: 's3:* on every bucket, plus a service prefix that does not exist.',
    text: pretty({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'S3Everything',
          Effect: 'Allow',
          Action: ['s3:*', 'dynamodb:Scan', 'cloudwatchlogs:GetLogEvents'],
          Resource: '*',
        },
        {
          Sid: 'ReadParams',
          Effect: 'Allow',
          Action: ['ssm:GetParameter', 'ssm:GetParametersByPath'],
          Resource: '*',
          Condition: { StringEquals: { 'aws:SourceIp': '10.0.0.0/8' } },
        },
      ],
    }),
  },
  {
    id: 'pass-role',
    label: 'PassRole escalation',
    description: 'A deployment policy that quietly allows becoming any role.',
    text: pretty({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DeployFunctions',
          Effect: 'Allow',
          Action: [
            'lambda:CreateFunction',
            'lambda:UpdateFunctionCode',
            'lambda:InvokeFunction',
            'iam:PassRole',
          ],
          Resource: '*',
        },
        {
          Sid: 'ManagePolicies',
          Effect: 'Allow',
          Action: ['iam:CreatePolicyVersion', 'iam:ListPolicyVersions'],
          Resource: 'arn:aws:iam::123456789012:policy/*',
        },
      ],
    }),
  },
  {
    id: 'least-privilege',
    label: 'Least-privilege (clean)',
    description: 'Scoped actions, scoped ARNs, a guard-rail Deny.',
    text: pretty({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'ReadAppBucket',
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:ListBucket'],
          Resource: ['arn:aws:s3:::my-app-assets', 'arn:aws:s3:::my-app-assets/*'],
        },
        {
          Sid: 'WriteOwnQueue',
          Effect: 'Allow',
          Action: ['sqs:SendMessage', 'sqs:GetQueueAttributes'],
          Resource: 'arn:aws:sqs:eu-west-1:123456789012:my-app-events',
        },
        {
          Sid: 'DenyOutsideRegion',
          Effect: 'Deny',
          Action: '*',
          Resource: '*',
          Condition: { StringNotEquals: { 'aws:RequestedRegion': 'eu-west-1' } },
        },
      ],
    }),
  },
  {
    id: 'public-bucket',
    label: 'Public bucket policy',
    description: 'World-readable objects over plain HTTP.',
    text: pretty({
      Version: '2012-10-17',
      Id: 'PublicReadPolicy',
      Statement: [
        {
          Sid: 'PublicRead',
          Effect: 'Allow',
          Principal: '*',
          Action: ['s3:GetObject', 's3:ListBucket'],
          Resource: ['arn:aws:s3:::marketing-site', 'arn:aws:s3:::marketing-site/*'],
        },
      ],
    }),
  },
  {
    id: 'trust-policy',
    label: 'Role trust policy',
    description: 'Cross-account trust that forgot the ExternalId.',
    text: pretty({
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'TrustVendorAccount',
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::999988887777:root' },
          Action: 'sts:AssumeRole',
        },
        {
          Sid: 'TrustLambda',
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    }),
  },
  {
    id: 'mitigated',
    label: 'Broad Allow, explicit Deny',
    description: 'A wildcard the Deny below neutralises.',
    text: pretty({
      Version: '2012-10-17',
      Statement: [
        { Sid: 'AllowIam', Effect: 'Allow', Action: 'iam:*', Resource: '*' },
        { Sid: 'DenyIam', Effect: 'Deny', Action: 'iam:*', Resource: '*' },
        {
          Sid: 'ReadLogs',
          Effect: 'Allow',
          Action: ['logs:GetLogEvents', 'logs:FilterLogEvents'],
          Resource: 'arn:aws:logs:eu-west-1:123456789012:log-group:/my-app/*',
        },
      ],
    }),
  },
];

export function getSample(id: string): SamplePolicy | undefined {
  return SAMPLES.find((s) => s.id === id);
}
