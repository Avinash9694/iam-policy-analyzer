import { ALLOW_ALL, findingsFor } from '@/test/helpers';

describe('admin-wildcard', () => {
  it('flags Allow * on *', () => {
    const [f] = findingsFor('admin-wildcard', { Sid: 'Admin', ...ALLOW_ALL });
    expect(f).toMatchObject({
      severity: 'critical',
      statementIndex: 0,
      sid: 'Admin',
      path: 'Statement[0].Action',
    });
    expect(f?.fix?.statement).not.toHaveProperty('Resource', '*');
  });

  it('flags * with NotResource (still admin on almost everything)', () => {
    expect(
      findingsFor('admin-wildcard', {
        Effect: 'Allow',
        Action: '*',
        NotResource: 'arn:aws:s3:::x',
      }),
    ).toHaveLength(1);
  });

  it('ignores Deny * on * and scoped wildcards', () => {
    expect(
      findingsFor('admin-wildcard', { Effect: 'Deny', Action: '*', Resource: '*' }),
    ).toHaveLength(0);
    expect(
      findingsFor('admin-wildcard', { Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::b/*' }),
    ).toHaveLength(0);
    expect(
      findingsFor('admin-wildcard', { Effect: 'Allow', Action: 's3:*', Resource: '*' }),
    ).toHaveLength(0);
  });
});

describe('service-wildcard', () => {
  it('is critical for iam/sts/organizations/kms and high otherwise', () => {
    const findings = findingsFor('service-wildcard', {
      Effect: 'Allow',
      Action: ['iam:*', 'sts:*', 'organizations:*', 'kms:*', 's3:*', 'ec2:*'],
      Resource: '*',
    });
    expect(findings.map((f) => f.severity)).toEqual([
      'critical',
      'critical',
      'critical',
      'critical',
      'high',
      'high',
    ]);
    expect(findings.map((f) => f.actions)).toEqual([
      ['iam:*'],
      ['sts:*'],
      ['organizations:*'],
      ['kms:*'],
      ['s3:*'],
      ['ec2:*'],
    ]);
  });

  it('suggests concrete actions in the fix and keeps the others', () => {
    const [f] = findingsFor('service-wildcard', {
      Effect: 'Allow',
      Action: ['s3:*', 'sqs:SendMessage'],
      Resource: '*',
    });
    expect(f?.fix?.statement.Action).toEqual([
      's3:GetObject',
      's3:PutObject',
      's3:ListBucket',
      'sqs:SendMessage',
    ]);
  });

  it('does not flag Deny, full wildcard or prefixed globs', () => {
    expect(
      findingsFor('service-wildcard', { Effect: 'Deny', Action: 's3:*', Resource: '*' }),
    ).toHaveLength(0);
    expect(findingsFor('service-wildcard', ALLOW_ALL)).toHaveLength(0);
    expect(
      findingsFor('service-wildcard', { Effect: 'Allow', Action: 's3:Get*', Resource: '*' }),
    ).toHaveLength(0);
  });
});

describe('resource-wildcard-on-mutating-action', () => {
  it('flags write verbs on *', () => {
    const [f] = findingsFor('resource-wildcard-on-mutating-action', {
      Effect: 'Allow',
      Action: ['ec2:TerminateInstances', 'ec2:DescribeInstances', 's3:PutObject'],
      Resource: '*',
    });
    expect(f).toMatchObject({
      severity: 'high',
      path: 'Statement[0].Resource',
      actions: ['ec2:TerminateInstances', 's3:PutObject'],
    });
    expect(f?.fix?.statement.Resource).toEqual([
      'arn:aws:ec2:us-east-1:123456789012:RESOURCE-TYPE/my-app-*',
    ]);
  });

  it('ignores read-only actions, scoped resources and wildcards reported elsewhere', () => {
    expect(
      findingsFor('resource-wildcard-on-mutating-action', {
        Effect: 'Allow',
        Action: ['ec2:Describe*', 's3:GetObject'],
        Resource: '*',
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('resource-wildcard-on-mutating-action', {
        Effect: 'Allow',
        Action: 's3:PutObject',
        Resource: 'arn:aws:s3:::b/*',
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('resource-wildcard-on-mutating-action', {
        Effect: 'Allow',
        Action: ['s3:*', '*'],
        Resource: '*',
      }),
    ).toHaveLength(0);
  });

  it('treats a verb glob such as Delete* as mutating', () => {
    expect(
      findingsFor('resource-wildcard-on-mutating-action', {
        Effect: 'Allow',
        Action: 'dynamodb:Delete*',
        Resource: '*',
      }),
    ).toHaveLength(1);
  });
});

describe('not-action-allow', () => {
  it('flags Allow with NotAction and offers an explicit Action list', () => {
    const [f] = findingsFor('not-action-allow', {
      Effect: 'Allow',
      NotAction: ['iam:*', 'organizations:*'],
      Resource: '*',
    });
    expect(f).toMatchObject({ severity: 'high', path: 'Statement[0].NotAction' });
    expect(f?.fix?.statement).not.toHaveProperty('NotAction');
    expect(f?.fix?.statement).toHaveProperty('Action');
  });

  it('does not flag Deny with NotAction', () => {
    expect(
      findingsFor('not-action-allow', { Effect: 'Deny', NotAction: 's3:GetObject', Resource: '*' }),
    ).toHaveLength(0);
  });
});
