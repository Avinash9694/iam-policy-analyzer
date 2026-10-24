import { findingsFor } from '@/test/helpers';

describe('data-exfil-actions', () => {
  it('flags data-read actions on *', () => {
    const [f] = findingsFor('data-exfil-actions', {
      Effect: 'Allow',
      Action: [
        's3:GetObject',
        'secretsmanager:GetSecretValue',
        'ssm:GetParameters',
        'sqs:ReceiveMessage',
      ],
      Resource: '*',
    });
    expect(f).toMatchObject({
      severity: 'high',
      actions: ['s3:GetObject', 'secretsmanager:GetSecretValue', 'ssm:GetParameters'],
    });
  });

  it('matches through action globs', () => {
    expect(
      findingsFor('data-exfil-actions', {
        Effect: 'Allow',
        Action: 'dynamodb:Get*',
        Resource: '*',
      })[0]?.actions,
    ).toEqual(['dynamodb:GetItem']);
  });

  it('skips scoped resources and wildcards reported by other rules', () => {
    expect(
      findingsFor('data-exfil-actions', {
        Effect: 'Allow',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::b/*',
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('data-exfil-actions', { Effect: 'Allow', Action: 's3:*', Resource: '*' }),
    ).toHaveLength(0);
    expect(
      findingsFor('data-exfil-actions', { Effect: 'Allow', Action: '*', Resource: '*' }),
    ).toHaveLength(0);
    expect(
      findingsFor('data-exfil-actions', { Effect: 'Deny', Action: 's3:GetObject', Resource: '*' }),
    ).toHaveLength(0);
  });
});

describe('unknown-action', () => {
  it('flags an unknown service prefix and a malformed action', () => {
    const findings = findingsFor('unknown-action', {
      Effect: 'Allow',
      Action: ['cloudwatchlogs:GetLogEvents', 'GetObject', 's3:GetObject'],
      Resource: '*',
    });
    expect(findings.map((f) => f.message)).toEqual([
      expect.stringContaining('"cloudwatchlogs" is not a known service prefix'),
      expect.stringContaining('not in the form "service:Action"'),
    ]);
    expect(findings[0]?.severity).toBe('low');
  });

  it('accepts known prefixes in any case, wildcards and NotAction lists', () => {
    expect(
      findingsFor('unknown-action', {
        Effect: 'Allow',
        Action: ['S3:GetObject', 'elasticloadbalancing:Describe*', '*'],
        Resource: '*',
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('unknown-action', {
        Effect: 'Allow',
        NotAction: 'nosuch:Thing',
        Resource: '*',
      })[0]?.path,
    ).toBe('Statement[0].NotAction');
  });
});

describe('condition-sanity', () => {
  const withCondition = (Condition: unknown) => ({
    Effect: 'Allow',
    Action: 's3:GetObject',
    Resource: '*',
    Condition,
  });

  it('flags an unknown operator as medium', () => {
    const [f] = findingsFor(
      'condition-sanity',
      withCondition({ StringEqual: { 'aws:username': 'x' } }),
    );
    expect(f).toMatchObject({
      severity: 'medium',
      message: expect.stringContaining('"StringEqual"'),
    });
  });

  it('accepts qualified operators', () => {
    expect(
      findingsFor(
        'condition-sanity',
        withCondition({
          'ForAnyValue:StringLike': { 'aws:TagKeys': 'x' },
          StringEqualsIfExists: { 'aws:RequestTag/env': 'prod' },
          'ForAllValues:ArnLikeIfExists': { 'aws:PrincipalArn': '*' },
        }),
      ),
    ).toHaveLength(0);
  });

  it('flags Bool and Null with non-boolean values and fixes them', () => {
    const findings = findingsFor(
      'condition-sanity',
      withCondition({
        Bool: { 'aws:SecureTransport': 'yes' },
        Null: { 'aws:TokenIssueTime': '1' },
      }),
    );
    expect(findings).toHaveLength(2);
    expect(findings[0]?.fix?.statement).toMatchObject({
      Condition: { Bool: { 'aws:SecureTransport': 'true' } },
    });
  });

  it('flags StringEquals on aws:SourceIp and moves it to IpAddress', () => {
    const [f] = findingsFor(
      'condition-sanity',
      withCondition({ StringEquals: { 'aws:SourceIp': '10.0.0.0/8', 'aws:username': 'a' } }),
    );
    expect(f?.severity).toBe('medium');
    expect(f?.fix?.statement).toMatchObject({
      Condition: {
        StringEquals: { 'aws:username': 'a' },
        IpAddress: { 'aws:SourceIp': '10.0.0.0/8' },
      },
    });
  });

  it('accepts well-formed conditions', () => {
    expect(
      findingsFor(
        'condition-sanity',
        withCondition({
          IpAddress: { 'aws:SourceIp': '10.0.0.0/8' },
          Bool: { 'aws:MultiFactorAuthPresent': true },
          Null: { 'aws:TokenIssueTime': 'false' },
        }),
      ),
    ).toHaveLength(0);
  });
});

describe('policy-version', () => {
  it('reports a missing or 2008 version as info and is quiet on 2012', () => {
    const base = { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' };
    expect(findingsFor('policy-version', base, { Version: undefined })[0]).toMatchObject({
      severity: 'info',
      statementIndex: null,
    });
    expect(findingsFor('policy-version', base, { Version: '2008-10-17' })[0]?.message).toContain(
      '2008-10-17',
    );
    expect(findingsFor('policy-version', base)).toHaveLength(0);
  });
});
