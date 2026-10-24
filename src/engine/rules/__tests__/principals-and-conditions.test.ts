import { findingsFor } from '@/test/helpers';

const bucket = ['arn:aws:s3:::b', 'arn:aws:s3:::b/*'];

describe('public-principal', () => {
  it('flags Principal "*" and {"AWS": "*"} without a restricting condition', () => {
    expect(
      findingsFor('public-principal', {
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: bucket,
      }),
    ).toHaveLength(1);
    const [f] = findingsFor('public-principal', {
      Effect: 'Allow',
      Principal: { AWS: '*' },
      Action: 'sqs:SendMessage',
      Resource: 'arn:aws:sqs:::q',
    });
    expect(f).toMatchObject({ severity: 'critical', path: 'Statement[0].Principal' });
    expect(f?.fix?.statement).toMatchObject({
      Condition: { StringEquals: { 'aws:PrincipalOrgID': expect.any(String) } },
    });
  });

  it.each(['aws:SourceArn', 'aws:SourceAccount', 'aws:PrincipalOrgID', 'aws:SourceVpce'])(
    'is satisfied by a %s condition',
    (key) => {
      expect(
        findingsFor('public-principal', {
          Effect: 'Allow',
          Principal: '*',
          Action: 'sns:Publish',
          Resource: 'arn:aws:sns:::t',
          Condition: { StringEquals: { [key]: 'x' } },
        }),
      ).toHaveLength(0);
    },
  );

  it('is not satisfied by an unrelated condition', () => {
    expect(
      findingsFor('public-principal', {
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: bucket,
        Condition: { StringLike: { 's3:prefix': 'public/*' } },
      }),
    ).toHaveLength(1);
  });

  it('flags Allow with NotPrincipal', () => {
    const [f] = findingsFor('public-principal', {
      Effect: 'Allow',
      NotPrincipal: { AWS: 'arn:aws:iam::1:root' },
      Action: 's3:GetObject',
      Resource: bucket,
    });
    expect(f?.path).toBe('Statement[0].NotPrincipal');
  });

  it('ignores named principals and Deny statements', () => {
    expect(
      findingsFor('public-principal', {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::1:root' },
        Action: 's3:GetObject',
        Resource: bucket,
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('public-principal', {
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: bucket,
      }),
    ).toHaveLength(0);
  });
});

describe('missing-mfa-condition', () => {
  it('flags sensitive actions without an MFA condition', () => {
    const [f] = findingsFor('missing-mfa-condition', {
      Effect: 'Allow',
      Action: ['iam:CreateUser', 's3:GetObject'],
      Resource: '*',
    });
    expect(f).toMatchObject({ severity: 'medium', actions: ['iam:CreateUser'] });
    expect(f?.fix?.statement).toMatchObject({
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
    });
  });

  it('matches catalogue entries through globs', () => {
    expect(
      findingsFor('missing-mfa-condition', {
        Effect: 'Allow',
        Action: 'ec2:Terminate*',
        Resource: '*',
      })[0]?.actions,
    ).toEqual(['ec2:TerminateInstances']);
    expect(
      findingsFor('missing-mfa-condition', { Effect: 'Allow', NotAction: 's3:*', Resource: '*' }),
    ).toHaveLength(1);
  });

  it('is satisfied by aws:MultiFactorAuthPresent or aws:MultiFactorAuthAge', () => {
    expect(
      findingsFor('missing-mfa-condition', {
        Effect: 'Allow',
        Action: 'iam:CreateUser',
        Resource: '*',
        Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('missing-mfa-condition', {
        Effect: 'Allow',
        Action: 'iam:CreateUser',
        Resource: '*',
        Condition: { NumericLessThan: { 'aws:MultiFactorAuthAge': '3600' } },
      }),
    ).toHaveLength(0);
  });

  it('skips non-sensitive actions, Deny statements and resource policies', () => {
    expect(
      findingsFor('missing-mfa-condition', {
        Effect: 'Allow',
        Action: ['s3:GetObject', 'sqs:SendMessage'],
        Resource: '*',
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('missing-mfa-condition', { Effect: 'Deny', Action: 'iam:*', Resource: '*' }),
    ).toHaveLength(0);
    expect(
      findingsFor('missing-mfa-condition', {
        Effect: 'Allow',
        Principal: '*',
        Action: 'kms:ScheduleKeyDeletion',
        Resource: '*',
      }),
    ).toHaveLength(0);
  });
});

describe('missing-secure-transport', () => {
  const read = {
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::1:root' },
    Action: 's3:GetObject',
    Resource: bucket,
  };

  it('flags an S3 bucket policy with no TLS deny and proposes the statement', () => {
    const [f] = findingsFor('missing-secure-transport', [read]);
    expect(f).toMatchObject({ severity: 'medium', statementIndex: null, path: 'Policy' });
    expect(f?.fix?.statement).toMatchObject({
      Effect: 'Deny',
      Resource: ['arn:aws:s3:::b', 'arn:aws:s3:::b/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    });
  });

  it('is satisfied by a Deny on aws:SecureTransport false (string or boolean)', () => {
    const deny = {
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: bucket,
      Condition: { Bool: { 'aws:SecureTransport': false } },
    };
    expect(findingsFor('missing-secure-transport', [read, deny])).toHaveLength(0);
  });

  it('is not satisfied by an Allow on SecureTransport true or a Deny on true', () => {
    const wrong = {
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: bucket,
      Condition: { Bool: { 'aws:SecureTransport': 'true' } },
    };
    expect(findingsFor('missing-secure-transport', [read, wrong])).toHaveLength(1);
  });

  it('ignores identity policies and non-S3 resource policies', () => {
    expect(
      findingsFor('missing-secure-transport', {
        Effect: 'Allow',
        Action: 's3:GetObject',
        Resource: bucket,
      }),
    ).toHaveLength(0);
    expect(
      findingsFor('missing-secure-transport', {
        Effect: 'Allow',
        Principal: '*',
        Action: 'sqs:SendMessage',
        Resource: 'arn:aws:sqs:::q',
      }),
    ).toHaveLength(0);
  });
});

describe('cross-account-trust', () => {
  const trust = (principal: unknown, condition?: unknown) => ({
    Effect: 'Allow',
    Principal: principal,
    Action: 'sts:AssumeRole',
    ...(condition ? { Condition: condition } : {}),
  });

  it('flags trusting an account root with no ExternalId / MFA / org condition', () => {
    expect(
      findingsFor('cross-account-trust', trust({ AWS: 'arn:aws:iam::999988887777:root' })),
    ).toHaveLength(1);
    expect(findingsFor('cross-account-trust', trust({ AWS: '999988887777' }))).toHaveLength(1);
  });

  it('is satisfied by sts:ExternalId, MFA or aws:PrincipalOrgID', () => {
    expect(
      findingsFor(
        'cross-account-trust',
        trust({ AWS: '999988887777' }, { StringEquals: { 'sts:ExternalId': 'abc' } }),
      ),
    ).toHaveLength(0);
    expect(
      findingsFor(
        'cross-account-trust',
        trust({ AWS: '999988887777' }, { Bool: { 'aws:MultiFactorAuthPresent': 'true' } }),
      ),
    ).toHaveLength(0);
    expect(
      findingsFor(
        'cross-account-trust',
        trust({ AWS: '999988887777' }, { StringEquals: { 'aws:PrincipalOrgID': 'o-1' } }),
      ),
    ).toHaveLength(0);
  });

  it('ignores specific role ARNs and service principals', () => {
    expect(
      findingsFor('cross-account-trust', trust({ AWS: 'arn:aws:iam::999988887777:role/deploy' })),
    ).toHaveLength(0);
    expect(
      findingsFor('cross-account-trust', trust({ Service: 'lambda.amazonaws.com' })),
    ).toHaveLength(0);
  });
});
