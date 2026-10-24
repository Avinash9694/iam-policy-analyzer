import { allFindings } from '@/test/helpers';

const active = (statements: Parameters<typeof allFindings>[0]) =>
  allFindings(statements).filter((f) => !f.mitigatedBy);
const mitigated = (statements: Parameters<typeof allFindings>[0]) =>
  allFindings(statements).filter((f) => f.mitigatedBy);

describe('deny mitigation', () => {
  it('never reports a Deny statement as risky', () => {
    expect(allFindings({ Effect: 'Deny', Action: '*', Resource: '*' })).toHaveLength(0);
    expect(allFindings({ Effect: 'Deny', NotAction: 's3:GetObject', Resource: '*' })).toHaveLength(
      0,
    );
  });

  it('marks an Allow finding mitigated when a Deny covers the same action and resource', () => {
    const findings = allFindings([
      { Sid: 'AllowIam', Effect: 'Allow', Action: 'iam:*', Resource: '*' },
      { Sid: 'DenyIam', Effect: 'Deny', Action: 'iam:*', Resource: '*' },
    ]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.mitigatedBy?.sid === 'DenyIam')).toBe(true);
    expect(findings[0]?.mitigatedBy?.reason).toMatch(/unconditional Deny/);
  });

  it('accepts a broader Deny (wildcard action, broader resource)', () => {
    expect(
      active([
        { Effect: 'Allow', Action: 's3:PutObject', Resource: '*' },
        { Effect: 'Deny', Action: '*', Resource: '*' },
      ]),
    ).toHaveLength(0);
    expect(
      active([
        {
          Effect: 'Allow',
          Action: 'ec2:TerminateInstances',
          Resource: 'arn:aws:ec2:*:*:instance/i-123',
        },
        { Effect: 'Deny', Action: 'ec2:Terminate*', Resource: 'arn:aws:ec2:*:*:instance/*' },
      ]),
    ).toHaveLength(0);
  });

  it('does not mitigate when the Deny is narrower or conditional', () => {
    expect(
      mitigated([
        { Effect: 'Allow', Action: 's3:PutObject', Resource: '*' },
        { Effect: 'Deny', Action: 's3:PutObject', Resource: 'arn:aws:s3:::one/*' },
      ]),
    ).toHaveLength(0);
    expect(
      mitigated([
        { Effect: 'Allow', Action: 's3:PutObject', Resource: '*' },
        {
          Effect: 'Deny',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        },
      ]),
    ).toHaveLength(0);
    expect(
      mitigated([
        { Effect: 'Allow', Action: ['s3:PutObject', 's3:DeleteObject'], Resource: '*' },
        { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' },
      ]),
    ).toHaveLength(0);
  });

  it('mitigates through Deny NotAction when the exclusions cannot overlap', () => {
    expect(
      mitigated([
        { Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: '*' },
        { Effect: 'Deny', NotAction: 's3:*', Resource: '*' },
      ]).length,
    ).toBeGreaterThan(0);
    expect(
      active([
        { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
        { Effect: 'Deny', NotAction: 's3:*', Resource: '*' },
      ]),
    ).toHaveLength(0);
    const partial = allFindings([
      { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
      { Effect: 'Deny', NotAction: ['s3:*', 'iam:Get*'], Resource: '*' },
    ]);
    expect(partial.filter((f) => !f.mitigatedBy).map((f) => f.ruleId)).toEqual([
      'service-wildcard',
      'missing-mfa-condition',
    ]);
    expect(partial.filter((f) => f.mitigatedBy).map((f) => f.ruleId)).toEqual([
      'privilege-escalation',
    ]);
  });

  it('sorts active findings before mitigated ones and by severity', () => {
    const findings = allFindings([
      { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
      { Effect: 'Deny', Action: 'iam:*', Resource: '*' },
      { Effect: 'Allow', Action: 'nosuch:Thing', Resource: '*' },
    ]);
    expect(findings[0]).toMatchObject({ ruleId: 'unknown-action', mitigatedBy: undefined });
    expect(findings.slice(1).every((f) => f.mitigatedBy)).toBe(true);
  });
});
