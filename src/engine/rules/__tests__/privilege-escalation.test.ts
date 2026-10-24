import { findingsFor } from '@/test/helpers';

const esc = (statements: Parameters<typeof findingsFor>[1]) =>
  findingsFor('privilege-escalation', statements);

describe('privilege-escalation', () => {
  it.each([
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:AttachUserPolicy',
    'iam:AttachRolePolicy',
    'iam:AttachGroupPolicy',
    'iam:PutUserPolicy',
    'iam:PutRolePolicy',
    'iam:CreateAccessKey',
    'iam:UpdateLoginProfile',
    'iam:CreateLoginProfile',
  ])('flags %s on its own', (action) => {
    const findings = esc({ Effect: 'Allow', Action: action, Resource: '*' });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: 'critical', actions: [action] });
  });

  it('needs sts:AssumeRole alongside iam:UpdateAssumeRolePolicy', () => {
    expect(
      esc({
        Effect: 'Allow',
        Action: 'iam:UpdateAssumeRolePolicy',
        Resource: 'arn:aws:iam::1:role/x',
      }),
    ).toHaveLength(0);
    expect(
      esc({
        Effect: 'Allow',
        Action: ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
        Resource: 'arn:aws:iam::1:role/x',
      }),
    ).toHaveLength(1);
  });

  it.each([
    ['lambda:CreateFunction', 'lambda:InvokeFunction'],
    ['ec2:RunInstances'],
    ['cloudformation:CreateStack'],
    ['glue:CreateDevEndpoint'],
    ['sagemaker:CreateNotebookInstance', 'sagemaker:CreatePresignedNotebookInstanceUrl'],
  ])('flags iam:PassRole combined with %s', (...partners) => {
    const findings = esc({
      Effect: 'Allow',
      Action: ['iam:PassRole', ...partners],
      Resource: 'arn:aws:iam::1:role/x',
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.actions).toEqual(['iam:PassRole', ...partners]);
    expect(findings[0]?.fix?.statement).toMatchObject({
      Condition: { StringEquals: { 'iam:PassedToService': expect.any(String) } },
    });
  });

  it('does not flag iam:PassRole alone, or a partner alone', () => {
    expect(esc({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' })).toHaveLength(0);
    expect(esc({ Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' })).toHaveLength(
      0,
    );
    expect(
      esc({ Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: '*' }),
    ).toHaveLength(0);
  });

  it('combines actions granted across different statements', () => {
    const findings = esc([
      { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Sid: 'Run', Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      sid: 'Pass',
      actions: ['iam:PassRole', 'ec2:RunInstances'],
    });
  });

  it('matches wildcards in actions', () => {
    expect(esc({ Effect: 'Allow', Action: 'iam:Put*', Resource: '*' })[0]?.actions).toEqual([
      'iam:PutUserPolicy',
      'iam:PutRolePolicy',
      'iam:PutGroupPolicy',
    ]);
    expect(esc({ Effect: 'Allow', Action: 'iam:*', Resource: '*' }).length).toBeGreaterThan(0);
    expect(esc({ Effect: 'Allow', Action: '*', Resource: '*' })[0]?.message).toMatch(
      /\d+ escalation paths/,
    );
  });

  it('matches through NotAction', () => {
    expect(esc({ Effect: 'Allow', NotAction: 's3:*', Resource: '*' })).toHaveLength(1);
    expect(esc({ Effect: 'Allow', NotAction: ['iam:*', 'sts:*'], Resource: '*' })).toHaveLength(0);
  });

  it('flags sts:AssumeRole only on a wildcard resource', () => {
    expect(esc({ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' })).toHaveLength(1);
    expect(
      esc({ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::1:role/deploy' }),
    ).toHaveLength(0);
  });

  it('groups several paths from one statement into one finding', () => {
    const findings = esc({
      Effect: 'Allow',
      Action: ['iam:CreatePolicyVersion', 'iam:CreateAccessKey'],
      Resource: '*',
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('2 escalation paths');
  });

  it('ignores Deny statements', () => {
    expect(esc({ Effect: 'Deny', Action: 'iam:CreatePolicyVersion', Resource: '*' })).toHaveLength(
      0,
    );
  });
});
