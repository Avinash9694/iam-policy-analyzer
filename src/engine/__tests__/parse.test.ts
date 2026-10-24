import { parsePolicy } from '../parse';
import { parse, parseErrors, policyJson } from '@/test/helpers';

describe('parsePolicy', () => {
  it('accepts a single statement object and normalises scalars to arrays', () => {
    const policy = parse({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' });
    expect(policy.statements).toHaveLength(1);
    expect(policy.statements[0]).toMatchObject({
      index: 0,
      effect: 'Allow',
      actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      notActions: [],
    });
    expect(policy.kind).toBe('identity');
  });

  it('accepts both policy versions and reports a missing one', () => {
    const v2008 = parsePolicy(
      JSON.stringify({
        Version: '2008-10-17',
        Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
      }),
    );
    expect(v2008.ok && v2008.policy.version).toBe('2008-10-17');
    const none = parsePolicy(
      JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }),
    );
    expect(none.ok && none.policy.version).toBeUndefined();
    expect(parseErrors(JSON.stringify({ Version: '2020-01-01', Statement: [] }))).toEqual(
      expect.arrayContaining([expect.stringMatching(/Version must be/)]),
    );
  });

  it('infers a resource policy from Principal and normalises its shapes', () => {
    const policy = parse([
      { Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' },
      {
        Effect: 'Allow',
        Principal: { AWS: ['arn:aws:iam::1:root', '*'], Service: 'lambda.amazonaws.com' },
        Action: 'sts:AssumeRole',
      },
    ]);
    expect(policy.kind).toBe('resource');
    expect(policy.statements[0]?.principal).toEqual({ any: true, entries: [] });
    expect(policy.statements[1]?.principal).toEqual({
      any: false,
      entries: [
        { type: 'AWS', values: ['arn:aws:iam::1:root', '*'] },
        { type: 'Service', values: ['lambda.amazonaws.com'] },
      ],
    });
  });

  it('normalises condition values to string arrays', () => {
    const policy = parse({
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: '*',
      Condition: {
        Bool: { 'aws:SecureTransport': true },
        StringEquals: { 'aws:PrincipalOrgID': ['o-1', 'o-2'] },
        NumericLessThan: { 'aws:MultiFactorAuthAge': 3600 },
      },
    });
    expect(policy.statements[0]?.condition).toEqual({
      Bool: { 'aws:SecureTransport': ['true'] },
      StringEquals: { 'aws:PrincipalOrgID': ['o-1', 'o-2'] },
      NumericLessThan: { 'aws:MultiFactorAuthAge': ['3600'] },
    });
  });

  it('records line spans for statements and their elements', () => {
    const text = policyJson([
      { Sid: 'A', Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: '*' },
      { Sid: 'B', Effect: 'Deny', Action: '*', Resource: '*' },
    ]);
    const result = parsePolicy(text);
    if (!result.ok) throw new Error('expected ok');
    const [a, b] = result.policy.statements;
    expect(a?.span).toEqual({ startLine: 4, endLine: 12 });
    expect(a?.elementSpans.Action).toEqual({ startLine: 7, endLine: 10 });
    expect(b?.span.startLine).toBe(13);
  });

  it('flags an unknown top-level key with a spelling hint', () => {
    const errors = parseErrors(
      JSON.stringify({
        version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
      }),
    );
    expect(errors).toEqual([
      expect.stringContaining('Unknown top-level key "version" — did you mean "Version"?'),
    ]);
  });

  it('flags an invalid or missing Effect', () => {
    expect(parseErrors(policyJson({ Effect: 'allow', Action: '*', Resource: '*' }))).toEqual([
      expect.stringMatching(/Effect must be exactly "Allow" or "Deny".*got "allow"/),
    ]);
    expect(parseErrors(policyJson({ Action: '*', Resource: '*' }))).toEqual([
      expect.stringMatching(/missing "Effect"/),
    ]);
  });

  it('requires Resource on identity-policy statements but not on resource policies', () => {
    expect(parseErrors(policyJson({ Effect: 'Allow', Action: 's3:GetObject' }))).toEqual([
      expect.stringMatching(/Statement\[0\] has no "Resource" or "NotResource"/),
    ]);
    expect(
      parseErrors(
        policyJson({
          Effect: 'Allow',
          Action: 'sts:AssumeRole',
          Principal: { Service: 'ec2.amazonaws.com' },
        }),
      ),
    ).toEqual([]);
  });

  it('rejects conflicting and missing element pairs', () => {
    expect(
      parseErrors(policyJson({ Effect: 'Allow', Action: '*', NotAction: 'iam:*', Resource: '*' })),
    ).toEqual([expect.stringMatching(/cannot have both "Action" and "NotAction"/)]);
    expect(parseErrors(policyJson({ Effect: 'Allow', Resource: '*' }))).toEqual([
      expect.stringMatching(/must have "Action" or "NotAction"/),
    ]);
    expect(
      parseErrors(
        policyJson({ Effect: 'Allow', Action: '*', Resource: '*', NotResource: 'arn:x' }),
      ),
    ).toEqual([expect.stringMatching(/cannot have both "Resource" and "NotResource"/)]);
  });

  it('rejects unknown statement keys, bad element types and empty arrays', () => {
    expect(parseErrors(policyJson({ Effect: 'Allow', Actions: '*', Resource: '*' }))).toEqual(
      expect.arrayContaining([
        expect.stringContaining('Unknown statement key "Actions" — did you mean "Action"?'),
      ]),
    );
    expect(parseErrors(policyJson({ Effect: 'Allow', Action: 42, Resource: '*' }))).toEqual([
      expect.stringMatching(/Action must be a string or an array of strings/),
    ]);
    expect(parseErrors(policyJson({ Effect: 'Allow', Action: [], Resource: '*' }))).toEqual([
      expect.stringMatching(/must not be an empty array/),
    ]);
  });

  it('rejects malformed Principal and Statement containers', () => {
    expect(
      parseErrors(
        policyJson({ Effect: 'Allow', Principal: 'arn:aws:iam::1:root', Action: 'sts:AssumeRole' }),
      ),
    ).toEqual([expect.stringMatching(/Principal as a string must be "\*"/)]);
    expect(
      parseErrors(
        policyJson({ Effect: 'Allow', Principal: { Account: '1' }, Action: 'sts:AssumeRole' }),
      ),
    ).toEqual([expect.stringMatching(/Unknown principal type "Account"/)]);
    expect(parseErrors(JSON.stringify({ Version: '2012-10-17' }))).toEqual([
      expect.stringMatching(/missing the "Statement" key/),
    ]);
    expect(parseErrors(JSON.stringify({ Version: '2012-10-17', Statement: 'x' }))).toEqual([
      expect.stringMatching(/Statement must be an object or an array/),
    ]);
    expect(parseErrors('[1]')).toEqual([expect.stringMatching(/must be a JSON object/)]);
  });

  it('surfaces a JSON syntax error with its line', () => {
    const result = parsePolicy(
      '{\n  "Version": "2012-10-17",\n  "Statement": [\n    { "Effect": "Allow", }\n  ]\n}',
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]).toMatchObject({
      line: 4,
      message: expect.stringMatching(/trailing comma/i),
    });
  });

  it('warns about duplicate and non-alphanumeric Sids without failing', () => {
    const result = parsePolicy(
      policyJson([
        { Sid: 'Same', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
        { Sid: 'Same', Effect: 'Allow', Action: 's3:ListBucket', Resource: '*' },
        { Sid: 'has-dash', Effect: 'Allow', Action: 's3:ListBucket', Resource: '*' },
      ]),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.warnings).toEqual([
      expect.stringMatching(/has-dash/),
      expect.stringMatching(/reuses Sid "Same"/),
    ]);
  });
});
