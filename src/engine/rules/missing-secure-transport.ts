import type { Rule, Statement } from '../types';
import { DOCS, makeFinding } from './helpers';

function isS3Arn(resource: string): boolean {
  return /^arn:aws[a-z-]*:s3:::/i.test(resource) || resource === '*';
}

function deniesInsecureTransport(statement: Statement): boolean {
  if (statement.effect !== 'Deny') return false;
  const bool = statement.condition.Bool ?? statement.condition.BoolIfExists;
  if (!bool) return false;
  const entry = Object.entries(bool).find(([k]) => k.toLowerCase() === 'aws:securetransport');
  return entry?.[1].some((v) => v.toLowerCase() === 'false') ?? false;
}

export const missingSecureTransport: Rule = {
  id: 'missing-secure-transport',
  severity: 'medium',
  title: 'Bucket policy does not enforce TLS',
  explanation:
    'S3 accepts both HTTP and HTTPS by default. Without a Deny on `aws:SecureTransport = false`, clients can read and write objects over plaintext, exposing data and credentials in transit on any network path between them and S3.',
  remediation:
    'Add a Deny statement for `s3:*` on the bucket and its objects with `"Bool": {"aws:SecureTransport": "false"}`. This is one of the S3 security best practices and has no effect on well-behaved SDK clients, which already use HTTPS.',
  references: [DOCS.secureTransport, DOCS.bucketPolicy],
  check({ policy }) {
    if (policy.kind !== 'resource') return [];
    const s3Resources = policy.statements.flatMap((s) => s.resources.filter(isS3Arn));
    if (s3Resources.length === 0 || !s3Resources.some((r) => r !== '*')) return [];
    if (policy.statements.some(deniesInsecureTransport)) return [];
    const bucket =
      s3Resources.find((r) => r !== '*')?.replace(/\/.*$/, '') ?? 'arn:aws:s3:::my-bucket';
    const first = policy.statements[0];
    return [
      makeFinding(missingSecureTransport, {
        statement: null,
        message: 'No statement denies requests made without TLS (aws:SecureTransport = false).',
        span: first
          ? { startLine: policy.span.startLine, endLine: first.span.startLine - 1 }
          : policy.span,
        fix: {
          description: 'Add this Deny statement to the policy.',
          statement: {
            Sid: 'DenyInsecureTransport',
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:*',
            Resource: [bucket, `${bucket}/*`],
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          },
        },
      }),
    ];
  },
};
