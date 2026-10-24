import type { Rule } from '../types';
import { DOCS, makeFinding } from './helpers';

export const policyVersion: Rule = {
  id: 'policy-version',
  severity: 'info',
  title: 'Policy version is missing or outdated',
  explanation:
    'Without `"Version": "2012-10-17"` the policy is evaluated under the 2008 grammar, where policy variables such as `${aws:username}` are treated as literal strings. A policy relying on them would then match nothing.',
  remediation: 'Add `"Version": "2012-10-17"` as the first key of the document.',
  references: [DOCS.version],
  check({ policy }) {
    if (policy.version === '2012-10-17') return [];
    return [
      makeFinding(policyVersion, {
        statement: null,
        message:
          policy.version === undefined
            ? 'No "Version" key — the document defaults to the 2008-10-17 grammar.'
            : 'Version "2008-10-17" is the legacy grammar; policy variables are not supported.',
        span: { startLine: policy.span.startLine, endLine: policy.span.startLine },
        fix: {
          description: 'Declare the current policy language version.',
          statement: { Version: '2012-10-17' },
        },
      }),
    ];
  },
};
