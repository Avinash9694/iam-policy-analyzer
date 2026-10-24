import { CONDITION_OPERATORS } from '../data/action-catalog';
import type { Rule } from '../types';
import { DOCS, describeTarget, makeFinding, rewriteStatement } from './helpers';

const QUALIFIER = /^(ForAllValues:|ForAnyValue:)?(.+?)(IfExists)?$/;
const BOOLEAN = new Set(['true', 'false']);

export function baseOperator(operator: string): string | undefined {
  const m = QUALIFIER.exec(operator);
  return m?.[2];
}

export const conditionSanity: Rule = {
  id: 'condition-sanity',
  severity: 'low',
  title: 'Condition is malformed or ineffective',
  explanation:
    'IAM accepts condition blocks it cannot evaluate as written. An unknown operator never matches (which for an Allow means the statement silently grants nothing, and for a Deny means it protects nothing); `Bool`/`Null` with non-boolean values and `StringEquals` on an IP key are common mistakes that defeat the intended guard.',
  remediation:
    'Use a documented operator for the key type: `IpAddress`/`NotIpAddress` for `aws:SourceIp`, `Bool` with "true"/"false", `Null` with "true"/"false", `ArnLike` for ARN patterns, `StringEquals`/`StringLike` for everything string-typed.',
  references: [DOCS.condition, DOCS.conditionKeys],
  check({ policy }) {
    return policy.statements.flatMap((s) =>
      Object.entries(s.condition).flatMap(([operator, keys]) => {
        const base = baseOperator(operator);
        if (!base || !CONDITION_OPERATORS.has(base)) {
          return [
            makeFinding(conditionSanity, {
              statement: s,
              element: 'Condition',
              key: operator,
              severity: 'medium',
              message: `${describeTarget(s)} uses unknown condition operator "${operator}" — it will never match.`,
            }),
          ];
        }
        const findings = [];
        const rawCondition = (s.raw.Condition ?? {}) as Record<string, Record<string, unknown>>;
        const rawKeys = rawCondition[operator] ?? {};
        for (const [key, values] of Object.entries(keys)) {
          const lowerKey = key.toLowerCase();
          if (
            (base === 'Bool' || base === 'Null') &&
            values.some((v) => !BOOLEAN.has(v.toLowerCase()))
          ) {
            findings.push(
              makeFinding(conditionSanity, {
                statement: s,
                element: 'Condition',
                key: `${operator}.${key}`,
                message: `${describeTarget(s)}: ${operator} on "${key}" has non-boolean value ${values.map((v) => `"${v}"`).join(', ')}.`,
                fix: {
                  description: 'Use the string "true" or "false".',
                  statement: rewriteStatement(s, {
                    Condition: { ...rawCondition, [operator]: { ...rawKeys, [key]: 'true' } },
                  }),
                },
              }),
            );
          }
          if (
            base.startsWith('String') &&
            (lowerKey === 'aws:sourceip' || lowerKey === 'aws:vpcsourceip')
          ) {
            findings.push(
              makeFinding(conditionSanity, {
                statement: s,
                element: 'Condition',
                key: `${operator}.${key}`,
                severity: 'medium',
                message: `${describeTarget(s)}: "${key}" compared with ${operator} — IP keys need IpAddress/NotIpAddress, or CIDR ranges will not match.`,
                fix: {
                  description: 'Compare IP addresses with the IpAddress operator.',
                  statement: rewriteStatement(s, {
                    Condition: {
                      ...rawCondition,
                      [operator]: Object.fromEntries(
                        Object.entries(rawKeys).filter(([k]) => k !== key),
                      ),
                      IpAddress: { ...(rawCondition.IpAddress ?? {}), [key]: rawKeys[key] },
                    },
                  }),
                },
              }),
            );
          }
        }
        return findings;
      }),
    );
  },
};
