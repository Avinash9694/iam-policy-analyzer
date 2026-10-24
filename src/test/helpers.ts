import { parsePolicy, runRules } from '@/engine';
import type { Finding, Policy } from '@/engine';
import { RULES } from '@/engine/rules';

type Json = Record<string, unknown>;

export function policyJson(statements: Json | Json[], extra: Json = {}): string {
  return JSON.stringify({ Version: '2012-10-17', ...extra, Statement: statements }, null, 2);
}

export function parse(statements: Json | Json[], extra: Json = {}): Policy {
  const result = parsePolicy(policyJson(statements, extra));
  if (!result.ok) {
    throw new Error(`expected a valid policy: ${result.errors.map((e) => e.message).join('; ')}`);
  }
  return result.policy;
}

export function parseErrors(text: string): string[] {
  const result = parsePolicy(text);
  return result.ok ? [] : result.errors.map((e) => e.message);
}

/** Runs a single rule in isolation (no Deny mitigation). */
export function findingsFor(
  ruleId: string,
  statements: Json | Json[],
  extra: Json = {},
): Finding[] {
  const rule = RULES.find((r) => r.id === ruleId);
  if (!rule) throw new Error(`unknown rule ${ruleId}`);
  return rule.check({ policy: parse(statements, extra) });
}

/** Runs the whole engine, including Deny mitigation. */
export function allFindings(statements: Json | Json[], extra: Json = {}): Finding[] {
  return runRules(parse(statements, extra));
}

export const ALLOW_ALL = { Effect: 'Allow', Action: '*', Resource: '*' };
