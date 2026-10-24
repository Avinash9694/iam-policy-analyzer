import { anyActionMatches, isFullWildcard } from '../matching';
import type {
  Finding,
  FindingFix,
  Policy,
  RuleMeta,
  SourceSpan,
  Statement,
  StatementElement,
} from '../types';

export const DOCS = {
  leastPrivilege:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
  wildcards:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html',
  notAction:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html',
  principal:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html',
  condition:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html',
  conditionKeys:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html',
  mfa: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html',
  secureTransport:
    'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html#transit',
  passRole: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html',
  confusedDeputy: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html',
  version:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html',
  actionsList:
    'https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html',
  bucketPolicy:
    'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html',
  trustPolicy:
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html',
} as const;

export function elementSpan(statement: Statement, element: StatementElement): SourceSpan {
  return statement.elementSpans[element] ?? statement.span;
}

export function statementPath(statement: Statement, element?: StatementElement): string {
  const base = `Statement[${statement.index}]`;
  return element ? `${base}.${element}` : base;
}

export interface FindingInput {
  statement: Statement | null;
  element?: StatementElement;
  message: string;
  fix?: FindingFix;
  severity?: Finding['severity'];
  span?: SourceSpan;
  /** Disambiguates several findings from one rule on one statement. */
  key?: string;
  /** Defaults to the statement's own Action list. */
  actions?: string[];
}

export function makeFinding(rule: RuleMeta, input: FindingInput): Finding {
  const { statement } = input;
  const path = statement ? statementPath(statement, input.element) : 'Policy';
  return {
    id: `${rule.id}:${path}${input.key ? `:${input.key}` : ''}`,
    ruleId: rule.id,
    severity: input.severity ?? rule.severity,
    title: rule.title,
    message: input.message,
    explanation: rule.explanation,
    remediation: rule.remediation,
    references: rule.references,
    statementIndex: statement ? statement.index : null,
    sid: statement?.sid,
    path,
    span:
      input.span ??
      (statement
        ? input.element
          ? elementSpan(statement, input.element)
          : statement.span
        : { startLine: 1, endLine: 1 }),
    fix: input.fix,
    actions: input.actions ?? statement?.actions ?? [],
    mitigatedBy: undefined,
  };
}

/** Whether the statement's Action/NotAction grants (or denies) a concrete action. */
export function statementCoversAction(statement: Statement, action: string): boolean {
  if (statement.notActions.length > 0) {
    return !anyActionMatches(statement.notActions, action);
  }
  return anyActionMatches(statement.actions, action);
}

export function allowStatements(policy: Policy): Statement[] {
  return policy.statements.filter((s) => s.effect === 'Allow');
}

export function denyStatements(policy: Policy): Statement[] {
  return policy.statements.filter((s) => s.effect === 'Deny');
}

/** Allow statements that grant `action`, irrespective of resource. */
export function statementsAllowing(policy: Policy, action: string): Statement[] {
  return allowStatements(policy).filter((s) => statementCoversAction(s, action));
}

export function hasWildcardResource(statement: Statement): boolean {
  return statement.resources.some(isFullWildcard);
}

export function hasCondition(statement: Statement): boolean {
  return Object.keys(statement.condition).length > 0;
}

/** All condition keys used in a statement, lower-cased, across every operator. */
export function conditionKeys(statement: Statement): string[] {
  const keys: string[] = [];
  for (const block of Object.values(statement.condition)) {
    for (const key of Object.keys(block)) keys.push(key.toLowerCase());
  }
  return keys;
}

export function hasConditionKey(statement: Statement, key: string): boolean {
  const wanted = key.toLowerCase();
  return conditionKeys(statement).some((k) => k === wanted || k === `${wanted}/`);
}

export function describeTarget(statement: Statement): string {
  return statement.sid
    ? `"${statement.sid}" (Statement[${statement.index}])`
    : `Statement[${statement.index}]`;
}

/** Copy of the raw statement with selected keys replaced; keeps key order readable. */
export function rewriteStatement(
  statement: Statement,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const order = [
    'Sid',
    'Effect',
    'Principal',
    'NotPrincipal',
    'Action',
    'NotAction',
    'Resource',
    'NotResource',
    'Condition',
  ];
  const merged: Record<string, unknown> = { ...statement.raw, ...patch };
  const out: Record<string, unknown> = {};
  for (const key of order) {
    if (key in merged && merged[key] !== undefined) out[key] = merged[key];
  }
  return out;
}

export function withCondition(
  statement: Statement,
  operator: string,
  key: string,
  value: unknown,
): Record<string, unknown> {
  const existing = (statement.raw.Condition ?? {}) as Record<string, Record<string, unknown>>;
  return {
    ...existing,
    [operator]: { ...(existing[operator] ?? {}), [key]: value },
  };
}
