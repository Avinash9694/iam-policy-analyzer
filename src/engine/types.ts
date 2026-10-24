export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Effect = 'Allow' | 'Deny';
export type PolicyKind = 'identity' | 'resource';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface SourceSpan {
  startLine: number;
  endLine: number;
}

/** `Principal: "*"` is `{ any: true }`; a map is `{ any: false, entries }`. */
export interface Principal {
  any: boolean;
  entries: { type: string; values: string[] }[];
}

/** operator -> condition key -> values (always arrays, keys kept in original case). */
export type ConditionBlock = Record<string, Record<string, string[]>>;

export interface Statement {
  index: number;
  sid: string | undefined;
  effect: Effect;
  actions: string[];
  notActions: string[];
  resources: string[];
  notResources: string[];
  principal: Principal | undefined;
  notPrincipal: Principal | undefined;
  condition: ConditionBlock;
  span: SourceSpan;
  /** Line spans of individual elements, for precise highlighting. */
  elementSpans: Partial<Record<StatementElement, SourceSpan>>;
  raw: Record<string, unknown>;
}

export type StatementElement =
  | 'Sid'
  | 'Effect'
  | 'Action'
  | 'NotAction'
  | 'Resource'
  | 'NotResource'
  | 'Principal'
  | 'NotPrincipal'
  | 'Condition';

export interface Policy {
  version: string | undefined;
  id: string | undefined;
  kind: PolicyKind;
  statements: Statement[];
  span: SourceSpan;
}

export interface ParseError {
  message: string;
  line: number | undefined;
  column: number | undefined;
  /** JSON-pointer-ish path such as `Statement[1].Effect`. */
  path: string | undefined;
}

export type ParseResult =
  { ok: true; policy: Policy; warnings: string[] } | { ok: false; errors: ParseError[] };

export interface FindingFix {
  description: string;
  /** Suggested replacement (or additional) statement. */
  statement: Record<string, unknown>;
}

export interface Mitigation {
  statementIndex: number;
  sid: string | undefined;
  reason: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  /** Short, specific to this occurrence. */
  message: string;
  explanation: string;
  remediation: string;
  references: string[];
  /** `null` for policy-level findings. */
  statementIndex: number | null;
  sid: string | undefined;
  /** Offending element path, e.g. `Statement[0].Action`. */
  path: string;
  span: SourceSpan;
  fix: FindingFix | undefined;
  /** Action patterns the finding is about; used to match neutralising Deny statements. */
  actions: string[];
  mitigatedBy: Mitigation | undefined;
}

export interface RuleMeta {
  id: string;
  severity: Severity;
  title: string;
  explanation: string;
  remediation: string;
  references: string[];
}

export interface RuleContext {
  policy: Policy;
}

export interface Rule extends RuleMeta {
  check(ctx: RuleContext): Finding[];
}

export type Verdict = 'clean' | 'low' | 'moderate' | 'high' | 'critical';

export interface RiskScore {
  score: number;
  verdict: Verdict;
  label: string;
  counts: Record<Severity, number>;
  mitigated: number;
}

export interface AnalysisResult {
  policy: Policy;
  findings: Finding[];
  score: RiskScore;
  warnings: string[];
}
