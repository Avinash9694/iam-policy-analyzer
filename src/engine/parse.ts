import { getProperty, JsonSyntaxError, parseJsonWithLocations, toPlain } from './json-ast';
import type { JsonNode, JsonProperty } from './json-ast';
import type {
  ConditionBlock,
  Effect,
  ParseError,
  ParseResult,
  Policy,
  Principal,
  SourceSpan,
  Statement,
  StatementElement,
} from './types';

const TOP_LEVEL_KEYS = new Set(['Version', 'Id', 'Statement']);
const STATEMENT_KEYS: ReadonlySet<string> = new Set<StatementElement>([
  'Sid',
  'Effect',
  'Action',
  'NotAction',
  'Resource',
  'NotResource',
  'Principal',
  'NotPrincipal',
  'Condition',
]);
const VERSIONS = new Set(['2012-10-17', '2008-10-17']);
const PRINCIPAL_TYPES = new Set(['AWS', 'Service', 'Federated', 'CanonicalUser']);

function spanOf(node: JsonNode): SourceSpan {
  return { startLine: node.loc.start.line, endLine: node.loc.end.line };
}

function err(message: string, node: JsonNode | undefined, path: string): ParseError {
  return {
    message,
    line: node?.loc.start.line,
    column: node?.loc.start.column,
    path,
  };
}

function editDistance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    let diagonal = prev[0] ?? 0;
    prev[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const temp = prev[j] ?? 0;
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      prev[j] = Math.min(temp + 1, (prev[j - 1] ?? 0) + 1, diagonal + cost);
      diagonal = temp;
    }
  }
  return prev[b.length] ?? 0;
}

function suggestKey(key: string, known: ReadonlySet<string>): string | undefined {
  const lower = key.toLowerCase();
  let best: { candidate: string; distance: number } | undefined;
  for (const candidate of known) {
    const distance = editDistance(lower, candidate.toLowerCase());
    if (distance <= 2 && (!best || distance < best.distance)) best = { candidate, distance };
  }
  return best?.candidate;
}

class Collector {
  readonly errors: ParseError[] = [];
  readonly warnings: string[] = [];

  error(message: string, node: JsonNode | undefined, path: string): void {
    this.errors.push(err(message, node, path));
  }
}

function readStringList(prop: JsonProperty, path: string, out: Collector): string[] | undefined {
  const node = prop.value;
  if (node.type === 'string') return [node.value];
  if (node.type === 'array') {
    const values: string[] = [];
    node.elements.forEach((el, i) => {
      if (el.type === 'string') {
        values.push(el.value);
      } else {
        out.error(`${path}[${i}] must be a string`, el, `${path}[${i}]`);
      }
    });
    if (node.elements.length === 0) {
      out.error(`${path} must not be an empty array`, node, path);
    }
    return values;
  }
  out.error(`${path} must be a string or an array of strings`, node, path);
  return undefined;
}

function readPrincipal(prop: JsonProperty, path: string, out: Collector): Principal | undefined {
  const node = prop.value;
  if (node.type === 'string') {
    if (node.value === '*') return { any: true, entries: [] };
    out.error(
      `${path} as a string must be "*"; use {"AWS": "..."} for a specific principal`,
      node,
      path,
    );
    return { any: false, entries: [] };
  }
  if (node.type !== 'object') {
    out.error(`${path} must be "*" or an object such as {"AWS": "arn:..."}`, node, path);
    return { any: false, entries: [] };
  }
  const entries: Principal['entries'] = [];
  for (const entry of node.properties) {
    if (!PRINCIPAL_TYPES.has(entry.key)) {
      const hint = suggestKey(entry.key, PRINCIPAL_TYPES);
      out.error(
        `Unknown principal type "${entry.key}"${hint ? ` — did you mean "${hint}"?` : ''}`,
        entry.value,
        `${path}.${entry.key}`,
      );
      continue;
    }
    const values = readStringList(entry, `${path}.${entry.key}`, out);
    if (values) entries.push({ type: entry.key, values });
  }
  return { any: false, entries };
}

function readCondition(prop: JsonProperty, path: string, out: Collector): ConditionBlock {
  const block: ConditionBlock = {};
  const node = prop.value;
  if (node.type !== 'object') {
    out.error(`${path} must be an object keyed by condition operator`, node, path);
    return block;
  }
  for (const operator of node.properties) {
    if (operator.value.type !== 'object') {
      out.error(
        `${path}.${operator.key} must be an object keyed by condition key`,
        operator.value,
        `${path}.${operator.key}`,
      );
      continue;
    }
    const keys: Record<string, string[]> = {};
    for (const key of operator.value.properties) {
      const valueNode = key.value;
      const keyPath = `${path}.${operator.key}.${key.key}`;
      if (valueNode.type === 'string') {
        keys[key.key] = [valueNode.value];
      } else if (valueNode.type === 'boolean' || valueNode.type === 'number') {
        keys[key.key] = [String(valueNode.value)];
      } else if (valueNode.type === 'array') {
        keys[key.key] = valueNode.elements.map((el) =>
          el.type === 'string' || el.type === 'boolean' || el.type === 'number'
            ? String(el.value)
            : (out.error(`${keyPath} contains a non-scalar value`, el, keyPath), ''),
        );
      } else {
        out.error(`${keyPath} must be a string, boolean, number or array`, valueNode, keyPath);
      }
    }
    block[operator.key] = keys;
  }
  return block;
}

function readStatement(node: JsonNode, index: number, out: Collector): Statement | undefined {
  const path = `Statement[${index}]`;
  if (node.type !== 'object') {
    out.error(`${path} must be an object`, node, path);
    return undefined;
  }
  const elementSpans: Statement['elementSpans'] = {};
  for (const prop of node.properties) {
    if (!STATEMENT_KEYS.has(prop.key)) {
      const hint = suggestKey(prop.key, STATEMENT_KEYS);
      out.error(
        `Unknown statement key "${prop.key}"${hint ? ` — did you mean "${hint}"?` : ''}`,
        prop.value,
        `${path}.${prop.key}`,
      );
    } else {
      elementSpans[prop.key as StatementElement] = {
        startLine: prop.keyLoc.start.line,
        endLine: prop.value.loc.end.line,
      };
    }
  }

  let sid: string | undefined;
  const sidProp = getProperty(node, 'Sid');
  if (sidProp) {
    if (sidProp.value.type === 'string') {
      sid = sidProp.value.value;
      if (!/^[A-Za-z0-9]*$/.test(sid)) {
        out.warnings.push(
          `${path}.Sid "${sid}" contains characters outside A–Z, a–z, 0–9, which some services reject`,
        );
      }
    } else {
      out.error(`${path}.Sid must be a string`, sidProp.value, `${path}.Sid`);
    }
  }

  let effect: Effect | undefined;
  const effectProp = getProperty(node, 'Effect');
  if (!effectProp) {
    out.error(`${path} is missing "Effect" (must be "Allow" or "Deny")`, node, `${path}.Effect`);
  } else if (
    effectProp.value.type === 'string' &&
    (effectProp.value.value === 'Allow' || effectProp.value.value === 'Deny')
  ) {
    effect = effectProp.value.value;
  } else {
    const shown =
      effectProp.value.type === 'string' ? `"${effectProp.value.value}"` : effectProp.value.type;
    out.error(
      `${path}.Effect must be exactly "Allow" or "Deny" (case-sensitive), got ${shown}`,
      effectProp.value,
      `${path}.Effect`,
    );
  }

  const actionProp = getProperty(node, 'Action');
  const notActionProp = getProperty(node, 'NotAction');
  if (actionProp && notActionProp) {
    out.error(
      `${path} cannot have both "Action" and "NotAction"`,
      notActionProp.value,
      `${path}.NotAction`,
    );
  }
  if (!actionProp && !notActionProp) {
    out.error(`${path} must have "Action" or "NotAction"`, node, `${path}.Action`);
  }
  const actions = actionProp ? (readStringList(actionProp, `${path}.Action`, out) ?? []) : [];
  const notActions = notActionProp
    ? (readStringList(notActionProp, `${path}.NotAction`, out) ?? [])
    : [];

  const resourceProp = getProperty(node, 'Resource');
  const notResourceProp = getProperty(node, 'NotResource');
  if (resourceProp && notResourceProp) {
    out.error(
      `${path} cannot have both "Resource" and "NotResource"`,
      notResourceProp.value,
      `${path}.NotResource`,
    );
  }
  const resources = resourceProp
    ? (readStringList(resourceProp, `${path}.Resource`, out) ?? [])
    : [];
  const notResources = notResourceProp
    ? (readStringList(notResourceProp, `${path}.NotResource`, out) ?? [])
    : [];

  const principalProp = getProperty(node, 'Principal');
  const notPrincipalProp = getProperty(node, 'NotPrincipal');
  if (principalProp && notPrincipalProp) {
    out.error(
      `${path} cannot have both "Principal" and "NotPrincipal"`,
      notPrincipalProp.value,
      `${path}.NotPrincipal`,
    );
  }
  const principal = principalProp
    ? readPrincipal(principalProp, `${path}.Principal`, out)
    : undefined;
  const notPrincipal = notPrincipalProp
    ? readPrincipal(notPrincipalProp, `${path}.NotPrincipal`, out)
    : undefined;

  const conditionProp = getProperty(node, 'Condition');
  const condition = conditionProp ? readCondition(conditionProp, `${path}.Condition`, out) : {};

  if (!effect) return undefined;
  return {
    index,
    sid,
    effect,
    actions,
    notActions,
    resources,
    notResources,
    principal,
    notPrincipal,
    condition,
    span: spanOf(node),
    elementSpans,
    raw: toPlain(node) as Record<string, unknown>,
  };
}

export function parsePolicy(text: string): ParseResult {
  let root: JsonNode;
  try {
    root = parseJsonWithLocations(text);
  } catch (e) {
    if (e instanceof JsonSyntaxError) {
      return {
        ok: false,
        errors: [
          {
            message: e.message,
            line: e.position.line,
            column: e.position.column,
            path: undefined,
          },
        ],
      };
    }
    throw e;
  }

  const out = new Collector();
  if (root.type !== 'object') {
    out.error('A policy document must be a JSON object with a "Statement" key', root, '');
    return { ok: false, errors: out.errors };
  }

  for (const prop of root.properties) {
    if (!TOP_LEVEL_KEYS.has(prop.key)) {
      const hint = suggestKey(prop.key, TOP_LEVEL_KEYS);
      out.error(
        `Unknown top-level key "${prop.key}"${hint ? ` — did you mean "${hint}"?` : ''}`,
        prop.value,
        prop.key,
      );
    }
  }

  let version: string | undefined;
  const versionProp = getProperty(root, 'Version');
  if (versionProp) {
    if (versionProp.value.type === 'string' && VERSIONS.has(versionProp.value.value)) {
      version = versionProp.value.value;
    } else {
      const shown =
        versionProp.value.type === 'string'
          ? `"${versionProp.value.value}"`
          : versionProp.value.type;
      out.error(
        `Version must be "2012-10-17" or "2008-10-17", got ${shown}`,
        versionProp.value,
        'Version',
      );
    }
  }

  let id: string | undefined;
  const idProp = getProperty(root, 'Id');
  if (idProp) {
    if (idProp.value.type === 'string') id = idProp.value.value;
    else out.error('Id must be a string', idProp.value, 'Id');
  }

  const statementProp = getProperty(root, 'Statement');
  const statements: Statement[] = [];
  if (!statementProp) {
    out.error('Policy is missing the "Statement" key', root, 'Statement');
  } else {
    const node = statementProp.value;
    const nodes =
      node.type === 'array' ? node.elements : node.type === 'object' ? [node] : undefined;
    if (!nodes) {
      out.error('Statement must be an object or an array of objects', node, 'Statement');
    } else if (nodes.length === 0) {
      out.error('Statement must contain at least one statement', node, 'Statement');
    } else {
      nodes.forEach((n, i) => {
        const statement = readStatement(n, i, out);
        if (statement) statements.push(statement);
      });
    }
  }

  const kind: Policy['kind'] = statements.some((s) => s.principal ?? s.notPrincipal)
    ? 'resource'
    : 'identity';

  if (kind === 'identity') {
    for (const s of statements) {
      if (s.resources.length === 0 && s.notResources.length === 0) {
        out.error(
          `Statement[${s.index}] has no "Resource" or "NotResource" — required in an identity policy (use "*" deliberately if you must)`,
          statementProp?.value.type === 'array'
            ? statementProp.value.elements[s.index]
            : statementProp?.value,
          `Statement[${s.index}].Resource`,
        );
      }
    }
  } else {
    for (const s of statements) {
      if (!s.principal && !s.notPrincipal) {
        out.error(
          `Statement[${s.index}] has no "Principal" — every statement in a resource policy needs one`,
          statementProp?.value.type === 'array'
            ? statementProp.value.elements[s.index]
            : statementProp?.value,
          `Statement[${s.index}].Principal`,
        );
      }
    }
  }

  const seenSids = new Map<string, number>();
  for (const s of statements) {
    if (s.sid === undefined) continue;
    const prev = seenSids.get(s.sid);
    if (prev !== undefined) {
      out.warnings.push(
        `Statement[${s.index}] reuses Sid "${s.sid}" from Statement[${prev}]; Sids must be unique in most services`,
      );
    }
    seenSids.set(s.sid, s.index);
  }

  if (out.errors.length > 0) return { ok: false, errors: out.errors };
  return {
    ok: true,
    policy: { version, id, kind, statements, span: spanOf(root) },
    warnings: out.warnings,
  };
}
