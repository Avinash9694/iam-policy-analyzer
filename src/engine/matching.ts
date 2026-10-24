const globCache = new Map<string, RegExp>();

function escapeRegex(text: string): string {
  return text.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/** Compiles an IAM glob (`*` any run, `?` one char) to a case-insensitive anchored RegExp. */
export function globToRegExp(pattern: string): RegExp {
  const cached = globCache.get(pattern);
  if (cached) return cached;
  const source = pattern.split('*').map((part) => part.split('?').map(escapeRegex).join('.'));
  const regex = new RegExp(`^${source.join('.*')}$`, 'i');
  globCache.set(pattern, regex);
  return regex;
}

/** Whether an IAM action pattern (`s3:Get*`, `iam:*`, `*`) matches a concrete action. */
export function actionMatches(pattern: string, action: string): boolean {
  if (pattern === '*') return true;
  return globToRegExp(pattern).test(action);
}

export function anyActionMatches(patterns: readonly string[], action: string): boolean {
  return patterns.some((pattern) => actionMatches(pattern, action));
}

export function splitAction(action: string): { service: string; name: string } | undefined {
  const idx = action.indexOf(':');
  if (idx <= 0 || idx === action.length - 1) return undefined;
  return { service: action.slice(0, idx).toLowerCase(), name: action.slice(idx + 1) };
}

export function isFullWildcard(value: string): boolean {
  return value.trim() === '*';
}

export function isServiceWildcard(action: string): boolean {
  const parts = splitAction(action);
  return parts?.name === '*';
}

function hasWildcard(value: string): boolean {
  return value.includes('*') || value.includes('?');
}

/** Subsumption of one glob segment by another, erring on the side of "not covered". */
function segmentCovers(broad: string, narrow: string): boolean {
  if (broad === '*' || broad.toLowerCase() === narrow.toLowerCase()) return true;
  if (!hasWildcard(narrow)) return globToRegExp(broad).test(narrow);
  const star = broad.indexOf('*');
  if (star !== -1 && star === broad.length - 1 && !broad.includes('?')) {
    return narrow.toLowerCase().startsWith(broad.slice(0, star).toLowerCase());
  }
  return false;
}

/**
 * Conservative check that `broad` (an action or resource pattern) covers everything
 * `narrow` covers. Exact glob subsumption is hard; patterns are compared colon-segment
 * by colon-segment (ARN fields, `service:Action`) so `arn:aws:ec2:*:*:instance/*` covers
 * `arn:aws:ec2:*:*:instance/i-1` even though both carry wildcards.
 */
export function resourceCovers(broad: string, narrow: string): boolean {
  if (broad === '*' || broad === narrow) return true;
  if (segmentCovers(broad, narrow)) return true;
  const b = broad.split(':');
  const n = narrow.split(':');
  if (b.length !== n.length || b.length < 2) return false;
  return b.every((segment, i) => segmentCovers(segment, n[i] ?? ''));
}

/** Whether a set of resource patterns covers each of another set's patterns. */
export function resourcesCover(broad: readonly string[], narrow: readonly string[]): boolean {
  if (narrow.length === 0) return broad.includes('*');
  return narrow.every((n) => broad.some((b) => resourceCovers(b, n)));
}

/** Whether two action patterns could match a common action (conservative: true when unsure). */
export function actionPatternsMayOverlap(a: string, b: string): boolean {
  if (a === '*' || b === '*') return true;
  const sa = splitAction(a);
  const sb = splitAction(b);
  if (!sa || !sb) return true;
  if (!hasWildcard(sa.service) && !hasWildcard(sb.service) && sa.service !== sb.service)
    return false;
  if (!hasWildcard(a)) return actionMatches(b, a);
  if (!hasWildcard(b)) return actionMatches(a, b);
  return true;
}
