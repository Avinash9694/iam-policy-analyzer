import { JsonSyntaxError, getProperty, parseJsonWithLocations, toPlain } from '../json-ast';

function fail(text: string): JsonSyntaxError {
  try {
    parseJsonWithLocations(text);
  } catch (e) {
    if (e instanceof JsonSyntaxError) return e;
    throw e;
  }
  throw new Error('expected a syntax error');
}

describe('json-ast', () => {
  it('round-trips values like JSON.parse', () => {
    const text = '{"a":[1,2.5,-3e2,true,false,null,"s\\n\\u0041"],"b":{"c":{}}}';
    expect(toPlain(parseJsonWithLocations(text))).toEqual(JSON.parse(text));
  });

  it('records line and column for nested nodes', () => {
    const node = parseJsonWithLocations('{\n  "Statement": [\n    { "Effect": "Allow" }\n  ]\n}');
    const statement = getProperty(node, 'Statement');
    expect(statement?.keyLoc.start).toMatchObject({ line: 2, column: 3 });
    expect(statement?.value.loc.start).toMatchObject({ line: 2, column: 16 });
    expect(statement?.value.loc.end.line).toBe(4);
    if (statement?.value.type !== 'array') throw new Error('expected array');
    expect(statement.value.elements[0]?.loc.start.line).toBe(3);
  });

  it('last duplicate key wins, like JSON.parse', () => {
    const node = parseJsonWithLocations('{"a": 1, "a": 2}');
    expect(toPlain(node)).toEqual({ a: 2 });
    if (node.type !== 'object') throw new Error('expected object');
    expect(getProperty(node, 'a')?.value).toMatchObject({ type: 'number', value: 2 });
  });

  it('reports a trailing comma with its position', () => {
    const error = fail('{\n  "a": 1,\n}');
    expect(error.message).toMatch(/trailing comma/i);
    expect(error.position).toMatchObject({ line: 3, column: 1 });
  });

  it('rejects single-quoted strings with a helpful message', () => {
    expect(fail("{'a': 1}").message).toMatch(/double quotes/);
  });

  it('rejects comments', () => {
    expect(fail('{\n // hi\n "a": 1}').message).toMatch(/comments are not allowed/i);
  });

  it('reports an unterminated string at its opening quote', () => {
    const error = fail('{"a": "oops\n}');
    expect(error.message).toMatch(/unterminated string/i);
    expect(error.position).toMatchObject({ line: 1, column: 7 });
  });

  it('rejects an empty document and trailing garbage', () => {
    expect(fail('   ').message).toMatch(/empty/i);
    expect(fail('{} {}').message).toMatch(/after the end/i);
  });

  it('rejects a missing colon and a bad escape', () => {
    expect(fail('{"a" 1}').message).toMatch(/expected ':'/);
    expect(fail('{"a": "\\x"}').message).toMatch(/invalid escape/i);
  });
});
