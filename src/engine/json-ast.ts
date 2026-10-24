/**
 * Minimal position-tracking JSON parser. The standard JSON.parse gives no
 * source locations, and we need per-statement line ranges for highlighting
 * and precise error positions for the parse-error state.
 */

export interface Position {
  line: number;
  column: number;
  offset: number;
}

export interface Loc {
  start: Position;
  end: Position;
}

export interface JsonProperty {
  key: string;
  keyLoc: Loc;
  value: JsonNode;
}

export type JsonNode =
  | { type: 'object'; properties: JsonProperty[]; loc: Loc }
  | { type: 'array'; elements: JsonNode[]; loc: Loc }
  | { type: 'string'; value: string; loc: Loc }
  | { type: 'number'; value: number; loc: Loc }
  | { type: 'boolean'; value: boolean; loc: Loc }
  | { type: 'null'; loc: Loc };

export class JsonSyntaxError extends Error {
  constructor(
    message: string,
    public readonly position: Position,
  ) {
    super(message);
    this.name = 'JsonSyntaxError';
  }
}

class Parser {
  private index = 0;
  private line = 1;
  private column = 1;

  constructor(private readonly text: string) {}

  parse(): JsonNode {
    this.skipWhitespace();
    if (this.index >= this.text.length) {
      throw this.error('Policy is empty — paste a JSON policy document');
    }
    const node = this.parseValue();
    this.skipWhitespace();
    if (this.index < this.text.length) {
      throw this.error(`Unexpected ${this.describeCurrent()} after the end of the document`);
    }
    return node;
  }

  private position(): Position {
    return { line: this.line, column: this.column, offset: this.index };
  }

  private error(message: string): JsonSyntaxError {
    return new JsonSyntaxError(message, this.position());
  }

  private describeCurrent(): string {
    const ch = this.text[this.index];
    if (ch === undefined) return 'end of input';
    if (ch === '\n') return 'line break';
    return `'${ch}'`;
  }

  private advance(count = 1): void {
    for (let i = 0; i < count; i += 1) {
      const ch = this.text[this.index];
      if (ch === undefined) return;
      this.index += 1;
      if (ch === '\n') {
        this.line += 1;
        this.column = 1;
      } else {
        this.column += 1;
      }
    }
  }

  private skipWhitespace(): void {
    while (this.index < this.text.length) {
      const ch = this.text[this.index];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
        this.advance();
      } else if (ch === '/' && this.text[this.index + 1] === '/') {
        throw this.error('Comments are not allowed in a JSON policy document');
      } else {
        return;
      }
    }
  }

  private parseValue(): JsonNode {
    const ch = this.text[this.index];
    switch (ch) {
      case '{':
        return this.parseObject();
      case '[':
        return this.parseArray();
      case '"':
        return this.parseString();
      case 't':
        return this.parseLiteral('true', { type: 'boolean', value: true });
      case 'f':
        return this.parseLiteral('false', { type: 'boolean', value: false });
      case 'n':
        return this.parseLiteral('null', { type: 'null' });
      default:
        if (ch === '-' || (ch !== undefined && ch >= '0' && ch <= '9')) {
          return this.parseNumber();
        }
        if (ch === "'") {
          throw this.error('Strings must use double quotes, not single quotes');
        }
        throw this.error(`Unexpected ${this.describeCurrent()} — expected a value`);
    }
  }

  private parseLiteral(
    word: string,
    node: { type: 'boolean'; value: boolean } | { type: 'null' },
  ): JsonNode {
    const start = this.position();
    if (!this.text.startsWith(word, this.index)) {
      throw this.error(`Unexpected ${this.describeCurrent()} — expected a value`);
    }
    this.advance(word.length);
    return { ...node, loc: { start, end: this.position() } };
  }

  private parseNumber(): JsonNode {
    const start = this.position();
    const match = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(this.text.slice(this.index));
    if (!match) {
      throw this.error('Invalid number');
    }
    this.advance(match[0].length);
    return { type: 'number', value: Number(match[0]), loc: { start, end: this.position() } };
  }

  private parseString(): JsonNode & { type: 'string' } {
    const start = this.position();
    this.advance(); // opening quote
    let value = '';
    for (;;) {
      const ch = this.text[this.index];
      if (ch === undefined) {
        throw new JsonSyntaxError('Unterminated string', start);
      }
      if (ch === '\n') {
        throw new JsonSyntaxError('Unterminated string — line break inside a string', start);
      }
      if (ch === '"') {
        this.advance();
        break;
      }
      if (ch === '\\') {
        const next = this.text[this.index + 1];
        const simple: Record<string, string> = {
          '"': '"',
          '\\': '\\',
          '/': '/',
          b: '\b',
          f: '\f',
          n: '\n',
          r: '\r',
          t: '\t',
        };
        if (next !== undefined && next in simple) {
          value += simple[next] ?? '';
          this.advance(2);
        } else if (next === 'u') {
          const hex = this.text.slice(this.index + 2, this.index + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw this.error('Invalid unicode escape sequence');
          }
          value += String.fromCharCode(parseInt(hex, 16));
          this.advance(6);
        } else {
          throw this.error(`Invalid escape sequence '\\${next ?? ''}'`);
        }
        continue;
      }
      value += ch;
      this.advance();
    }
    return { type: 'string', value, loc: { start, end: this.position() } };
  }

  private parseArray(): JsonNode {
    const start = this.position();
    this.advance();
    const elements: JsonNode[] = [];
    this.skipWhitespace();
    if (this.text[this.index] === ']') {
      this.advance();
      return { type: 'array', elements, loc: { start, end: this.position() } };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] === ']') {
        throw this.error('Trailing comma before closing bracket');
      }
      elements.push(this.parseValue());
      this.skipWhitespace();
      const ch = this.text[this.index];
      if (ch === ',') {
        this.advance();
        continue;
      }
      if (ch === ']') {
        this.advance();
        return { type: 'array', elements, loc: { start, end: this.position() } };
      }
      throw this.error(`Unexpected ${this.describeCurrent()} — expected ',' or ']' in array`);
    }
  }

  private parseObject(): JsonNode {
    const start = this.position();
    this.advance();
    const properties: JsonProperty[] = [];
    this.skipWhitespace();
    if (this.text[this.index] === '}') {
      this.advance();
      return { type: 'object', properties, loc: { start, end: this.position() } };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] === '}') {
        throw this.error('Trailing comma before closing brace');
      }
      if (this.text[this.index] === "'") {
        throw this.error('Property names must use double quotes, not single quotes');
      }
      if (this.text[this.index] !== '"') {
        throw this.error(`Unexpected ${this.describeCurrent()} — expected a quoted property name`);
      }
      const keyNode = this.parseString();
      this.skipWhitespace();
      if (this.text[this.index] !== ':') {
        throw this.error(`Unexpected ${this.describeCurrent()} — expected ':' after property name`);
      }
      this.advance();
      this.skipWhitespace();
      const value = this.parseValue();
      properties.push({ key: keyNode.value, keyLoc: keyNode.loc, value });
      this.skipWhitespace();
      const ch = this.text[this.index];
      if (ch === ',') {
        this.advance();
        continue;
      }
      if (ch === '}') {
        this.advance();
        return { type: 'object', properties, loc: { start, end: this.position() } };
      }
      throw this.error(`Unexpected ${this.describeCurrent()} — expected ',' or '}' in object`);
    }
  }
}

export function parseJsonWithLocations(text: string): JsonNode {
  return new Parser(text).parse();
}

/** Converts an AST back to plain data, mirroring JSON.parse (last duplicate key wins). */
export function toPlain(node: JsonNode): unknown {
  switch (node.type) {
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const prop of node.properties) out[prop.key] = toPlain(prop.value);
      return out;
    }
    case 'array':
      return node.elements.map(toPlain);
    case 'null':
      return null;
    default:
      return node.value;
  }
}

export function getProperty(node: JsonNode, key: string): JsonProperty | undefined {
  if (node.type !== 'object') return undefined;
  // Last duplicate wins, matching JSON.parse semantics.
  for (let i = node.properties.length - 1; i >= 0; i -= 1) {
    const prop = node.properties[i];
    if (prop?.key === key) return prop;
  }
  return undefined;
}
