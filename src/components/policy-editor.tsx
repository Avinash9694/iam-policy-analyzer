import { useCallback, useEffect, useMemo, useRef } from 'react';
import type { SourceSpan } from '@/engine';

interface Props {
  value: string;
  onChange: (next: string) => void;
  highlight: SourceSpan | null;
  errorLine: number | null;
  onClear: () => void;
}

const LINE_HEIGHT_PX = 24;

export function PolicyEditor({ value, onChange, highlight, errorLine, onClear }: Props) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const backdropRef = useRef<HTMLDivElement>(null);

  const lineCount = useMemo(() => Math.max(1, value.split('\n').length), [value]);
  const lines = useMemo(() => Array.from({ length: lineCount }, (_, i) => i + 1), [lineCount]);

  const syncScroll = useCallback(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    if (gutterRef.current) gutterRef.current.scrollTop = ta.scrollTop;
    if (backdropRef.current) {
      backdropRef.current.scrollTop = ta.scrollTop;
      backdropRef.current.scrollLeft = ta.scrollLeft;
    }
  }, []);

  useEffect(() => {
    const target = highlight?.startLine ?? errorLine;
    const ta = textareaRef.current;
    if (!target || !ta) return;
    const top = (target - 1) * LINE_HEIGHT_PX;
    const visible = top >= ta.scrollTop && top + LINE_HEIGHT_PX <= ta.scrollTop + ta.clientHeight;
    if (!visible && typeof ta.scrollTo === 'function') {
      ta.scrollTo({ top: Math.max(0, top - ta.clientHeight / 3), behavior: 'smooth' });
    }
  }, [highlight, errorLine]);

  const isHighlighted = (line: number): boolean =>
    highlight !== null && line >= highlight.startLine && line <= highlight.endLine;

  return (
    <section
      aria-label="Policy editor"
      className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-card transition-colors focus-within:border-accent/60"
    >
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <label htmlFor="policy-input" className="text-sm font-medium">
          Policy document <span className="font-normal text-fg-muted">(JSON)</span>
        </label>
        <div className="flex items-center gap-3 text-xs text-fg-muted">
          <span className="font-mono tabular-nums" aria-live="off">
            {lineCount} {lineCount === 1 ? 'line' : 'lines'}
          </span>
          <button
            type="button"
            onClick={onClear}
            disabled={value.length === 0}
            className="h-8 rounded-lg px-2 text-xs font-medium text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg disabled:opacity-40"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="editor-text relative flex min-h-0 flex-1">
        <div
          ref={gutterRef}
          aria-hidden="true"
          className="hide-scroll w-12 shrink-0 select-none overflow-hidden border-r border-border bg-surface-2 py-3 text-right text-fg-subtle"
        >
          {lines.map((n) => (
            <div
              key={n}
              className={`pr-2 ${isHighlighted(n) ? 'bg-highlight text-accent' : ''} ${errorLine === n ? 'bg-sev-critical/20 text-sev-critical' : ''}`}
            >
              {n}
            </div>
          ))}
        </div>

        <div className="relative min-w-0 flex-1">
          <div
            ref={backdropRef}
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 overflow-hidden py-3"
          >
            {lines.map((n) => (
              <div
                key={n}
                className={`h-6 ${
                  isHighlighted(n)
                    ? 'border-l-2 border-[color:var(--highlight-border)] bg-highlight'
                    : errorLine === n
                      ? 'border-l-2 border-sev-critical bg-sev-critical/15'
                      : ''
                }`}
              />
            ))}
          </div>
          <textarea
            id="policy-input"
            ref={textareaRef}
            value={value}
            onChange={(e) => {
              onChange(e.target.value);
            }}
            onScroll={syncScroll}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            wrap="off"
            placeholder={'{\n  "Version": "2012-10-17",\n  "Statement": [ … ]\n}'}
            aria-describedby="editor-help"
            className="editor-textarea editor-text relative block h-full w-full resize-none overflow-auto whitespace-pre px-3 py-3 outline-none"
          />
        </div>
      </div>
      <p id="editor-help" className="sr-only">
        Paste an AWS IAM identity or resource policy. Findings update as you type and highlight the
        statement lines in this editor.
      </p>
    </section>
  );
}
