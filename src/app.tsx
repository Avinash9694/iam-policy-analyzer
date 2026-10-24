import { useCallback, useEffect, useMemo, useState } from 'react';
import { AppFooter } from './components/app-footer';
import { AppHeader } from './components/app-header';
import { FindingsPanel } from './components/findings-panel';
import { PolicyEditor } from './components/policy-editor';
import type { Finding } from './engine';
import { useAnalysis } from './hooks/use-analysis';
import { usePolicyText } from './hooks/use-policy-text';
import { useTheme } from './hooks/use-theme';

export function App() {
  const { theme, toggle } = useTheme();
  const [text, setText] = usePolicyText();
  const { state } = useAnalysis(text);
  const [selected, setSelected] = useState<Finding | null>(null);

  useEffect(() => {
    setSelected(null);
  }, [text]);

  const highlight = useMemo(() => {
    if (!selected) return null;
    if (state.kind !== 'done' || !state.ok) return null;
    const current = state.result.findings.find((f) => f.id === selected.id);
    return current ? current.span : null;
  }, [selected, state]);

  const errorLine = state.kind === 'done' && !state.ok ? (state.errors[0]?.line ?? null) : null;

  const pickSample = useCallback(
    (sample: string) => {
      setText(sample);
    },
    [setText],
  );

  return (
    <div className="flex min-h-full flex-col lg:h-dvh">
      <AppHeader theme={theme} onToggleTheme={toggle} policyText={text} onPickSample={pickSample} />
      <main className="mx-auto grid w-full min-w-0 max-w-[1600px] flex-1 grid-cols-1 gap-4 p-4 sm:p-6 lg:min-h-0 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
        <div className="flex min-h-[360px] min-w-0 flex-col lg:min-h-0">
          <PolicyEditor
            value={text}
            onChange={setText}
            highlight={highlight}
            errorLine={errorLine}
            onClear={() => {
              setText('');
            }}
          />
        </div>
        <div className="flex min-h-[420px] min-w-0 flex-col lg:min-h-0">
          <FindingsPanel
            state={state}
            selectedId={selected?.id ?? null}
            onSelect={setSelected}
            onPickSample={pickSample}
          />
        </div>
      </main>
      <AppFooter />
    </div>
  );
}
