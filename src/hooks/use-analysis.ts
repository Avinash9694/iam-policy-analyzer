import { useDeferredValue, useMemo } from 'react';
import { analyzePolicyText } from '@/engine';
import type { AnalyzeTextResult } from '@/engine';

export type AnalysisState = { kind: 'empty' } | ({ kind: 'done' } & AnalyzeTextResult);

export function useAnalysis(text: string): { state: AnalysisState; stale: boolean } {
  const deferred = useDeferredValue(text);
  const state = useMemo<AnalysisState>(() => {
    if (deferred.trim().length === 0) return { kind: 'empty' };
    return { kind: 'done', ...analyzePolicyText(deferred) };
  }, [deferred]);
  return { state, stale: deferred !== text };
}
