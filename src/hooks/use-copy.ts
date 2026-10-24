import { useCallback, useEffect, useRef, useState } from 'react';
import { copyText } from '@/lib/clipboard';

export type CopyStatus = 'idle' | 'copied' | 'failed';

export function useCopy(resetMs = 1800): {
  status: CopyStatus;
  copy: (text: string) => Promise<void>;
} {
  const [status, setStatus] = useState<CopyStatus>('idle');
  const timer = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  const copy = useCallback(
    async (text: string) => {
      const ok = await copyText(text);
      setStatus(ok ? 'copied' : 'failed');
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => {
        setStatus('idle');
      }, resetMs);
    },
    [resetMs],
  );

  return { status, copy };
}
