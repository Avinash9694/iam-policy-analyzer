import { useCallback, useEffect, useRef, useState } from 'react';
import { decodePolicyHash, encodePolicyHash } from '@/lib/share';

/** Policy text, kept in sync with the URL hash so a link reproduces the analysis. */
export function usePolicyText(): [string, (next: string) => void] {
  const [text, setText] = useState<string>(() => decodePolicyHash(window.location.hash) ?? '');
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const hash = encodePolicyHash(text);
      const url = `${window.location.pathname}${window.location.search}${hash}`;
      if (window.location.hash !== hash) history.replaceState(null, '', url);
    }, 250);
    return () => {
      window.clearTimeout(timer.current);
    };
  }, [text]);

  useEffect(() => {
    const onHashChange = (): void => {
      const incoming = decodePolicyHash(window.location.hash);
      if (incoming !== null) setText(incoming);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => {
      window.removeEventListener('hashchange', onHashChange);
    };
  }, []);

  const update = useCallback((next: string) => {
    setText(next);
  }, []);
  return [text, update];
}
