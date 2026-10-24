import { useCallback, useEffect, useState } from 'react';
import { readStorage, writeStorage } from '@/lib/storage';

export type Theme = 'dark' | 'light';
const KEY = 'iam-analyzer:theme';

function systemTheme(): Theme {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'dark';
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function initialTheme(): Theme {
  const stored = readStorage(KEY);
  return stored === 'light' || stored === 'dark' ? stored : systemTheme();
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(initialTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === 'dark' ? 'light' : 'dark';
      writeStorage(KEY, next);
      return next;
    });
  }, []);

  return { theme, toggle };
}
