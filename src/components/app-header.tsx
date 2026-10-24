import { useCopy } from '@/hooks/use-copy';
import type { Theme } from '@/hooks/use-theme';
import { buildShareUrl } from '@/lib/share';
import { CheckIcon, LinkIcon, LockIcon, MoonIcon, ShieldIcon, SunIcon } from './icons';
import { SamplePicker } from './sample-picker';

interface Props {
  theme: Theme;
  onToggleTheme: () => void;
  policyText: string;
  onPickSample: (text: string) => void;
}

export function AppHeader({ theme, onToggleTheme, policyText, onPickSample }: Props) {
  const share = useCopy();
  const canShare = policyText.trim().length > 0;

  return (
    <header className="border-b border-border bg-surface">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3 sm:px-6">
        <div className="flex min-w-0 flex-1 items-center gap-3 md:flex-none">
          <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
            <ShieldIcon size={20} />
          </span>
          <div className="min-w-0">
            <h1 className="truncate text-base font-semibold leading-tight">IAM Policy Analyzer</h1>
            <p className="truncate text-xs text-fg-muted">
              Wildcards, escalation paths, public access — with fixes
            </p>
          </div>
        </div>

        <span
          className="order-3 inline-flex w-full items-center gap-1.5 text-xs text-fg-muted md:order-none md:w-auto md:rounded-full md:border md:border-border md:bg-surface-2 md:px-2.5 md:py-1"
          title="The policy is parsed and analysed in this tab. Nothing is sent to a server."
        >
          <LockIcon size={12} />
          Analysis runs locally in your browser
        </span>

        <button
          type="button"
          onClick={onToggleTheme}
          className="grid size-10 shrink-0 place-items-center rounded-xl border border-border bg-surface-2 text-fg transition-colors hover:border-border-strong hover:bg-surface-3 md:order-last"
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {theme === 'dark' ? <SunIcon size={16} /> : <MoonIcon size={16} />}
        </button>

        <div className="order-2 flex w-full min-w-0 items-center gap-2 md:order-none md:ml-auto md:w-auto">
          <SamplePicker onPick={onPickSample} />
          <button
            type="button"
            onClick={() => void share.copy(buildShareUrl(policyText))}
            disabled={!canShare}
            className="inline-flex h-10 shrink-0 items-center gap-2 rounded-xl border border-border bg-surface-2 px-3 text-sm font-medium text-fg transition-colors hover:border-border-strong hover:bg-surface-3 disabled:cursor-not-allowed disabled:opacity-50"
            aria-live="polite"
          >
            {share.status === 'copied' ? <CheckIcon size={16} /> : <LinkIcon size={16} />}
            <span>
              {share.status === 'copied'
                ? 'Link copied'
                : share.status === 'failed'
                  ? 'Copy failed'
                  : 'Copy link'}
            </span>
          </button>
        </div>
      </div>
    </header>
  );
}
