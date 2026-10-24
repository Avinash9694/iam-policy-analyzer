import { GitHubIcon, LinkedInIcon } from './icons';

export function AppFooter() {
  return (
    <footer className="border-t border-border bg-surface">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 py-3 text-xs text-fg-muted sm:px-6">
        <p>
          Built by{' '}
          <a
            href="https://avinash9694.github.io"
            className="font-medium text-fg underline-offset-2 hover:underline"
          >
            Avinash Sahu
          </a>
          . Static analysis only — it cannot see which actions a service actually supports on a
          given resource.{' '}
          <a
            href="https://github.com/Avinash9694/iam-policy-analyzer"
            className="text-fg underline-offset-2 hover:underline"
          >
            Source on GitHub
          </a>
          .
        </p>
        <div className="flex items-center gap-1">
          <a
            href="https://github.com/Avinash9694"
            aria-label="GitHub profile"
            className="grid size-10 place-items-center rounded-lg transition-colors hover:bg-surface-2 hover:text-fg"
          >
            <GitHubIcon size={18} />
          </a>
          <a
            href="https://www.linkedin.com/in/A-v-i-n-a-s-h/"
            aria-label="LinkedIn profile"
            className="grid size-10 place-items-center rounded-lg transition-colors hover:bg-surface-2 hover:text-fg"
          >
            <LinkedInIcon size={18} />
          </a>
        </div>
      </div>
    </footer>
  );
}
