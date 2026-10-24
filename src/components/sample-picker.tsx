import { SAMPLES, getSample } from '@/data/samples';

interface Props {
  onPick: (text: string) => void;
}

export function SamplePicker({ onPick }: Props) {
  return (
    <label className="inline-flex h-10 min-w-0 flex-1 items-center gap-2 rounded-xl border border-border bg-surface-2 pl-3 text-sm text-fg-muted transition-colors focus-within:border-border-strong hover:border-border-strong md:flex-none">
      <span className="hidden sm:inline">Sample</span>
      <select
        aria-label="Load a sample policy"
        className="h-full min-w-0 flex-1 cursor-pointer truncate rounded-r-xl bg-transparent pr-3 text-sm font-medium text-fg outline-none"
        value=""
        onChange={(e) => {
          const sample = getSample(e.target.value);
          if (sample) onPick(sample.text);
        }}
      >
        <option value="" disabled>
          Choose a policy…
        </option>
        {SAMPLES.map((s) => (
          <option key={s.id} value={s.id}>
            {s.label}
          </option>
        ))}
      </select>
    </label>
  );
}
