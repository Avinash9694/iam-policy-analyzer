import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../app';
import { SAMPLES } from '@/data/samples';

beforeEach(() => {
  window.location.hash = '';
  window.localStorage.clear();
});

describe('App', () => {
  it('shows the empty state and the local-analysis badge', () => {
    render(<App />);
    expect(
      screen.getByRole('heading', { name: /paste a policy to analyse it/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/analysis runs locally in your browser/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /copy link/i })).toBeDisabled();
  });

  it('loads a sample, lists findings grouped by severity and highlights the statement on click', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'PassRole escalation' }));

    expect(
      await screen.findByRole('img', { name: /risk score 9\d out of 100/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/critical risk/i).length).toBeGreaterThan(0);
    const editor = screen.getByLabelText(/policy document/i);
    expect(editor).toHaveValue(SAMPLES.find((s) => s.id === 'pass-role')?.text);

    const card = screen.getAllByRole('button', { name: /privilege-escalation path/i })[0]!;
    await user.click(card);
    expect(card).toHaveAttribute('aria-expanded', 'true');
    const panel = document.getElementById(card.getAttribute('aria-controls')!)!;
    expect(
      within(panel).getByRole('button', { name: /copy fixed statement/i }),
    ).toBeInTheDocument();
    expect(within(panel).getByText(/why it matters/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /copy link/i })).toBeEnabled();
  });

  it('shows a parse error pointing at the offending line', async () => {
    const user = userEvent.setup();
    render(<App />);
    const editor = screen.getByLabelText(/policy document/i);
    await user.click(editor);
    await user.paste(
      '{\n  "Version": "2012-10-17",\n  "Statement": [\n    { "Effect": "Maybe", "Action": "*", "Resource": "*" }\n  ]\n}',
    );
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText(/line 4/)).toBeInTheDocument();
    expect(within(alert).getByText(/Effect must be exactly "Allow" or "Deny"/)).toBeInTheDocument();
  });

  it('filters findings by severity chip', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Full admin (inline)' }));
    await screen.findByRole('img', { name: /risk score/i });
    const chips = screen.getByRole('group', { name: /filter by severity/i });
    const critical = within(chips).getByRole('button', { name: /^critical/i });
    expect(screen.getByRole('heading', { name: /^critical/i })).toBeInTheDocument();
    await user.click(critical);
    expect(critical).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByRole('heading', { name: /^critical/i })).not.toBeInTheDocument();
  });

  it('toggles and persists the theme', async () => {
    const user = userEvent.setup();
    render(<App />);
    const toggle = screen.getByRole('button', { name: /switch to (light|dark) theme/i });
    const before = document.documentElement.dataset.theme;
    await user.click(toggle);
    expect(document.documentElement.dataset.theme).not.toBe(before);
    expect(window.localStorage.getItem('iam-analyzer:theme')).toBe(
      document.documentElement.dataset.theme,
    );
  });
});
