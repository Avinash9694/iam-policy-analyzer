import { buildShareUrl, decodePolicyHash, encodePolicyHash } from '../share';

describe('share hash', () => {
  const text = '{\n  "Version": "2012-10-17",\n  "Statement": []\n}';

  it('round-trips policy text through the hash', () => {
    expect(decodePolicyHash(encodePolicyHash(text))).toBe(text);
  });

  it('produces an empty hash for blank text and null for a foreign hash', () => {
    expect(encodePolicyHash('   ')).toBe('');
    expect(decodePolicyHash('')).toBeNull();
    expect(decodePolicyHash('#other=1')).toBeNull();
    expect(decodePolicyHash('#p=%%%')).toBeNull();
  });

  it('builds a share URL on the current origin and path', () => {
    const url = buildShareUrl(text, {
      origin: 'https://example.test',
      pathname: '/iam-policy-analyzer/',
    });
    expect(url.startsWith('https://example.test/iam-policy-analyzer/#p=')).toBe(true);
    expect(decodePolicyHash(new URL(url).hash)).toBe(text);
  });
});
