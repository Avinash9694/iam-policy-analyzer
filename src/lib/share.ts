import { compressToEncodedURIComponent, decompressFromEncodedURIComponent } from 'lz-string';

const PARAM = 'p';

export function encodePolicyHash(text: string): string {
  if (text.trim().length === 0) return '';
  return `#${PARAM}=${compressToEncodedURIComponent(text)}`;
}

export function decodePolicyHash(hash: string): string | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash;
  if (!raw) return null;
  const params = new URLSearchParams(raw);
  const value = params.get(PARAM);
  if (!value) return null;
  try {
    const text = decompressFromEncodedURIComponent(value);
    return text && text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

export function buildShareUrl(
  text: string,
  location: Pick<Location, 'origin' | 'pathname'> = window.location,
): string {
  return `${location.origin}${location.pathname}${encodePolicyHash(text)}`;
}
