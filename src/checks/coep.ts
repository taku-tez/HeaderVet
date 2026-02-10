import type { HeaderCheck } from '../types.js';

const HEADER = 'cross-origin-embedder-policy';

export function checkCOEP(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return { header: 'Cross-Origin-Embedder-Policy', status: 'missing', severity: 'low', value: null, message: 'Cross-Origin-Embedder-Policy header is missing.', recommendation: 'Cross-Origin-Embedder-Policy: require-corp', score: 0, maxScore: 5 };
  }

  const v = value.trim().toLowerCase();

  if (v === 'require-corp') {
    return { header: 'Cross-Origin-Embedder-Policy', status: 'pass', severity: 'info', value, message: 'COEP set to require-corp (most secure).', recommendation: null, score: 5, maxScore: 5 };
  }

  if (v === 'credentialless') {
    return { header: 'Cross-Origin-Embedder-Policy', status: 'pass', severity: 'info', value, message: 'COEP set to credentialless.', recommendation: null, score: 4, maxScore: 5 };
  }

  if (v === 'unsafe-none') {
    return { header: 'Cross-Origin-Embedder-Policy', status: 'warn', severity: 'low', value, message: 'COEP set to unsafe-none — no isolation.', recommendation: 'Cross-Origin-Embedder-Policy: require-corp', score: 2, maxScore: 5 };
  }

  return { header: 'Cross-Origin-Embedder-Policy', status: 'fail', severity: 'low', value, message: `Invalid COEP value: "${value}".`, recommendation: 'Cross-Origin-Embedder-Policy: require-corp', score: 1, maxScore: 5 };
}
