import type { HeaderCheck } from '../types.js';

const HEADER = 'cross-origin-opener-policy';
const VALID = ['same-origin', 'same-origin-allow-popups', 'unsafe-none'];

export function checkCOOP(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'Cross-Origin-Opener-Policy',
      status: 'missing',
      severity: 'low',
      value: null,
      message: 'Cross-Origin-Opener-Policy header is missing.',
      recommendation: 'Cross-Origin-Opener-Policy: same-origin',
      score: 0,
      maxScore: 5,
    };
  }

  const v = value.trim().toLowerCase();

  if (v === 'same-origin') {
    return { header: 'Cross-Origin-Opener-Policy', status: 'pass', severity: 'info', value, message: 'COOP set to same-origin (most secure).', recommendation: null, score: 5, maxScore: 5 };
  }

  if (v === 'same-origin-allow-popups') {
    return { header: 'Cross-Origin-Opener-Policy', status: 'pass', severity: 'info', value, message: 'COOP set to same-origin-allow-popups.', recommendation: null, score: 4, maxScore: 5 };
  }

  if (v === 'unsafe-none') {
    return { header: 'Cross-Origin-Opener-Policy', status: 'warn', severity: 'low', value, message: 'COOP set to unsafe-none — no isolation.', recommendation: 'Cross-Origin-Opener-Policy: same-origin', score: 2, maxScore: 5 };
  }

  return { header: 'Cross-Origin-Opener-Policy', status: 'fail', severity: 'low', value, message: `Invalid COOP value: "${value}". Valid: ${VALID.join(', ')}`, recommendation: 'Cross-Origin-Opener-Policy: same-origin', score: 1, maxScore: 5 };
}
