import type { HeaderCheck } from '../types.js';

const HEADER = 'cross-origin-resource-policy';

export function checkCORP(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return { header: 'Cross-Origin-Resource-Policy', status: 'missing', severity: 'low', value: null, message: 'Cross-Origin-Resource-Policy header is missing.', recommendation: 'Cross-Origin-Resource-Policy: same-origin', score: 0, maxScore: 5 };
  }

  const v = value.trim().toLowerCase();

  if (v === 'same-origin') {
    return { header: 'Cross-Origin-Resource-Policy', status: 'pass', severity: 'info', value, message: 'CORP set to same-origin (most restrictive).', recommendation: null, score: 5, maxScore: 5 };
  }
  if (v === 'same-site') {
    return { header: 'Cross-Origin-Resource-Policy', status: 'pass', severity: 'info', value, message: 'CORP set to same-site.', recommendation: null, score: 4, maxScore: 5 };
  }
  if (v === 'cross-origin') {
    return { header: 'Cross-Origin-Resource-Policy', status: 'warn', severity: 'low', value, message: 'CORP set to cross-origin — allows all origins.', recommendation: 'Cross-Origin-Resource-Policy: same-origin', score: 2, maxScore: 5 };
  }

  return { header: 'Cross-Origin-Resource-Policy', status: 'fail', severity: 'low', value, message: `Invalid CORP value: "${value}".`, recommendation: 'Cross-Origin-Resource-Policy: same-origin', score: 1, maxScore: 5 };
}
