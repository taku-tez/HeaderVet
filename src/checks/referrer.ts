import type { HeaderCheck } from '../types.js';

const HEADER = 'referrer-policy';
const SECURE_VALUES = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
const WEAK_VALUES = ['origin', 'origin-when-cross-origin'];
const UNSAFE_VALUES = ['unsafe-url', 'no-referrer-when-downgrade'];

export function checkReferrerPolicy(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return { header: 'Referrer-Policy', status: 'missing', severity: 'medium', value: null, message: 'Referrer-Policy header is missing.', recommendation: 'Referrer-Policy: strict-origin-when-cross-origin', score: 0, maxScore: 5 };
  }

  // Can have multiple comma-separated, browser uses last supported
  const policies = value.split(',').map(p => p.trim().toLowerCase());
  const effective = policies[policies.length - 1];

  if (SECURE_VALUES.includes(effective)) {
    return { header: 'Referrer-Policy', status: 'pass', severity: 'info', value, message: `Referrer-Policy is set to "${effective}" (secure).`, recommendation: null, score: 5, maxScore: 5 };
  }

  if (WEAK_VALUES.includes(effective)) {
    return { header: 'Referrer-Policy', status: 'warn', severity: 'low', value, message: `Referrer-Policy "${effective}" leaks origin info cross-origin.`, recommendation: 'Referrer-Policy: strict-origin-when-cross-origin', score: 3, maxScore: 5 };
  }

  if (UNSAFE_VALUES.includes(effective)) {
    return { header: 'Referrer-Policy', status: 'fail', severity: 'medium', value, message: `Referrer-Policy "${effective}" leaks full URL — unsafe.`, recommendation: 'Referrer-Policy: strict-origin-when-cross-origin', score: 1, maxScore: 5 };
  }

  return { header: 'Referrer-Policy', status: 'fail', severity: 'medium', value, message: `Unknown Referrer-Policy value: "${effective}".`, recommendation: 'Referrer-Policy: strict-origin-when-cross-origin', score: 1, maxScore: 5 };
}
