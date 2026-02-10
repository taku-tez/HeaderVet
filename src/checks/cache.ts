import type { HeaderCheck } from '../types.js';

const HEADER = 'cache-control';

export function checkCacheControl(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return { header: 'Cache-Control', status: 'missing', severity: 'low', value: null, message: 'Cache-Control header is missing. Sensitive responses may be cached.', recommendation: 'Cache-Control: no-store, no-cache, must-revalidate, private', score: 0, maxScore: 5 };
  }

  const lower = value.toLowerCase();
  let score = 2;
  const issues: string[] = [];

  if (lower.includes('no-store')) {
    score += 2;
  } else if (lower.includes('public')) {
    issues.push("'public' directive may cache sensitive data on shared caches.");
    score -= 1;
  }

  if (lower.includes('private')) {
    score += 1;
  }

  if (lower.includes('no-cache')) {
    score += 0.5;
  }

  if (lower.includes('must-revalidate')) {
    score += 0.5;
  }

  score = Math.max(0, Math.min(5, Math.round(score)));

  if (issues.length === 0 && score >= 4) {
    return { header: 'Cache-Control', status: 'pass', severity: 'info', value, message: 'Cache-Control is configured with security in mind.', recommendation: null, score, maxScore: 5 };
  }

  return {
    header: 'Cache-Control',
    status: score >= 3 ? 'warn' : 'fail',
    severity: 'low',
    value,
    message: issues.length ? issues.join(' ') : 'Cache-Control could be more restrictive for sensitive content.',
    recommendation: 'Cache-Control: no-store, no-cache, must-revalidate, private',
    score,
    maxScore: 5,
  };
}
