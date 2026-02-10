import type { HeaderCheck } from '../types.js';

const HEADER = 'strict-transport-security';
const MIN_MAX_AGE = 31536000; // 1 year

export function checkHSTS(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'Strict-Transport-Security',
      status: 'missing',
      severity: 'high',
      value: null,
      message: 'Strict-Transport-Security header is missing.',
      recommendation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      score: 0,
      maxScore: 10,
    };
  }

  const issues: string[] = [];
  let score = 6;

  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

  if (!maxAgeMatch) {
    issues.push('Missing max-age directive.');
    score -= 3;
  } else if (maxAge < MIN_MAX_AGE) {
    issues.push(`max-age=${maxAge} is below recommended minimum of ${MIN_MAX_AGE} (1 year).`);
    score -= 2;
  } else {
    score += 1;
  }

  const hasIncludeSub = /includeSubDomains/i.test(value);
  if (hasIncludeSub) {
    score += 2;
  } else {
    issues.push('Missing includeSubDomains.');
  }

  const hasPreload = /preload/i.test(value);
  if (hasPreload) {
    score += 1;
  } else {
    issues.push('Missing preload directive.');
  }

  score = Math.max(0, Math.min(10, score));

  if (issues.length === 0) {
    return {
      header: 'Strict-Transport-Security',
      status: 'pass',
      severity: 'info',
      value,
      message: 'HSTS is well configured with includeSubDomains and preload.',
      recommendation: null,
      score,
      maxScore: 10,
    };
  }

  return {
    header: 'Strict-Transport-Security',
    status: score >= 6 ? 'warn' : 'fail',
    severity: score >= 6 ? 'low' : 'medium',
    value,
    message: issues.join(' '),
    recommendation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    score,
    maxScore: 10,
  };
}
