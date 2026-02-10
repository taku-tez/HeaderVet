import type { HeaderCheck } from '../types.js';

const HEADER = 'cache-control';

export function checkCacheControl(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'Cache-Control',
      status: 'missing',
      severity: 'low',
      value: null,
      message: 'Cache-Control header is missing. Sensitive responses may be cached.',
      recommendation: 'Cache-Control: no-store, no-cache, must-revalidate, private',
      detail: 'Without Cache-Control, browsers and proxies may cache sensitive data. This is especially important for authenticated pages.',
      score: 0,
      maxScore: 5,
    };
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

  // Detect s-maxage (CDN/proxy caching)
  const sMaxAgeMatch = lower.match(/s-maxage=(\d+)/);
  if (sMaxAgeMatch) {
    const sMaxAge = parseInt(sMaxAgeMatch[1], 10);
    if (sMaxAge > 0 && !lower.includes('private') && !lower.includes('no-store')) {
      issues.push(`s-maxage=${sMaxAge} detected — shared caches will store this response. Ensure no sensitive data is cached.`);
    }
  }

  score = Math.max(0, Math.min(5, Math.round(score)));

  if (issues.length === 0 && score >= 4) {
    return {
      header: 'Cache-Control',
      status: 'pass',
      severity: 'info',
      value,
      message: 'Cache-Control is configured with security in mind.',
      recommendation: null,
      detail: 'Cache-Control restricts caching appropriately for sensitive content.',
      score,
      maxScore: 5,
    };
  }

  return {
    header: 'Cache-Control',
    status: score >= 3 ? 'warn' : 'fail',
    severity: 'low',
    value,
    message: issues.length ? issues.join(' ') : 'Cache-Control could be more restrictive for sensitive content.',
    recommendation: 'Cache-Control: no-store, no-cache, must-revalidate, private',
    detail: 'For authenticated pages, use "no-store, private" to prevent sensitive data caching.',
    score,
    maxScore: 5,
  };
}
