import type { HeaderCheck } from '../types.js';

const HEADER = 'x-frame-options';

export function checkXFrameOptions(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'X-Frame-Options',
      status: 'missing',
      severity: 'medium',
      value: null,
      message: 'X-Frame-Options header is missing. Site may be vulnerable to clickjacking.',
      recommendation: 'X-Frame-Options: DENY',
      score: 0,
      maxScore: 5,
    };
  }

  const upper = value.toUpperCase().trim();

  if (upper === 'DENY') {
    return {
      header: 'X-Frame-Options',
      status: 'pass',
      severity: 'info',
      value,
      message: 'X-Frame-Options is set to DENY.',
      recommendation: null,
      score: 5,
      maxScore: 5,
    };
  }

  if (upper === 'SAMEORIGIN') {
    return {
      header: 'X-Frame-Options',
      status: 'pass',
      severity: 'info',
      value,
      message: 'X-Frame-Options is set to SAMEORIGIN.',
      recommendation: null,
      score: 5,
      maxScore: 5,
    };
  }

  if (upper.startsWith('ALLOW-FROM')) {
    return {
      header: 'X-Frame-Options',
      status: 'warn',
      severity: 'low',
      value,
      message: 'ALLOW-FROM is deprecated and not supported by modern browsers. Use CSP frame-ancestors instead.',
      recommendation: "Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com",
      score: 3,
      maxScore: 5,
    };
  }

  return {
    header: 'X-Frame-Options',
    status: 'fail',
    severity: 'medium',
    value,
    message: `Invalid X-Frame-Options value: "${value}".`,
    recommendation: 'X-Frame-Options: DENY',
    score: 1,
    maxScore: 5,
  };
}
