import type { HeaderCheck } from '../types.js';

const HEADER = 'x-dns-prefetch-control';

export function checkDNSPrefetchControl(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'X-DNS-Prefetch-Control',
      status: 'warn',
      severity: 'low',
      value: null,
      message: 'X-DNS-Prefetch-Control header is missing. DNS prefetching may leak visited links.',
      recommendation: 'X-DNS-Prefetch-Control: off',
      detail: 'DNS prefetching can leak information about which links a user is viewing. Setting this to "off" prevents browsers from pre-resolving external hostnames.',
      score: 1,
      maxScore: 3,
    };
  }

  const v = value.trim().toLowerCase();

  if (v === 'off') {
    return {
      header: 'X-DNS-Prefetch-Control',
      status: 'pass',
      severity: 'info',
      value,
      message: 'X-DNS-Prefetch-Control is set to off (recommended for privacy).',
      recommendation: null,
      detail: 'DNS prefetching is disabled, preventing information leakage.',
      score: 3,
      maxScore: 3,
    };
  }

  if (v === 'on') {
    return {
      header: 'X-DNS-Prefetch-Control',
      status: 'warn',
      severity: 'low',
      value,
      message: 'X-DNS-Prefetch-Control is "on" — DNS prefetching may leak visited links.',
      recommendation: 'X-DNS-Prefetch-Control: off',
      detail: 'DNS prefetching is explicitly enabled. This improves performance but can leak information about page content.',
      score: 1,
      maxScore: 3,
    };
  }

  return {
    header: 'X-DNS-Prefetch-Control',
    status: 'fail',
    severity: 'low',
    value,
    message: `Invalid X-DNS-Prefetch-Control value: "${value}". Expected "off" or "on".`,
    recommendation: 'X-DNS-Prefetch-Control: off',
    score: 0,
    maxScore: 3,
  };
}
