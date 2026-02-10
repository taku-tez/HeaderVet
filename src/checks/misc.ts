import type { HeaderCheck } from '../types.js';

export function checkXContentTypeOptions(headers: Record<string, string>): HeaderCheck {
  const value = headers['x-content-type-options'] ?? null;

  if (!value) {
    return { header: 'X-Content-Type-Options', status: 'missing', severity: 'medium', value: null, message: 'X-Content-Type-Options is missing. Browsers may MIME-sniff responses.', recommendation: 'X-Content-Type-Options: nosniff', score: 0, maxScore: 5 };
  }

  if (value.trim().toLowerCase() === 'nosniff') {
    return { header: 'X-Content-Type-Options', status: 'pass', severity: 'info', value, message: 'X-Content-Type-Options is set to nosniff.', recommendation: null, score: 5, maxScore: 5 };
  }

  return { header: 'X-Content-Type-Options', status: 'fail', severity: 'medium', value, message: `Invalid value: "${value}". Expected "nosniff".`, recommendation: 'X-Content-Type-Options: nosniff', score: 1, maxScore: 5 };
}

export function checkXXSSProtection(headers: Record<string, string>): HeaderCheck {
  const value = headers['x-xss-protection'] ?? null;

  if (!value) {
    // Not having it is actually fine for modern browsers
    return { header: 'X-XSS-Protection', status: 'pass', severity: 'info', value: null, message: 'X-XSS-Protection is absent — acceptable for modern browsers that deprecated this feature.', recommendation: null, score: 5, maxScore: 5 };
  }

  const v = value.trim();

  if (v === '0') {
    return { header: 'X-XSS-Protection', status: 'pass', severity: 'info', value, message: 'X-XSS-Protection disabled (recommended — feature is deprecated and can introduce vulnerabilities).', recommendation: null, score: 5, maxScore: 5 };
  }

  if (v === '1; mode=block') {
    return { header: 'X-XSS-Protection', status: 'warn', severity: 'low', value, message: 'X-XSS-Protection is enabled. This feature is deprecated and can create XSS vulnerabilities in older browsers.', recommendation: 'X-XSS-Protection: 0 (disable the deprecated feature; rely on CSP instead)', score: 3, maxScore: 5 };
  }

  if (v === '1') {
    return { header: 'X-XSS-Protection', status: 'warn', severity: 'low', value, message: 'X-XSS-Protection: 1 without mode=block can enable XSS attacks via selective filtering.', recommendation: 'X-XSS-Protection: 0 (disable the deprecated feature; rely on CSP instead)', score: 2, maxScore: 5 };
  }

  return { header: 'X-XSS-Protection', status: 'warn', severity: 'low', value, message: `Unusual X-XSS-Protection value: "${value}". Consider disabling it.`, recommendation: 'X-XSS-Protection: 0', score: 2, maxScore: 5 };
}
