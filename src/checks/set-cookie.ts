import type { HeaderCheck } from '../types.js';

const HEADER = 'set-cookie';

export function checkSetCookie(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'Set-Cookie',
      status: 'pass',
      severity: 'info',
      value: null,
      message: 'No Set-Cookie header present — no cookie security issues.',
      recommendation: null,
      detail: 'No cookies are being set in this response.',
      score: 5,
      maxScore: 5,
    };
  }

  // Parse multiple cookies (may be comma-separated in single header)
  const cookies = value.split(/,(?=\s*[^;]*=)/).map(c => c.trim());
  const issues: string[] = [];
  let score = 3;

  for (const cookie of cookies) {
    const nameMatch = cookie.match(/^([^=]+)=/);
    const name = nameMatch ? nameMatch[1].trim() : 'unknown';

    // Parse attributes (everything after first ;)
    const parts = cookie.split(';').map(p => p.trim().toLowerCase());
    const attrs = parts.slice(1);

    const hasSecure = attrs.some(a => a === 'secure');
    const hasHttpOnly = attrs.some(a => a === 'httponly');
    const hasSameSite = attrs.some(a => a.startsWith('samesite'));
    const hasSameSiteNone = attrs.some(a => a.replace(/\s/g, '') === 'samesite=none');
    const hasPath = attrs.some(a => a.replace(/\s/g, '').startsWith('path=/'));

    if (!hasSecure) {
      issues.push(`Cookie "${name}" is missing Secure flag — may be sent over HTTP.`);
      score -= 1;
    }

    if (!hasHttpOnly) {
      issues.push(`Cookie "${name}" is missing HttpOnly flag — accessible via JavaScript.`);
      score -= 1;
    }

    if (!hasSameSite) {
      issues.push(`Cookie "${name}" is missing SameSite attribute — vulnerable to CSRF.`);
      score -= 0.5;
    } else if (hasSameSiteNone && !hasSecure) {
      issues.push(`Cookie "${name}" has SameSite=None without Secure — will be rejected by browsers.`);
      score -= 1;
    }

    // Check for __Secure- or __Host- prefix without proper flags
    if (name.startsWith('__Secure-') && !hasSecure) {
      issues.push(`Cookie "${name}" uses __Secure- prefix but is missing Secure flag.`);
    }
    if (name.startsWith('__Host-')) {
      if (!hasSecure) {
        issues.push(`Cookie "${name}" uses __Host- prefix but is missing Secure flag.`);
      }
      if (!hasPath) {
        issues.push(`Cookie "${name}" uses __Host- prefix but is missing Path=/.`);
      }
    }
  }

  score = Math.max(0, Math.min(5, Math.round(score)));

  if (issues.length === 0) {
    return {
      header: 'Set-Cookie',
      status: 'pass',
      severity: 'info',
      value,
      message: 'All cookies have Secure, HttpOnly, and SameSite attributes.',
      recommendation: null,
      detail: 'Cookies are properly secured with all recommended attributes.',
      score,
      maxScore: 5,
    };
  }

  return {
    header: 'Set-Cookie',
    status: score >= 2 ? 'warn' : 'fail',
    severity: score >= 2 ? 'medium' : 'high',
    value,
    message: issues.join(' '),
    recommendation: 'Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax; Path=/',
    detail: 'Cookies should always include Secure (HTTPS only), HttpOnly (no JS access), and SameSite (CSRF protection) attributes.',
    score,
    maxScore: 5,
  };
}
