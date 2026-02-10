import { describe, it, expect } from 'vitest';
import { checkCSP } from '../src/checks/csp.js';
import { checkHSTS } from '../src/checks/hsts.js';
import { checkXFrameOptions } from '../src/checks/x-frame.js';
import { checkPermissionsPolicy } from '../src/checks/permissions-policy.js';
import { checkCOOP } from '../src/checks/coop.js';
import { checkCOEP } from '../src/checks/coep.js';
import { checkCORP } from '../src/checks/corp.js';
import { checkReferrerPolicy } from '../src/checks/referrer.js';
import { checkCacheControl } from '../src/checks/cache.js';
import { checkXContentTypeOptions, checkXXSSProtection } from '../src/checks/misc.js';
import { checkSetCookie } from '../src/checks/set-cookie.js';
import { checkDNSPrefetchControl } from '../src/checks/dns-prefetch.js';
import { calculateGrade } from '../src/scoring.js';
import { formatJSON, formatQuiet } from '../src/reporter.js';
import type { HeaderCheck, ScanResult } from '../src/types.js';

const ALL_CHECKS = [
  checkCSP, checkHSTS, checkXFrameOptions, checkXContentTypeOptions,
  checkPermissionsPolicy, checkCOOP, checkCOEP, checkCORP,
  checkReferrerPolicy, checkXXSSProtection, checkCacheControl,
  checkSetCookie, checkDNSPrefetchControl,
];

function runAllChecks(headers: Record<string, string>): HeaderCheck[] {
  return ALL_CHECKS.map(fn => fn(headers));
}

function makeScanResult(headers: Record<string, string>, url = 'https://example.com'): ScanResult {
  const checks = runAllChecks(headers);
  const { grade, totalScore, maxScore } = calculateGrade(checks);
  return { url, finalUrl: url, statusCode: 200, redirectChain: [], checks, grade, totalScore, maxScore, timestamp: new Date().toISOString() };
}

// ─── Realistic header sets ───

describe('Realistic header sets', () => {
  it('perfect headers → A+', () => {
    const r = makeScanResult({
      'content-security-policy': "default-src 'none'; script-src 'nonce-abc'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; report-uri /csp",
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-resource-policy': 'same-origin',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'x-xss-protection': '0',
      'cache-control': 'no-store, no-cache, must-revalidate, private',
      'x-dns-prefetch-control': 'off',
    });
    expect(['A+', 'A']).toContain(r.grade);
    expect(r.totalScore).toBeGreaterThan(r.maxScore * 0.85);
  });

  it('no headers at all → F', () => {
    const r = makeScanResult({});
    expect(r.grade).toBe('F');
  });

  it('only HSTS → still low grade', () => {
    const r = makeScanResult({
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    });
    expect(['E', 'F']).toContain(r.grade);
  });

  it('typical modern site (CSP + HSTS + basics)', () => {
    const r = makeScanResult({
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000',
      'x-frame-options': 'SAMEORIGIN',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
    });
    expect(['B', 'C', 'D']).toContain(r.grade);
  });

  it('insecure cookie drags score down', () => {
    const withSecure = makeScanResult({
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Lax',
    });
    const withInsecure = makeScanResult({
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000',
      'set-cookie': 'session=abc',
    });
    expect(withSecure.totalScore).toBeGreaterThan(withInsecure.totalScore);
  });
});

// ─── Multiple URL simulation ───

describe('Multiple URL processing', () => {
  it('summary with multiple results', () => {
    const r1 = makeScanResult({}, 'https://good.example.com');
    const r2 = makeScanResult({
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000',
    }, 'https://better.example.com');

    const quiet = formatQuiet([r1, r2]);
    expect(quiet).toContain('good.example.com');
    expect(quiet).toContain('better.example.com');
  });

  it('JSON output for multiple URLs is an array', () => {
    const r1 = makeScanResult({}, 'https://a.com');
    const r2 = makeScanResult({}, 'https://b.com');
    const json = JSON.parse(formatJSON([r1, r2]));
    expect(Array.isArray(json)).toBe(true);
    expect(json).toHaveLength(2);
  });

  it('JSON output for single URL is an object', () => {
    const r = makeScanResult({}, 'https://a.com');
    const json = JSON.parse(formatJSON([r]));
    expect(json.url).toBe('https://a.com');
  });
});

// ─── Edge cases ───

describe('Edge cases', () => {
  it('empty string header values treated as present', () => {
    // Empty CSP is still "present" but very bad
    const r = checkCSP({ 'content-security-policy': '' });
    // Should not be 'missing' since key exists
    expect(r.score).toBeLessThanOrEqual(8);
  });

  it('header with extra whitespace', () => {
    const r = checkHSTS({ 'strict-transport-security': '  max-age=31536000 ; includeSubDomains ; preload  ' });
    expect(r.status).toBe('pass');
  });

  it('case sensitivity in header values', () => {
    const r = checkCOOP({ 'cross-origin-opener-policy': 'Same-Origin' });
    expect(r.status).toBe('pass');
  });

  it('all checks return valid structure', () => {
    const checks = runAllChecks({});
    for (const c of checks) {
      expect(c.header).toBeDefined();
      expect(c.status).toBeDefined();
      expect(c.severity).toBeDefined();
      expect(typeof c.score).toBe('number');
      expect(typeof c.maxScore).toBe('number');
      expect(c.score).toBeGreaterThanOrEqual(0);
      expect(c.score).toBeLessThanOrEqual(c.maxScore);
      expect(c.message).toBeDefined();
    }
  });

  it('all checks return valid structure with full headers', () => {
    const checks = runAllChecks({
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'permissions-policy': 'camera=()',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-resource-policy': 'same-origin',
      'referrer-policy': 'no-referrer',
      'x-xss-protection': '0',
      'cache-control': 'no-store',
      'set-cookie': 'a=b; Secure; HttpOnly; SameSite=Lax',
      'x-dns-prefetch-control': 'off',
    });
    for (const c of checks) {
      expect(c.score).toBeGreaterThanOrEqual(0);
      expect(c.score).toBeLessThanOrEqual(c.maxScore);
    }
  });

  it('maxScore total is consistent', () => {
    const checks = runAllChecks({});
    const total = checks.reduce((s, c) => s + c.maxScore, 0);
    // 15 + 10 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 3 = 78
    expect(total).toBe(78);
  });

  it('severity levels are valid', () => {
    const checks = runAllChecks({});
    const valid = ['critical', 'high', 'medium', 'low', 'info'];
    for (const c of checks) {
      expect(valid).toContain(c.severity);
    }
  });

  it('status values are valid', () => {
    const checks = runAllChecks({});
    const valid = ['pass', 'warn', 'fail', 'missing'];
    for (const c of checks) {
      expect(valid).toContain(c.status);
    }
  });
});

// ─── CSP weight is highest ───

describe('Scoring weights', () => {
  it('CSP has highest maxScore (15)', () => {
    const checks = runAllChecks({});
    const csp = checks.find(c => c.header === 'Content-Security-Policy');
    expect(csp!.maxScore).toBe(15);
  });

  it('HSTS has second highest maxScore (10)', () => {
    const checks = runAllChecks({});
    const hsts = checks.find(c => c.header === 'Strict-Transport-Security');
    expect(hsts!.maxScore).toBe(10);
  });

  it('COOP/COEP/CORP are medium weight (5 each)', () => {
    const checks = runAllChecks({});
    for (const name of ['Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy']) {
      const c = checks.find(c => c.header === name);
      expect(c!.maxScore).toBe(5);
    }
  });

  it('X-DNS-Prefetch-Control is lowest weight (3)', () => {
    const checks = runAllChecks({});
    const dns = checks.find(c => c.header === 'X-DNS-Prefetch-Control');
    expect(dns!.maxScore).toBe(3);
  });
});
