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

// ─── CSP ───

describe('CSP', () => {
  it('missing → critical', () => {
    const r = checkCSP({});
    expect(r.status).toBe('missing');
    expect(r.severity).toBe('critical');
    expect(r.score).toBe(0);
  });

  it('good CSP → pass', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'; report-to /csp" });
    expect(r.status).toBe('pass');
    expect(r.score).toBeGreaterThanOrEqual(10);
  });

  it('unsafe-inline → warn/fail', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" });
    expect(r.message).toContain('unsafe-inline');
    expect(r.score).toBeLessThan(10);
  });

  it('unsafe-eval → penalized', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-eval'" });
    expect(r.message).toContain('unsafe-eval');
  });

  it('wildcard → penalized', () => {
    const r = checkCSP({ 'content-security-policy': "default-src *" });
    expect(r.message).toContain('Wildcard');
  });

  it('missing default-src → penalized', () => {
    const r = checkCSP({ 'content-security-policy': "script-src 'self'" });
    expect(r.message).toContain('default-src');
  });

  it('missing frame-ancestors → noted', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'" });
    expect(r.message).toContain('frame-ancestors');
  });

  it('report-uri bonus', () => {
    const a = checkCSP({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" });
    const b = checkCSP({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'; report-uri /csp" });
    expect(b.score).toBeGreaterThanOrEqual(a.score);
  });
});

// ─── HSTS ───

describe('HSTS', () => {
  it('missing → fail', () => {
    const r = checkHSTS({});
    expect(r.status).toBe('missing');
    expect(r.score).toBe(0);
  });

  it('full HSTS → pass', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' });
    expect(r.status).toBe('pass');
    expect(r.score).toBe(10);
  });

  it('short max-age → penalized', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=86400' });
    expect(r.message).toContain('below recommended');
  });

  it('missing includeSubDomains', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=31536000; preload' });
    expect(r.message).toContain('includeSubDomains');
  });

  it('missing preload', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' });
    expect(r.message).toContain('preload');
  });

  it('missing max-age directive', () => {
    const r = checkHSTS({ 'strict-transport-security': 'includeSubDomains' });
    expect(r.message).toContain('max-age');
  });
});

// ─── X-Frame-Options ───

describe('X-Frame-Options', () => {
  it('missing', () => {
    const r = checkXFrameOptions({});
    expect(r.status).toBe('missing');
  });

  it('DENY → pass', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'DENY' });
    expect(r.status).toBe('pass');
    expect(r.score).toBe(5);
  });

  it('SAMEORIGIN → pass', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'SAMEORIGIN' });
    expect(r.status).toBe('pass');
  });

  it('ALLOW-FROM → warn', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'ALLOW-FROM https://example.com' });
    expect(r.status).toBe('warn');
  });

  it('invalid value → fail', () => {
    const r = checkXFrameOptions({ 'x-frame-options': 'INVALID' });
    expect(r.status).toBe('fail');
  });
});

// ─── X-Content-Type-Options ───

describe('X-Content-Type-Options', () => {
  it('missing', () => {
    expect(checkXContentTypeOptions({}).status).toBe('missing');
  });

  it('nosniff → pass', () => {
    expect(checkXContentTypeOptions({ 'x-content-type-options': 'nosniff' }).status).toBe('pass');
  });

  it('invalid → fail', () => {
    expect(checkXContentTypeOptions({ 'x-content-type-options': 'bad' }).status).toBe('fail');
  });
});

// ─── Permissions-Policy ───

describe('Permissions-Policy', () => {
  it('missing', () => {
    expect(checkPermissionsPolicy({}).status).toBe('missing');
  });

  it('good policy → pass', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=(), microphone=(), geolocation=()' });
    expect(r.status).toBe('pass');
  });

  it('wildcard camera → warn', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=*' });
    expect(r.status).toBe('warn');
    expect(r.message).toContain('camera');
  });
});

// ─── COOP ───

describe('COOP', () => {
  it('missing', () => { expect(checkCOOP({}).status).toBe('missing'); });
  it('same-origin → pass', () => { expect(checkCOOP({ 'cross-origin-opener-policy': 'same-origin' }).status).toBe('pass'); });
  it('same-origin-allow-popups → pass', () => { expect(checkCOOP({ 'cross-origin-opener-policy': 'same-origin-allow-popups' }).score).toBe(4); });
  it('unsafe-none → warn', () => { expect(checkCOOP({ 'cross-origin-opener-policy': 'unsafe-none' }).status).toBe('warn'); });
  it('invalid → fail', () => { expect(checkCOOP({ 'cross-origin-opener-policy': 'bad' }).status).toBe('fail'); });
});

// ─── COEP ───

describe('COEP', () => {
  it('missing', () => { expect(checkCOEP({}).status).toBe('missing'); });
  it('require-corp → pass', () => { expect(checkCOEP({ 'cross-origin-embedder-policy': 'require-corp' }).score).toBe(5); });
  it('credentialless → pass', () => { expect(checkCOEP({ 'cross-origin-embedder-policy': 'credentialless' }).score).toBe(4); });
  it('unsafe-none → warn', () => { expect(checkCOEP({ 'cross-origin-embedder-policy': 'unsafe-none' }).status).toBe('warn'); });
  it('invalid → fail', () => { expect(checkCOEP({ 'cross-origin-embedder-policy': 'bad' }).status).toBe('fail'); });
});

// ─── CORP ───

describe('CORP', () => {
  it('missing', () => { expect(checkCORP({}).status).toBe('missing'); });
  it('same-origin → pass 5', () => { expect(checkCORP({ 'cross-origin-resource-policy': 'same-origin' }).score).toBe(5); });
  it('same-site → pass 4', () => { expect(checkCORP({ 'cross-origin-resource-policy': 'same-site' }).score).toBe(4); });
  it('cross-origin → warn', () => { expect(checkCORP({ 'cross-origin-resource-policy': 'cross-origin' }).status).toBe('warn'); });
  it('invalid → fail', () => { expect(checkCORP({ 'cross-origin-resource-policy': 'bad' }).status).toBe('fail'); });
});

// ─── Referrer-Policy ───

describe('Referrer-Policy', () => {
  it('missing', () => { expect(checkReferrerPolicy({}).status).toBe('missing'); });
  it('strict-origin-when-cross-origin → pass', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'strict-origin-when-cross-origin' }).status).toBe('pass'); });
  it('no-referrer → pass', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'no-referrer' }).status).toBe('pass'); });
  it('origin → warn', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'origin' }).status).toBe('warn'); });
  it('unsafe-url → fail', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'unsafe-url' }).status).toBe('fail'); });
  it('unknown → fail', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'garbage' }).status).toBe('fail'); });
  it('multiple values → uses last', () => {
    const r = checkReferrerPolicy({ 'referrer-policy': 'no-referrer, strict-origin-when-cross-origin' });
    expect(r.status).toBe('pass');
  });
});

// ─── Cache-Control ───

describe('Cache-Control', () => {
  it('missing', () => { expect(checkCacheControl({}).status).toBe('missing'); });
  it('no-store private → pass', () => {
    const r = checkCacheControl({ 'cache-control': 'no-store, no-cache, must-revalidate, private' });
    expect(r.status).toBe('pass');
  });
  it('public → penalized', () => {
    const r = checkCacheControl({ 'cache-control': 'public, max-age=3600' });
    expect(r.message).toContain('public');
  });
  it('minimal → warn', () => {
    const r = checkCacheControl({ 'cache-control': 'max-age=300' });
    expect(r.score).toBeLessThan(5);
  });
});

// ─── X-XSS-Protection ───

describe('X-XSS-Protection', () => {
  it('absent → pass (modern)', () => { expect(checkXXSSProtection({}).status).toBe('pass'); });
  it('0 → pass', () => { expect(checkXXSSProtection({ 'x-xss-protection': '0' }).status).toBe('pass'); });
  it('1; mode=block → warn', () => { expect(checkXXSSProtection({ 'x-xss-protection': '1; mode=block' }).status).toBe('warn'); });
  it('1 → warn', () => { expect(checkXXSSProtection({ 'x-xss-protection': '1' }).status).toBe('warn'); });
});
