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

// ─── CSP ───

describe('CSP', () => {
  it('missing → critical', () => {
    const r = checkCSP({});
    expect(r.status).toBe('missing');
    expect(r.severity).toBe('critical');
    expect(r.score).toBe(0);
    expect(r.maxScore).toBe(15);
  });

  it('good CSP → pass', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'none'; script-src 'nonce-abc'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; report-to /csp" });
    expect(r.status).toBe('pass');
    expect(r.score).toBeGreaterThanOrEqual(10);
  });

  it('unsafe-inline → penalized', () => {
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
    const base = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";
    const a = checkCSP({ 'content-security-policy': base });
    const b = checkCSP({ 'content-security-policy': `${base}; report-uri /csp` });
    expect(b.score).toBeGreaterThanOrEqual(a.score);
  });

  it('missing base-uri → noted', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" });
    expect(r.message).toContain('base-uri');
  });

  it('missing form-action → noted', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'self'" });
    expect(r.message).toContain('form-action');
  });

  it('missing object-src → noted', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" });
    expect(r.message).toContain('object-src');
  });

  it('nonce-based CSP has no nonce warning', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'nonce-abc123'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" });
    expect(r.message).not.toContain('nonce');
  });

  it('hash-based CSP has no hash warning', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'sha256-abc123'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" });
    expect(r.message).not.toContain('nonce');
  });

  it('script-src without nonce/hash → recommends nonce/hash', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" });
    expect(r.message).toContain('nonce');
  });

  it('report-to detected', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; report-to default" });
    // report-to gives bonus
    expect(r.score).toBeGreaterThan(0);
  });

  it('multiple unsafe directives → heavily penalized', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'" });
    expect(r.score).toBeLessThan(5);
  });

  it('complete CSP with all directives → high score', () => {
    const r = checkCSP({ 'content-security-policy': "default-src 'none'; script-src 'nonce-abc'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; report-uri /csp" });
    expect(r.status).toBe('pass');
    expect(r.score).toBeGreaterThanOrEqual(10);
  });

  it('has detail field', () => {
    const r = checkCSP({});
    expect(r.detail).toBeDefined();
    expect(r.detail!.length).toBeGreaterThan(0);
  });
});

// ─── HSTS ───

describe('HSTS', () => {
  it('missing → critical', () => {
    const r = checkHSTS({});
    expect(r.status).toBe('missing');
    expect(r.severity).toBe('critical');
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
    expect(r.message).toContain('subdomains');
  });

  it('missing preload', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' });
    expect(r.message).toContain('preload');
  });

  it('missing max-age directive', () => {
    const r = checkHSTS({ 'strict-transport-security': 'includeSubDomains' });
    expect(r.message).toContain('max-age');
  });

  it('max-age=0 → penalized', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=0' });
    expect(r.message).toContain('below recommended');
  });

  it('very long max-age → pass with includeSubDomains and preload', () => {
    const r = checkHSTS({ 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload' });
    expect(r.status).toBe('pass');
    expect(r.score).toBe(10);
  });

  it('has detail field', () => {
    const r = checkHSTS({});
    expect(r.detail).toBeDefined();
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

  it('case insensitive', () => {
    expect(checkXFrameOptions({ 'x-frame-options': 'deny' }).status).toBe('pass');
    expect(checkXFrameOptions({ 'x-frame-options': 'sameorigin' }).status).toBe('pass');
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

  it('nosniff with whitespace → pass', () => {
    expect(checkXContentTypeOptions({ 'x-content-type-options': ' nosniff ' }).status).toBe('pass');
  });
});

// ─── Permissions-Policy ───

describe('Permissions-Policy', () => {
  it('missing', () => {
    expect(checkPermissionsPolicy({}).status).toBe('missing');
  });

  it('good policy → pass', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()' });
    expect(r.status).toBe('pass');
  });

  it('wildcard camera → warn', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=*' });
    expect(r.status).toBe('warn');
    expect(r.message).toContain('camera');
  });

  it('missing dangerous APIs → warns', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'usb=()' });
    expect(r.message).toContain('camera');
    expect(r.message).toContain('microphone');
    expect(r.message).toContain('geolocation');
    expect(r.message).toContain('payment');
  });

  it('partial restriction → warn', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=(), microphone=()' });
    expect(r.status).toBe('warn');
    expect(r.message).toContain('geolocation');
  });

  it('all wildcard → low score', () => {
    const r = checkPermissionsPolicy({ 'permissions-policy': 'camera=*, microphone=*, geolocation=*, payment=*' });
    expect(r.score).toBeLessThanOrEqual(1);
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
  it('same-origin → pass', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'same-origin' }).status).toBe('pass'); });
  it('strict-origin → pass', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'strict-origin' }).status).toBe('pass'); });
  it('origin → warn', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'origin' }).status).toBe('warn'); });
  it('origin-when-cross-origin → warn', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'origin-when-cross-origin' }).status).toBe('warn'); });
  it('unsafe-url → fail', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'unsafe-url' }).status).toBe('fail'); });
  it('no-referrer-when-downgrade → fail', () => { expect(checkReferrerPolicy({ 'referrer-policy': 'no-referrer-when-downgrade' }).status).toBe('fail'); });
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
  it('s-maxage detected', () => {
    const r = checkCacheControl({ 'cache-control': 's-maxage=600, max-age=300' });
    expect(r.message).toContain('s-maxage');
  });
  it('s-maxage with private → no warning', () => {
    const r = checkCacheControl({ 'cache-control': 'private, s-maxage=600' });
    expect(r.message).not.toContain('s-maxage');
  });
  it('no-store → good score', () => {
    const r = checkCacheControl({ 'cache-control': 'no-store' });
    expect(r.score).toBeGreaterThanOrEqual(4);
  });
  it('has detail field', () => {
    const r = checkCacheControl({});
    expect(r.detail).toBeDefined();
  });
});

// ─── X-XSS-Protection ───

describe('X-XSS-Protection', () => {
  it('absent → pass (modern)', () => { expect(checkXXSSProtection({}).status).toBe('pass'); });
  it('0 → pass', () => { expect(checkXXSSProtection({ 'x-xss-protection': '0' }).status).toBe('pass'); });
  it('1; mode=block → warn', () => { expect(checkXXSSProtection({ 'x-xss-protection': '1; mode=block' }).status).toBe('warn'); });
  it('1 → warn', () => { expect(checkXXSSProtection({ 'x-xss-protection': '1' }).status).toBe('warn'); });
  it('unusual value → warn', () => { expect(checkXXSSProtection({ 'x-xss-protection': '2' }).status).toBe('warn'); });
});

// ─── Set-Cookie ───

describe('Set-Cookie', () => {
  it('absent → pass (no cookies)', () => {
    const r = checkSetCookie({});
    expect(r.status).toBe('pass');
    expect(r.score).toBe(5);
  });

  it('fully secured cookie → pass', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Lax; Path=/' });
    expect(r.status).toBe('pass');
    expect(r.score).toBeGreaterThanOrEqual(3);
  });

  it('missing Secure flag → warn', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc; HttpOnly; SameSite=Lax' });
    expect(r.message).toContain('Secure');
  });

  it('missing HttpOnly flag → warn', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc; Secure; SameSite=Lax' });
    expect(r.message).toContain('HttpOnly');
  });

  it('missing SameSite → warn', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc; Secure; HttpOnly' });
    expect(r.message).toContain('SameSite');
  });

  it('SameSite=None without Secure → extra penalty', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc; HttpOnly; SameSite=None' });
    expect(r.message).toContain('SameSite=None without Secure');
  });

  it('no attributes at all → fail', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc' });
    expect(r.message).toContain('Secure');
    expect(r.message).toContain('HttpOnly');
    expect(r.message).toContain('SameSite');
  });

  it('__Secure- prefix without Secure flag', () => {
    const r = checkSetCookie({ 'set-cookie': '__Secure-session=abc; HttpOnly; SameSite=Lax' });
    expect(r.message).toContain('__Secure-');
  });

  it('__Host- prefix without Secure flag', () => {
    const r = checkSetCookie({ 'set-cookie': '__Host-session=abc; HttpOnly; SameSite=Lax; Path=/' });
    expect(r.message).toContain('__Host-');
  });

  it('__Host- prefix without Path=/', () => {
    const r = checkSetCookie({ 'set-cookie': '__Host-session=abc; Secure; HttpOnly; SameSite=Lax' });
    expect(r.message).toContain('Path=/');
  });

  it('__Host- fully correct', () => {
    const r = checkSetCookie({ 'set-cookie': '__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/' });
    expect(r.status).toBe('pass');
  });

  it('has detail and recommendation', () => {
    const r = checkSetCookie({ 'set-cookie': 'session=abc' });
    expect(r.detail).toBeDefined();
    expect(r.recommendation).toBeDefined();
  });
});

// ─── X-DNS-Prefetch-Control ───

describe('X-DNS-Prefetch-Control', () => {
  it('missing → warn', () => {
    const r = checkDNSPrefetchControl({});
    expect(r.status).toBe('warn');
    expect(r.score).toBe(1);
    expect(r.maxScore).toBe(3);
  });

  it('off → pass', () => {
    const r = checkDNSPrefetchControl({ 'x-dns-prefetch-control': 'off' });
    expect(r.status).toBe('pass');
    expect(r.score).toBe(3);
  });

  it('on → warn', () => {
    const r = checkDNSPrefetchControl({ 'x-dns-prefetch-control': 'on' });
    expect(r.status).toBe('warn');
    expect(r.score).toBe(1);
  });

  it('invalid → fail', () => {
    const r = checkDNSPrefetchControl({ 'x-dns-prefetch-control': 'maybe' });
    expect(r.status).toBe('fail');
    expect(r.score).toBe(0);
  });

  it('has detail', () => {
    const r = checkDNSPrefetchControl({});
    expect(r.detail).toBeDefined();
  });
});
