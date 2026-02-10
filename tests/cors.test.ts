import { describe, it, expect } from 'vitest';
import { checkCORS } from '../src/checks/cors.js';

describe('checkCORS', () => {
  it('absent → pass (most restrictive)', () => {
    const r = checkCORS({});
    expect(r.status).toBe('pass');
    expect(r.score).toBe(5);
  });

  it('wildcard * → fail', () => {
    const r = checkCORS({ 'access-control-allow-origin': '*' });
    expect(r.status).toBe('fail');
    expect(r.severity).toBe('high');
    expect(r.score).toBe(0);
  });

  it('null origin → fail', () => {
    const r = checkCORS({ 'access-control-allow-origin': 'null' });
    expect(r.status).toBe('fail');
    expect(r.severity).toBe('high');
    expect(r.score).toBe(0);
  });

  it('http:// origin → warn', () => {
    const r = checkCORS({ 'access-control-allow-origin': 'http://example.com' });
    expect(r.status).toBe('warn');
    expect(r.score).toBe(3);
  });

  it('https:// origin → pass', () => {
    const r = checkCORS({ 'access-control-allow-origin': 'https://example.com' });
    expect(r.status).toBe('pass');
    expect(r.score).toBe(5);
  });

  it('whitespace trimmed', () => {
    const r = checkCORS({ 'access-control-allow-origin': '  *  ' });
    expect(r.status).toBe('fail');
  });

  it('NULL uppercase → fail', () => {
    const r = checkCORS({ 'access-control-allow-origin': 'NULL' });
    expect(r.status).toBe('fail');
  });
});
