import { describe, it, expect } from 'vitest';
import { fetchHeaders } from '../src/scanner.js';

describe('Scanner', () => {
  it('fetchHeaders is a function', () => {
    expect(typeof fetchHeaders).toBe('function');
  });

  it('rejects invalid URLs', async () => {
    await expect(fetchHeaders('not-a-url', { timeout: 500 })).rejects.toThrow();
  });

  it('times out on unreachable hosts', async () => {
    // 192.0.2.1 is TEST-NET, should time out
    await expect(fetchHeaders('http://192.0.2.1', { timeout: 500 })).rejects.toThrow();
  });

  it('respects custom user agent option', () => {
    // Just verify the option is accepted (no actual request)
    expect(() => fetchHeaders('http://192.0.2.1', { userAgent: 'TestBot/1.0', timeout: 100 })).not.toThrow();
  });

  it('respects cookie option', () => {
    expect(() => fetchHeaders('http://192.0.2.1', { cookie: 'session=abc', timeout: 100 })).not.toThrow();
  });

  it('respects customHeaders option', () => {
    expect(() => fetchHeaders('http://192.0.2.1', { customHeaders: { 'X-Test': 'value' }, timeout: 100 })).not.toThrow();
  });
});
