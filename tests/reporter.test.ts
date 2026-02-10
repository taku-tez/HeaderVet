import { describe, it, expect } from 'vitest';
import { formatJSON, formatSARIF } from '../src/reporter.js';
import type { ScanResult } from '../src/types.js';

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    url: 'https://example.com',
    finalUrl: 'https://example.com',
    statusCode: 200,
    redirectChain: [],
    checks: [
      { header: 'X-Content-Type-Options', status: 'pass', severity: 'info', value: 'nosniff', message: 'OK', recommendation: null, score: 5, maxScore: 5 },
      { header: 'Content-Security-Policy', status: 'missing', severity: 'critical', value: null, message: 'Missing', recommendation: "default-src 'self'", score: 0, maxScore: 15 },
    ],
    grade: 'D',
    totalScore: 5,
    maxScore: 20,
    timestamp: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('formatJSON', () => {
  it('single result → object', () => {
    const json = formatJSON([makeScanResult()]);
    const parsed = JSON.parse(json);
    expect(parsed.url).toBe('https://example.com');
    expect(parsed.grade).toBe('D');
  });

  it('multiple results → array', () => {
    const json = formatJSON([makeScanResult(), makeScanResult({ url: 'https://other.com' })]);
    const parsed = JSON.parse(json);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
  });
});

describe('formatSARIF', () => {
  it('valid SARIF structure', () => {
    const sarif = JSON.parse(formatSARIF([makeScanResult()]));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('HeaderVet');
  });

  it('only includes non-pass results', () => {
    const sarif = JSON.parse(formatSARIF([makeScanResult()]));
    const results = sarif.runs[0].results;
    expect(results).toHaveLength(1); // only the missing CSP
    expect(results[0].ruleId).toBe('content-security-policy');
    expect(results[0].level).toBe('error');
  });

  it('includes recommendation in message', () => {
    const sarif = JSON.parse(formatSARIF([makeScanResult()]));
    expect(sarif.runs[0].results[0].message.text).toContain('Recommendation');
  });
});
