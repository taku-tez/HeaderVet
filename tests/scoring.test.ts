import { describe, it, expect } from 'vitest';
import { calculateGrade, meetsMinGrade, parseGrade } from '../src/scoring.js';
import type { HeaderCheck } from '../src/types.js';

function coreCheck(header: string, present: boolean): HeaderCheck {
  return {
    header,
    status: present ? 'pass' : 'missing',
    severity: 'info',
    value: present ? 'x' : null,
    message: '',
    recommendation: null,
    score: present ? 5 : 0,
    maxScore: 5,
  };
}

function bonusCheck(header: string, present: boolean): HeaderCheck {
  return {
    header,
    status: present ? 'pass' : 'missing',
    severity: 'info',
    value: present ? 'x' : null,
    message: '',
    recommendation: null,
    score: present ? 5 : 0,
    maxScore: 5,
  };
}

const CORE_HEADERS = [
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
];

const BONUS_HEADERS = [
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Resource-Policy',
  'Cache-Control',
];

function makeChecks(corePresent: number, bonusPresent: number = 0): HeaderCheck[] {
  const checks: HeaderCheck[] = [];
  for (let i = 0; i < CORE_HEADERS.length; i++) {
    checks.push(coreCheck(CORE_HEADERS[i], i < corePresent));
  }
  for (let i = 0; i < BONUS_HEADERS.length; i++) {
    checks.push(bonusCheck(BONUS_HEADERS[i], i < bonusPresent));
  }
  return checks;
}

describe('calculateGrade - core header based', () => {
  it('6/6 core + 3 bonus → A+', () => {
    const { grade } = calculateGrade(makeChecks(6, 3));
    expect(grade).toBe('A+');
  });

  it('6/6 core + 0 bonus → A', () => {
    const { grade } = calculateGrade(makeChecks(6, 0));
    expect(grade).toBe('A');
  });

  it('6/6 core + 2 bonus → A (not enough bonus for A+)', () => {
    const { grade } = calculateGrade(makeChecks(6, 2));
    expect(grade).toBe('A');
  });

  it('5/6 core → B', () => {
    const { grade } = calculateGrade(makeChecks(5));
    expect(grade).toBe('B');
  });

  it('4/6 core → C', () => {
    const { grade } = calculateGrade(makeChecks(4));
    expect(grade).toBe('C');
  });

  it('3/6 core → D', () => {
    const { grade } = calculateGrade(makeChecks(3));
    expect(grade).toBe('D');
  });

  it('2/6 core → E', () => {
    const { grade } = calculateGrade(makeChecks(2));
    expect(grade).toBe('E');
  });

  it('1/6 core → F', () => {
    const { grade } = calculateGrade(makeChecks(1));
    expect(grade).toBe('F');
  });

  it('0/6 core → F', () => {
    const { grade } = calculateGrade(makeChecks(0));
    expect(grade).toBe('F');
  });

  it('empty checks → F', () => {
    const { grade } = calculateGrade([]);
    expect(grade).toBe('F');
  });

  it('scores sum correctly', () => {
    const checks = makeChecks(3, 2);
    const { totalScore, maxScore } = calculateGrade(checks);
    expect(totalScore).toBe(25); // 3*5 + 2*5
    expect(maxScore).toBe(50);   // 6*5 + 4*5
  });

  it('fail status CSP still counts as present', () => {
    const checks = makeChecks(5); // 5 core present
    // Replace the missing 6th core with a "fail" (present but bad)
    const missingIdx = checks.findIndex(c => c.status === 'missing' && CORE_HEADERS.includes(c.header));
    if (missingIdx >= 0) {
      checks[missingIdx].status = 'fail';
      checks[missingIdx].score = 2;
    }
    const { grade } = calculateGrade(checks);
    expect(grade).toBe('A'); // 6/6 present, no bonus → A
  });

  it('warn status counts as present', () => {
    const checks = makeChecks(5);
    const missingIdx = checks.findIndex(c => c.status === 'missing' && CORE_HEADERS.includes(c.header));
    if (missingIdx >= 0) {
      checks[missingIdx].status = 'warn';
      checks[missingIdx].score = 3;
    }
    const { grade } = calculateGrade(checks);
    expect(grade).toBe('A'); // 6/6 present
  });
});

describe('meetsMinGrade', () => {
  it('A+ meets A+', () => { expect(meetsMinGrade('A+', 'A+')).toBe(true); });
  it('A meets A', () => { expect(meetsMinGrade('A', 'A')).toBe(true); });
  it('A+ meets C', () => { expect(meetsMinGrade('A+', 'C')).toBe(true); });
  it('F does not meet C', () => { expect(meetsMinGrade('F', 'C')).toBe(false); });
  it('D does not meet C', () => { expect(meetsMinGrade('D', 'C')).toBe(false); });
  it('C meets C', () => { expect(meetsMinGrade('C', 'C')).toBe(true); });
  it('B meets C', () => { expect(meetsMinGrade('B', 'C')).toBe(true); });
  it('E does not meet D', () => { expect(meetsMinGrade('E', 'D')).toBe(false); });
  it('A meets F', () => { expect(meetsMinGrade('A', 'F')).toBe(true); });
  it('F meets F', () => { expect(meetsMinGrade('F', 'F')).toBe(true); });
});

describe('parseGrade', () => {
  it('parses A+', () => { expect(parseGrade('A+')).toBe('A+'); });
  it('parses a (lowercase)', () => { expect(parseGrade('a')).toBe('A'); });
  it('parses F', () => { expect(parseGrade('F')).toBe('F'); });
  it('parses B', () => { expect(parseGrade('B')).toBe('B'); });
  it('parses C', () => { expect(parseGrade('c')).toBe('C'); });
  it('parses D', () => { expect(parseGrade('d')).toBe('D'); });
  it('parses E', () => { expect(parseGrade('e')).toBe('E'); });
  it('invalid → null', () => { expect(parseGrade('X')).toBeNull(); });
  it('empty → null', () => { expect(parseGrade('')).toBeNull(); });
  it('a+ lowercase → A+', () => { expect(parseGrade('a+')).toBe('A+'); });
});
