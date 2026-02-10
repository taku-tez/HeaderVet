import { describe, it, expect } from 'vitest';
import { calculateGrade, meetsMinGrade, parseGrade } from '../src/scoring.js';
import type { HeaderCheck } from '../src/types.js';

function makeCheck(score: number, maxScore: number): HeaderCheck {
  return { header: 'Test', status: 'pass', severity: 'info', value: 'x', message: '', recommendation: null, score, maxScore };
}

describe('calculateGrade', () => {
  it('100% → A+', () => {
    const { grade } = calculateGrade([makeCheck(10, 10)]);
    expect(grade).toBe('A+');
  });

  it('95% → A+', () => {
    const { grade } = calculateGrade([makeCheck(95, 100)]);
    expect(grade).toBe('A+');
  });

  it('90% → A', () => {
    const { grade } = calculateGrade([makeCheck(90, 100)]);
    expect(grade).toBe('A');
  });

  it('85% → A', () => {
    const { grade } = calculateGrade([makeCheck(85, 100)]);
    expect(grade).toBe('A');
  });

  it('70% → B', () => {
    const { grade } = calculateGrade([makeCheck(70, 100)]);
    expect(grade).toBe('B');
  });

  it('55% → C', () => {
    const { grade } = calculateGrade([makeCheck(55, 100)]);
    expect(grade).toBe('C');
  });

  it('40% → D', () => {
    const { grade } = calculateGrade([makeCheck(40, 100)]);
    expect(grade).toBe('D');
  });

  it('25% → E', () => {
    const { grade } = calculateGrade([makeCheck(25, 100)]);
    expect(grade).toBe('E');
  });

  it('10% → F', () => {
    const { grade } = calculateGrade([makeCheck(10, 100)]);
    expect(grade).toBe('F');
  });

  it('0% → F', () => {
    const { grade } = calculateGrade([makeCheck(0, 100)]);
    expect(grade).toBe('F');
  });

  it('empty checks → F', () => {
    const { grade } = calculateGrade([]);
    expect(grade).toBe('F');
  });

  it('multiple checks sum correctly', () => {
    const { totalScore, maxScore } = calculateGrade([makeCheck(5, 10), makeCheck(3, 10)]);
    expect(totalScore).toBe(8);
    expect(maxScore).toBe(20);
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
});

describe('parseGrade', () => {
  it('parses A+', () => { expect(parseGrade('A+')).toBe('A+'); });
  it('parses a (lowercase)', () => { expect(parseGrade('a')).toBe('A'); });
  it('parses F', () => { expect(parseGrade('F')).toBe('F'); });
  it('invalid → null', () => { expect(parseGrade('X')).toBeNull(); });
  it('empty → null', () => { expect(parseGrade('')).toBeNull(); });
});
