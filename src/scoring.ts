import type { Grade, HeaderCheck } from './types.js';

export function calculateGrade(checks: HeaderCheck[]): { grade: Grade; totalScore: number; maxScore: number } {
  const totalScore = checks.reduce((sum, c) => sum + c.score, 0);
  const maxScore = checks.reduce((sum, c) => sum + c.maxScore, 0);
  const pct = maxScore > 0 ? (totalScore / maxScore) * 100 : 0;

  let grade: Grade;
  if (pct >= 95) grade = 'A+';
  else if (pct >= 85) grade = 'A';
  else if (pct >= 70) grade = 'B';
  else if (pct >= 55) grade = 'C';
  else if (pct >= 40) grade = 'D';
  else if (pct >= 25) grade = 'E';
  else grade = 'F';

  return { grade, totalScore, maxScore };
}

const GRADE_ORDER: Grade[] = ['A+', 'A', 'B', 'C', 'D', 'E', 'F'];

export function gradeIndex(g: Grade): number {
  return GRADE_ORDER.indexOf(g);
}

export function parseGrade(s: string): Grade | null {
  const upper = s.toUpperCase().trim();
  if (upper === 'A+') return 'A+';
  const valid: Grade[] = ['A+', 'A', 'B', 'C', 'D', 'E', 'F'];
  return valid.includes(upper as Grade) ? (upper as Grade) : null;
}

/** Returns true if the actual grade meets or exceeds the minimum */
export function meetsMinGrade(actual: Grade, minimum: Grade): boolean {
  return gradeIndex(actual) <= gradeIndex(minimum);
}
