import type { Grade, HeaderCheck } from './types.js';

/**
 * Core headers that SecurityHeaders.com grades on.
 * These determine the grade. Other headers are informational bonus.
 */
const CORE_HEADERS = new Set([
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
]);

export function calculateGrade(checks: HeaderCheck[]): { grade: Grade; totalScore: number; maxScore: number } {
  const totalScore = checks.reduce((sum, c) => sum + c.score, 0);
  const maxScore = checks.reduce((sum, c) => sum + c.maxScore, 0);

  // Grade is based on core headers only (SecurityHeaders.com compatible)
  const coreChecks = checks.filter(c => CORE_HEADERS.has(c.header));
  // Header is "present" if it's not missing (pass, warn, or fail all mean the header exists)
  const corePresent = coreChecks.filter(c => c.status !== 'missing').length;
  const coreTotal = coreChecks.length;
  const corePct = coreTotal > 0 ? (corePresent / coreTotal) * 100 : 0;

  // Bonus: extra headers (COOP/COEP/CORP/Set-Cookie/Cache/DNS-Prefetch) can upgrade within grade
  const bonusChecks = checks.filter(c => !CORE_HEADERS.has(c.header));
  const bonusPresent = bonusChecks.filter(c => c.status === 'pass').length;
  const hasBonus = bonusPresent >= 3;

  let grade: Grade;
  if (corePct >= 100 && hasBonus) grade = 'A+';
  else if (corePct >= 100) grade = 'A';
  else if (corePct >= 83) grade = 'B';  // 5/6 core headers
  else if (corePct >= 66) grade = 'C';  // 4/6
  else if (corePct >= 50) grade = 'D';  // 3/6
  else if (corePct >= 33) grade = 'E';  // 2/6
  else grade = 'F';                      // 0-1/6

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
