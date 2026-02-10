import type { HeaderCheck } from '../types.js';

const HEADER = 'content-security-policy';

export function checkCSP(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'Content-Security-Policy',
      status: 'missing',
      severity: 'critical',
      value: null,
      message: 'Content-Security-Policy header is missing.',
      recommendation: "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      score: 0,
      maxScore: 15,
    };
  }

  const issues: string[] = [];
  let score = 10; // start with base for having it

  const directives = parseDirectives(value);

  if (!directives['default-src']) {
    issues.push("Missing 'default-src' directive.");
    score -= 2;
  }

  // Check for unsafe-inline
  for (const [dir, vals] of Object.entries(directives)) {
    if (vals.includes("'unsafe-inline'")) {
      issues.push(`'unsafe-inline' found in ${dir} — weakens CSP significantly.`);
      score -= 3;
    }
    if (vals.includes("'unsafe-eval'")) {
      issues.push(`'unsafe-eval' found in ${dir} — allows arbitrary code execution.`);
      score -= 3;
    }
  }

  // Check for wildcard sources
  for (const [dir, vals] of Object.entries(directives)) {
    if (vals.includes('*')) {
      issues.push(`Wildcard source '*' in ${dir} — too permissive.`);
      score -= 2;
    }
  }

  // Check for frame-ancestors (clickjacking)
  if (!directives['frame-ancestors']) {
    issues.push("Missing 'frame-ancestors' — consider adding frame-ancestors 'none' or 'self'.");
    score -= 1;
  }

  // Bonus for report-uri/report-to
  if (directives['report-uri'] || directives['report-to']) {
    score += 2;
  }

  score = Math.max(0, Math.min(15, score));

  if (issues.length === 0) {
    return {
      header: 'Content-Security-Policy',
      status: 'pass',
      severity: 'info',
      value,
      message: 'Content-Security-Policy is well configured.',
      recommendation: null,
      score,
      maxScore: 15,
    };
  }

  return {
    header: 'Content-Security-Policy',
    status: score >= 7 ? 'warn' : 'fail',
    severity: score >= 7 ? 'medium' : 'high',
    value,
    message: issues.join(' '),
    recommendation: buildRecommendation(directives, issues),
    score,
    maxScore: 15,
  };
}

function parseDirectives(csp: string): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length === 0 || !tokens[0]) continue;
    const name = tokens[0].toLowerCase();
    result[name] = tokens.slice(1);
  }
  return result;
}

function buildRecommendation(directives: Record<string, string[]>, issues: string[]): string {
  const parts: string[] = [];

  if (issues.some(i => i.includes('unsafe-inline'))) {
    parts.push("Remove 'unsafe-inline' and use nonce-based or hash-based CSP instead.");
  }
  if (issues.some(i => i.includes('unsafe-eval'))) {
    parts.push("Remove 'unsafe-eval'. Refactor code to avoid eval().");
  }
  if (!directives['default-src']) {
    parts.push("Add: default-src 'self';");
  }
  if (!directives['frame-ancestors']) {
    parts.push("Add: frame-ancestors 'none';");
  }

  parts.push("Recommended: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  return parts.join('\n');
}
