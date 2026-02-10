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
      recommendation: "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
      detail: 'CSP is the most important security header. It prevents XSS, clickjacking, and data injection attacks by controlling which resources the browser is allowed to load.',
      score: 0,
      maxScore: 15,
    };
  }

  const issues: string[] = [];
  let score = 8; // base for having it

  const directives = parseDirectives(value);

  // default-src check
  if (!directives['default-src']) {
    issues.push("Missing 'default-src' directive.");
    score -= 2;
  }

  // unsafe-inline / unsafe-eval checks
  for (const [dir, vals] of Object.entries(directives)) {
    if (vals.includes("'unsafe-inline'")) {
      // style-src unsafe-inline is common and low risk; script-src is high risk
      if (dir === 'script-src' || dir === 'default-src') {
        issues.push(`'unsafe-inline' found in ${dir} — weakens CSP significantly.`);
        score -= 3;
      } else {
        issues.push(`'unsafe-inline' found in ${dir} — consider removing if possible.`);
        score -= 1;
      }
    }
    if (vals.includes("'unsafe-eval'")) {
      issues.push(`'unsafe-eval' found in ${dir} — allows arbitrary code execution.`);
      score -= 3;
    }
  }

  // Wildcard sources
  for (const [dir, vals] of Object.entries(directives)) {
    if (vals.includes('*')) {
      issues.push(`Wildcard source '*' in ${dir} — too permissive.`);
      score -= 2;
    }
  }

  // frame-ancestors (clickjacking)
  if (!directives['frame-ancestors']) {
    issues.push("Missing 'frame-ancestors' — consider adding frame-ancestors 'none' or 'self'.");
    score -= 1;
  }

  // base-uri restriction
  if (!directives['base-uri']) {
    issues.push("Missing 'base-uri' — add base-uri 'self' or 'none' to prevent base tag injection.");
    score -= 1;
  }

  // form-action restriction
  if (!directives['form-action']) {
    issues.push("Missing 'form-action' — add form-action 'self' to restrict form submission targets.");
    score -= 1;
  }

  // object-src restriction
  if (!directives['object-src']) {
    issues.push("Missing 'object-src' — add object-src 'none' to prevent plugin-based attacks.");
    score -= 1;
  }

  // script-src nonce/hash recommendation
  const scriptSrc = directives['script-src'] || directives['default-src'] || [];
  const hasNonce = scriptSrc.some(v => v.startsWith("'nonce-"));
  const hasHash = scriptSrc.some(v => v.startsWith("'sha256-") || v.startsWith("'sha384-") || v.startsWith("'sha512-"));
  if (!hasNonce && !hasHash && scriptSrc.length > 0 && !scriptSrc.includes("'none'")) {
    issues.push("Consider using nonce-based or hash-based CSP for script-src for stronger protection.");
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
      detail: 'CSP includes all recommended directives with restrictive values.',
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
    detail: 'CSP is present but has configuration issues that reduce its effectiveness.',
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
  if (!directives['base-uri']) {
    parts.push("Add: base-uri 'self';");
  }
  if (!directives['form-action']) {
    parts.push("Add: form-action 'self';");
  }
  if (!directives['object-src']) {
    parts.push("Add: object-src 'none';");
  }

  parts.push("Recommended: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'");
  return parts.join('\n');
}

// Export for testing
export { parseDirectives };
