import type { HeaderCheck } from '../types.js';

const HEADER = 'access-control-allow-origin';

export function checkCORS(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    // No CORS header is fine — means no cross-origin access allowed
    return {
      header: 'Access-Control-Allow-Origin',
      status: 'pass',
      severity: 'info',
      value: null,
      message: 'Access-Control-Allow-Origin is absent — no cross-origin resource sharing enabled.',
      recommendation: null,
      detail: 'Not setting CORS headers is the most restrictive option. Resources are only accessible from the same origin.',
      score: 5,
      maxScore: 5,
    };
  }

  // Wildcard * allows any origin
  if (value.trim() === '*') {
    return {
      header: 'Access-Control-Allow-Origin',
      status: 'fail',
      severity: 'high',
      value,
      message: 'Access-Control-Allow-Origin is set to wildcard (*) — any origin can access resources. This can lead to data leakage and CSRF-like attacks.',
      recommendation: 'Restrict Access-Control-Allow-Origin to specific trusted origins instead of using wildcard (*).',
      detail: 'A wildcard CORS policy allows any website to make cross-origin requests and read responses. This is dangerous for authenticated endpoints and can expose sensitive data.',
      score: 0,
      maxScore: 5,
    };
  }

  // null origin is dangerous (can be spoofed via sandboxed iframes, data: URIs)
  if (value.trim().toLowerCase() === 'null') {
    return {
      header: 'Access-Control-Allow-Origin',
      status: 'fail',
      severity: 'high',
      value,
      message: 'Access-Control-Allow-Origin is set to "null" — this is exploitable via sandboxed iframes and data: URIs.',
      recommendation: 'Never use "null" as an allowed origin. Specify explicit trusted origins.',
      detail: 'The "null" origin can be triggered by attackers using sandboxed iframes, local file requests, or data: URIs, making this effectively as dangerous as a wildcard.',
      score: 0,
      maxScore: 5,
    };
  }

  // Specific origin — check for http:// (non-secure)
  const trimmed = value.trim();
  if (trimmed.startsWith('http://')) {
    return {
      header: 'Access-Control-Allow-Origin',
      status: 'warn',
      severity: 'medium',
      value,
      message: `Access-Control-Allow-Origin allows non-HTTPS origin: ${trimmed}. Consider using HTTPS origins only.`,
      recommendation: 'Use HTTPS origins in Access-Control-Allow-Origin to prevent data exposure over insecure connections.',
      detail: 'Allowing HTTP origins means cross-origin responses can be intercepted by network attackers.',
      score: 3,
      maxScore: 5,
    };
  }

  // Specific HTTPS origin — good
  return {
    header: 'Access-Control-Allow-Origin',
    status: 'pass',
    severity: 'info',
    value,
    message: `Access-Control-Allow-Origin is restricted to: ${trimmed}.`,
    recommendation: null,
    detail: 'CORS is configured with a specific origin, which is the recommended approach.',
    score: 5,
    maxScore: 5,
  };
}
