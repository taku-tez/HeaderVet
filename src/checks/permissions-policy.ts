import type { HeaderCheck } from '../types.js';

const HEADER = 'permissions-policy';
const DANGEROUS_APIS = ['camera', 'microphone', 'geolocation', 'payment'];

export function checkPermissionsPolicy(headers: Record<string, string>): HeaderCheck {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      header: 'Permissions-Policy',
      status: 'missing',
      severity: 'medium',
      value: null,
      message: 'Permissions-Policy header is missing.',
      recommendation: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
      detail: 'Permissions-Policy controls which browser features and APIs can be used. Without it, any embedded content could access sensitive features like camera and microphone.',
      score: 0,
      maxScore: 5,
    };
  }

  const issues: string[] = [];
  let score = 3;
  const policies = value.toLowerCase();

  for (const feature of DANGEROUS_APIS) {
    if (policies.includes(`${feature}=*`) || policies.includes(`${feature}=("*")`)) {
      issues.push(`${feature} is allowed for all origins — restrict it.`);
      score -= 1;
    } else if (policies.includes(`${feature}=()`)) {
      score += 0.5;
    } else if (!policies.includes(feature)) {
      issues.push(`${feature} is not explicitly restricted — add ${feature}=() to deny access.`);
    }
  }

  score = Math.max(0, Math.min(5, Math.round(score)));

  if (issues.length === 0) {
    return {
      header: 'Permissions-Policy',
      status: 'pass',
      severity: 'info',
      value,
      message: 'Permissions-Policy is well configured with all dangerous APIs restricted.',
      recommendation: null,
      detail: 'All sensitive APIs (camera, microphone, geolocation, payment) are explicitly denied.',
      score,
      maxScore: 5,
    };
  }

  return {
    header: 'Permissions-Policy',
    status: 'warn',
    severity: 'medium',
    value,
    message: issues.join(' '),
    recommendation: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
    detail: 'Permissions-Policy is present but does not restrict all dangerous APIs.',
    score,
    maxScore: 5,
  };
}
