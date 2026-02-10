import type { HeaderCheck } from '../types.js';

const HEADER = 'permissions-policy';

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
      score: 0,
      maxScore: 5,
    };
  }

  const issues: string[] = [];
  let score = 3;

  // Check if sensitive features are restricted
  const sensitiveFeatures = ['camera', 'microphone', 'geolocation', 'payment'];
  const policies = value.toLowerCase();

  for (const feature of sensitiveFeatures) {
    if (policies.includes(`${feature}=*`) || policies.includes(`${feature}=("*")`)) {
      issues.push(`${feature} is allowed for all origins — restrict it.`);
      score -= 1;
    } else if (policies.includes(`${feature}=()`)) {
      score += 0.5;
    }
  }

  score = Math.max(0, Math.min(5, Math.round(score)));

  if (issues.length === 0) {
    return {
      header: 'Permissions-Policy',
      status: 'pass',
      severity: 'info',
      value,
      message: 'Permissions-Policy is configured.',
      recommendation: null,
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
    score,
    maxScore: 5,
  };
}
