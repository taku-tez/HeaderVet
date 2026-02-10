export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
export type Status = 'pass' | 'warn' | 'fail' | 'missing';

export interface HeaderCheck {
  header: string;
  status: Status;
  severity: Severity;
  value: string | null;
  message: string;
  recommendation: string | null;
  /** Points awarded (0-10 per check) */
  score: number;
  /** Max possible points for this check */
  maxScore: number;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  statusCode: number;
  redirectChain: RedirectHop[];
  checks: HeaderCheck[];
  grade: Grade;
  totalScore: number;
  maxScore: number;
  timestamp: string;
}

export interface RedirectHop {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
}

export interface ScanOptions {
  followRedirects?: boolean;
  timeout?: number;
  userAgent?: string;
}

export interface CliOptions {
  json?: boolean;
  sarif?: boolean;
  ci?: boolean;
  minGrade?: string;
  stdin?: boolean;
  timeout?: number;
}

export interface SarifResult {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } };
  results: SarifResultEntry[];
}

export interface SarifRule {
  id: string;
  shortDescription: { text: string };
  helpUri?: string;
}

export interface SarifResultEntry {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
}
