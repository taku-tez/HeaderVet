#!/usr/bin/env node

import { Command } from 'commander';
import { fetchHeaders } from './scanner.js';
import { checkCSP } from './checks/csp.js';
import { checkHSTS } from './checks/hsts.js';
import { checkXFrameOptions } from './checks/x-frame.js';
import { checkPermissionsPolicy } from './checks/permissions-policy.js';
import { checkCOOP } from './checks/coop.js';
import { checkCOEP } from './checks/coep.js';
import { checkCORP } from './checks/corp.js';
import { checkReferrerPolicy } from './checks/referrer.js';
import { checkCacheControl } from './checks/cache.js';
import { checkXContentTypeOptions, checkXXSSProtection } from './checks/misc.js';
import { checkSetCookie } from './checks/set-cookie.js';
import { checkDNSPrefetchControl } from './checks/dns-prefetch.js';
import { calculateGrade, meetsMinGrade, parseGrade } from './scoring.js';
import { formatTable, formatJSON, formatSARIF, formatSummary, formatQuiet } from './reporter.js';
import type { ScanResult, HeaderCheck, Grade, ScanOptions } from './types.js';
import * as readline from 'node:readline';

const ALL_CHECKS = [
  checkCSP,
  checkHSTS,
  checkXFrameOptions,
  checkXContentTypeOptions,
  checkPermissionsPolicy,
  checkCOOP,
  checkCOEP,
  checkCORP,
  checkReferrerPolicy,
  checkXXSSProtection,
  checkCacheControl,
  checkSetCookie,
  checkDNSPrefetchControl,
];

export async function scanUrl(url: string, opts: ScanOptions = {}): Promise<ScanResult> {
  // Ensure URL has protocol
  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }

  const result = await fetchHeaders(url, opts);
  const checks: HeaderCheck[] = ALL_CHECKS.map(fn => fn(result.headers));
  const { grade, totalScore, maxScore } = calculateGrade(checks);

  return {
    url,
    finalUrl: result.finalUrl,
    statusCode: result.statusCode,
    redirectChain: result.redirectChain,
    checks,
    grade,
    totalScore,
    maxScore,
    timestamp: new Date().toISOString(),
  };
}

async function readStdinUrls(): Promise<string[]> {
  const rl = readline.createInterface({ input: process.stdin });
  const urls: string[] = [];
  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) urls.push(trimmed);
  }
  return urls;
}

function parseCustomHeaders(headerArgs: string[] | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!headerArgs) return result;
  for (const h of headerArgs) {
    const idx = h.indexOf(':');
    if (idx > 0) {
      result[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
    }
  }
  return result;
}

async function main() {
  const program = new Command();

  program
    .name('headervet')
    .description('HTTP Security Header checker — score, fix, and enforce security headers')
    .version('1.0.0')
    .argument('[urls...]', 'URLs to scan')
    .option('--json', 'Output as JSON')
    .option('--sarif', 'Output as SARIF')
    .option('--ci', 'CI mode — exit with non-zero code if grade is below threshold')
    .option('--min-grade <grade>', 'Minimum acceptable grade (default: C)', 'C')
    .option('--stdin', 'Read URLs from stdin (one per line)')
    .option('--timeout <ms>', 'Request timeout in milliseconds', '10000')
    .option('--follow-redirects', 'Follow redirects (default: true)', true)
    .option('--no-follow-redirects', 'Do not follow redirects')
    .option('--user-agent <string>', 'Custom User-Agent string')
    .option('--cookie <string>', 'Cookie header for authenticated scanning')
    .option('--header <key:value>', 'Custom header (repeatable)', (val: string, prev: string[]) => [...prev, val], [] as string[])
    .option('--verbose', 'Show detailed explanations for each check')
    .option('--quiet', 'Output grade only')
    .action(async (urls: string[], opts) => {
      let targetUrls: string[] = urls;

      if (opts.stdin) {
        targetUrls = [...targetUrls, ...(await readStdinUrls())];
      }

      if (targetUrls.length === 0) {
        program.help();
        return;
      }

      const timeout = parseInt(opts.timeout, 10);
      const scanOpts: ScanOptions = {
        timeout,
        followRedirects: opts.followRedirects,
        userAgent: opts.userAgent,
        cookie: opts.cookie,
        customHeaders: parseCustomHeaders(opts.header),
      };
      const results: ScanResult[] = [];

      for (const url of targetUrls) {
        try {
          results.push(await scanUrl(url, scanOpts));
        } catch (err: any) {
          console.error(`Error scanning ${url}: ${err.message}`);
          process.exitCode = 1;
        }
      }

      if (results.length === 0) {
        process.exit(1);
      }

      // Output
      if (opts.quiet) {
        console.log(formatQuiet(results));
      } else if (opts.sarif) {
        console.log(formatSARIF(results));
      } else if (opts.json) {
        console.log(formatJSON(results));
      } else {
        console.log(formatTable(results, { verbose: opts.verbose }));
        if (results.length > 1) {
          console.log(formatSummary(results));
        }
      }

      // CI mode
      if (opts.ci) {
        const minGrade = parseGrade(opts.minGrade) ?? 'C';
        const failed = results.filter(r => !meetsMinGrade(r.grade, minGrade as Grade));
        if (failed.length > 0) {
          if (!opts.json && !opts.sarif && !opts.quiet) {
            console.error(`\n❌ CI check failed: ${failed.length} URL(s) below grade ${minGrade}`);
          }
          process.exit(1);
        }
      }
    });

  await program.parseAsync();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
