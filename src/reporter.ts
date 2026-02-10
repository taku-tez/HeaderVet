import chalk from 'chalk';
import type { ScanResult, SarifResult, HeaderCheck, Status, Grade } from './types.js';

interface TableOptions {
  verbose?: boolean;
}

// ── Table Output ──

export function formatTable(results: ScanResult[], opts: TableOptions = {}): string {
  const out: string[] = [];

  for (const r of results) {
    out.push('');
    out.push(chalk.bold(`🔍 ${r.url}`));
    if (r.url !== r.finalUrl) {
      out.push(chalk.dim(`   ↳ Final URL: ${r.finalUrl}`));
    }
    if (r.redirectChain.length > 0) {
      out.push(chalk.dim(`   ↳ Redirects: ${r.redirectChain.map(h => `${h.statusCode} ${h.url}`).join(' → ')}`));
    }
    out.push('');

    // Header row
    const hdrLine = `  ${'Status'.padEnd(8)} ${'Header'.padEnd(32)} ${'Score'.padEnd(8)} ${'Severity'.padEnd(10)} Details`;
    out.push(chalk.dim(hdrLine));
    out.push(chalk.dim('  ' + '─'.repeat(100)));

    for (const c of r.checks) {
      const icon = statusIcon(c.status);
      const scoreStr = `${c.score}/${c.maxScore}`;
      const sev = c.severity.toUpperCase().padEnd(10);
      const line = `  ${icon.padEnd(10)} ${c.header.padEnd(32)} ${scoreStr.padEnd(8)} ${sev} ${c.message}`;
      out.push(colorLine(line, c.status));

      if (opts.verbose && c.detail) {
        out.push(chalk.dim(`  ${''.padEnd(10)} ${''.padEnd(32)} ${''.padEnd(8)} ${''.padEnd(10)} ℹ️  ${c.detail}`));
      }

      if (c.recommendation) {
        for (const recLine of c.recommendation.split('\n')) {
          out.push(chalk.yellow(`  ${''.padEnd(10)} ${''.padEnd(32)} ${''.padEnd(8)} ${''.padEnd(10)} 💡 ${recLine}`));
        }
      }
    }

    out.push('');
    out.push(gradeBlock(r.grade, r.totalScore, r.maxScore));
    out.push('');
  }

  return out.join('\n');
}

// ── Quiet Output ──

export function formatQuiet(results: ScanResult[]): string {
  return results.map(r => `${r.url}: ${r.grade}`).join('\n');
}

// ── Summary Output (multiple URLs) ──

export function formatSummary(results: ScanResult[]): string {
  const out: string[] = [];
  out.push('');
  out.push(chalk.bold('📊 Summary'));
  out.push(chalk.dim('  ' + '─'.repeat(60)));

  const gradeCounts: Record<string, number> = {};
  let totalScore = 0;
  let totalMax = 0;

  for (const r of results) {
    gradeCounts[r.grade] = (gradeCounts[r.grade] || 0) + 1;
    totalScore += r.totalScore;
    totalMax += r.maxScore;
  }

  const avgPct = totalMax > 0 ? Math.round((totalScore / totalMax) * 100) : 0;

  out.push(`  URLs scanned: ${results.length}`);
  out.push(`  Average score: ${avgPct}%`);
  out.push(`  Grade distribution: ${Object.entries(gradeCounts).map(([g, c]) => `${g}×${c}`).join(', ')}`);

  // Worst URL
  const worst = results.reduce((a, b) => (a.totalScore / a.maxScore) < (b.totalScore / b.maxScore) ? a : b);
  out.push(`  Worst: ${worst.url} (${worst.grade})`);

  // Best URL
  const best = results.reduce((a, b) => (a.totalScore / a.maxScore) > (b.totalScore / b.maxScore) ? a : b);
  out.push(`  Best:  ${best.url} (${best.grade})`);

  out.push('');
  return out.join('\n');
}

function statusIcon(s: Status): string {
  switch (s) {
    case 'pass': return '✅ PASS';
    case 'warn': return '⚠️  WARN';
    case 'fail': return '❌ FAIL';
    case 'missing': return '🚫 MISS';
  }
}

function colorLine(line: string, s: Status): string {
  switch (s) {
    case 'pass': return chalk.green(line);
    case 'warn': return chalk.yellow(line);
    case 'fail': return chalk.red(line);
    case 'missing': return chalk.red(line);
  }
}

function gradeBlock(grade: Grade, total: number, max: number): string {
  const pct = max > 0 ? Math.round((total / max) * 100) : 0;
  const bar = `  Score: ${total}/${max} (${pct}%)`;
  const g = `  Grade: ${grade}`;

  const color = ['A+', 'A'].includes(grade) ? chalk.green
    : grade === 'B' ? chalk.cyan
    : grade === 'C' ? chalk.yellow
    : chalk.red;

  return [chalk.bold(color(g)), chalk.dim(bar)].join('\n');
}

// ── JSON Output ──

export function formatJSON(results: ScanResult[]): string {
  return JSON.stringify(results.length === 1 ? results[0] : results, null, 2);
}

// ── SARIF Output ──

export function formatSARIF(results: ScanResult[]): string {
  const allChecks: { check: HeaderCheck; url: string }[] = [];
  for (const r of results) {
    for (const c of r.checks) {
      allChecks.push({ check: c, url: r.url });
    }
  }

  const ruleMap = new Map<string, { id: string; desc: string }>();
  for (const { check } of allChecks) {
    const id = check.header.toLowerCase().replace(/[^a-z0-9]/g, '-');
    if (!ruleMap.has(id)) {
      ruleMap.set(id, { id, desc: `Check for ${check.header}` });
    }
  }

  const sarif: SarifResult = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'HeaderVet',
          version: '1.0.0',
          informationUri: 'https://github.com/taku-tez/HeaderVet',
          rules: Array.from(ruleMap.values()).map(r => ({
            id: r.id,
            shortDescription: { text: r.desc },
          })),
        },
      },
      results: allChecks
        .filter(({ check }) => check.status !== 'pass')
        .map(({ check, url }) => ({
          ruleId: check.header.toLowerCase().replace(/[^a-z0-9]/g, '-'),
          level: severityToLevel(check.status),
          message: {
            text: check.recommendation
              ? `${check.message}\n\nRecommendation: ${check.recommendation}`
              : check.message,
          },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: url },
            },
          }],
        })),
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

function severityToLevel(s: Status): 'error' | 'warning' | 'note' | 'none' {
  switch (s) {
    case 'fail': case 'missing': return 'error';
    case 'warn': return 'warning';
    case 'pass': return 'none';
  }
}
