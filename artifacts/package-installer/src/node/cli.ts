#!/usr/bin/env node
/**
 * apk-scan — batch-scan APKs and write JSON safety reports.
 *
 * Exists so the scanner is usable today from a terminal or CI job, independent
 * of any installer UI. Exits non-zero when a finding at or above `--fail-on`
 * fires, which is what makes it a gate rather than a viewer.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { scanBatch, type ScanProgress } from '../batch.js';
import { buildBatchReport, meetsThreshold, toCsv, type BatchReport } from '../report.js';
import type { SignerPins } from '../diff.js';
import type { Severity } from '../safety.js';
import { fromPaths } from './sources.js';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const USAGE = `apk-scan — batch APK manifest, signature and safety scanning

Usage:
  apk-scan <path...> [options]

Paths may be APK files or directories (searched recursively).

Options:
  --out <dir>            Write batch.json/batch.csv plus one report per APK
  --pins <file>          JSON map of package name -> [expected signer SHA-256]
  --concurrency <n>      Sources scanned at once (default 4)
  --format <json|csv>    Output format for the batch report (default json)
  --fail-on <severity>   Exit 1 when a finding at or above this fires
                         (critical|high|medium|low|info|none, default none)
  --generated-at <iso>   Fixed timestamp, for reproducible output
  --timings              Include per-source durations (makes output non-reproducible)
  --quiet                Suppress progress output
  --help                 Show this message
`;

interface Options {
  paths: string[];
  out: string | null;
  pins: string | null;
  concurrency: number;
  format: 'json' | 'csv';
  failOn: Severity | null;
  generatedAt: Date | undefined;
  timings: boolean;
  quiet: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: string[]): Options {
  const options: Options = {
    paths: [],
    out: null,
    pins: null,
    concurrency: 4,
    format: 'json',
    failOn: null,
    generatedAt: undefined,
    timings: false,
    quiet: false,
  };

  const next = (i: number, flag: string): string => {
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new UsageError(`${flag} needs a value`);
    }
    return value;
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--out':
        options.out = next(i, arg);
        i++;
        break;
      case '--pins':
        options.pins = next(i, arg);
        i++;
        break;
      case '--concurrency': {
        const value = Number.parseInt(next(i, arg), 10);
        if (!Number.isFinite(value) || value < 1) {
          throw new UsageError('--concurrency must be a positive integer');
        }
        options.concurrency = value;
        i++;
        break;
      }
      case '--format': {
        const value = next(i, arg);
        if (value !== 'json' && value !== 'csv') {
          throw new UsageError('--format must be json or csv');
        }
        options.format = value;
        i++;
        break;
      }
      case '--fail-on': {
        const value = next(i, arg);
        if (value === 'none') options.failOn = null;
        else if ((SEVERITIES as string[]).includes(value)) options.failOn = value as Severity;
        else throw new UsageError(`--fail-on must be one of ${SEVERITIES.join('|')}|none`);
        i++;
        break;
      }
      case '--generated-at': {
        const value = new Date(next(i, arg));
        if (Number.isNaN(value.getTime())) throw new UsageError('--generated-at must be an ISO date');
        options.generatedAt = value;
        i++;
        break;
      }
      case '--timings':
        options.timings = true;
        break;
      case '--quiet':
        options.quiet = true;
        break;
      case '--help':
      case '-h':
        process.stdout.write(USAGE);
        process.exit(0);
        break;
      default:
        if (arg.startsWith('--')) throw new UsageError(`unknown option ${arg}`);
        options.paths.push(arg);
    }
  }

  if (options.paths.length === 0) throw new UsageError('no input paths given');
  return options;
}

/** Turns a source id into something safe to use as a filename. */
function reportFileName(sourceId: string): string {
  return `${sourceId.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'report'}.json`;
}

function summarize(report: BatchReport, quiet: boolean): void {
  if (quiet) return;
  const { totals } = report;
  process.stderr.write(
    `\nScanned ${totals.scanned} — ${totals.ok} ok, ${totals.failed} failed, ` +
      `${totals.blocked} blocked, ${totals.clean} clean\n`,
  );

  const counts = SEVERITIES.map((s) => `${s}: ${totals.bySeverity[s]}`).join('  ');
  process.stderr.write(`Worst severity per APK — ${counts}\n`);

  if (report.findings.length > 0) {
    process.stderr.write(`\nCross-package findings (${report.findings.length}):\n`);
    for (const finding of report.findings.slice(0, 20)) {
      process.stderr.write(`  [${finding.severity}] ${finding.title} — ${finding.evidence ?? ''}\n`);
    }
    if (report.findings.length > 20) {
      process.stderr.write(`  … ${report.findings.length - 20} more\n`);
    }
  }
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n\n${USAGE}`);
    process.exitCode = 2;
    return;
  }

  let pins: SignerPins | undefined;
  if (options.pins !== null) {
    pins = JSON.parse(await readFile(options.pins, 'utf8')) as SignerPins;
  }

  const sources = await fromPaths(options.paths);
  if (sources.length === 0) {
    process.stderr.write('no APK-like files found\n');
    process.exitCode = 2;
    return;
  }

  const onProgress = options.quiet
    ? undefined
    : ({ completed, total, sourceId }: ScanProgress): void => {
        process.stderr.write(`[${completed}/${total}] ${sourceId}\n`);
      };

  const results = await scanBatch(sources, {
    concurrency: options.concurrency,
    onProgress,
    now: options.generatedAt,
  });

  const report = buildBatchReport(results, {
    generatedAt: options.generatedAt,
    pins,
    includeTimings: options.timings,
  });

  const serialized =
    options.format === 'csv' ? toCsv(report) : `${JSON.stringify(report, null, 2)}\n`;

  if (options.out !== null) {
    await mkdir(options.out, { recursive: true });
    await writeFile(join(options.out, `batch.${options.format}`), serialized);
    for (const entry of report.results) {
      if (entry.report === null) continue;
      await writeFile(
        join(options.out, reportFileName(entry.sourceId)),
        `${JSON.stringify(entry.report, null, 2)}\n`,
      );
    }
    if (!options.quiet) process.stderr.write(`\nWrote reports to ${options.out}\n`);
  } else {
    process.stdout.write(serialized);
  }

  summarize(report, options.quiet);

  if (options.failOn !== null && meetsThreshold(report, options.failOn)) {
    if (!options.quiet) {
      process.stderr.write(`\nFailing: a finding at or above "${options.failOn}" was reported.\n`);
    }
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
