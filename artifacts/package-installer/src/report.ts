/**
 * Batch report assembly and export.
 *
 * These reports get committed and diffed, so byte-for-byte determinism is a
 * requirement: given the same inputs and the same `generatedAt`, two runs must
 * produce identical JSON. That rules out wall-clock timings and any ordering
 * that depends on completion order — see `includeTimings`.
 */

import { analyzeBatch, type PackageSummary, type ScannedPackage, type SignerPins } from './diff.js';
import type { ApkJsonReport } from './inspect.js';
import type { ScanResult } from './batch.js';
import type { Finding, Severity } from './safety.js';

export const BATCH_SCHEMA_VERSION = 1;

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface BatchResultEntry {
  sourceId: string;
  status: 'ok' | 'failed';
  report: ApkJsonReport | null;
  error: string | null;
  /** Present only when `includeTimings` was set; excluded by default so the
   *  report stays reproducible. */
  durationMs?: number;
}

export interface BatchTotals {
  scanned: number;
  ok: number;
  failed: number;
  /** Packages with a critical or high finding. */
  blocked: number;
  /** Scanned APKs with nothing above `info`. */
  clean: number;
  /**
   * Successfully scanned APKs counted by their worst severity. `info` is always
   * zero: a report whose findings are all informational has `worstSeverity`
   * null and is counted under `clean` instead.
   */
  bySeverity: Record<Severity, number>;
}

export interface BatchReport {
  schemaVersion: typeof BATCH_SCHEMA_VERSION;
  generatedAt: string;
  totals: BatchTotals;
  results: BatchResultEntry[];
  packages: PackageSummary[];
  /** Cross-version, cross-package and pinning findings, worst-first. */
  findings: Finding[];
}

export interface BuildBatchReportOptions {
  /** Fixed timestamp for reproducible output. Defaults to now. */
  generatedAt?: Date;
  /** Expected signing keys per package. */
  pins?: SignerPins;
  /** Include per-source durations. Makes the report non-reproducible. */
  includeTimings?: boolean;
}

/** Assembles scan results into the durable batch report. */
export function buildBatchReport(
  results: ScanResult[],
  options: BuildBatchReportOptions = {},
): BatchReport {
  const { generatedAt = new Date(), pins, includeTimings = false } = options;

  const scanned: ScannedPackage[] = [];
  const entries: BatchResultEntry[] = [];
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let ok = 0;
  let failed = 0;
  let blocked = 0;
  let clean = 0;

  for (const result of results) {
    const entry: BatchResultEntry = {
      sourceId: result.sourceId,
      status: result.status,
      report: result.status === 'ok' ? result.report : null,
      error: result.status === 'failed' ? result.error : null,
    };
    if (includeTimings) entry.durationMs = result.durationMs;
    entries.push(entry);

    if (result.status === 'ok') {
      ok++;
      scanned.push({ sourceId: result.sourceId, report: result.report });
      const worst = result.report.safety.worstSeverity;
      if (worst !== null) bySeverity[worst]++;
      else clean++;
      if (result.report.safety.blockInstall) blocked++;
    } else {
      failed++;
    }
  }

  const analysis = analyzeBatch(scanned, pins);

  return {
    schemaVersion: BATCH_SCHEMA_VERSION,
    generatedAt: generatedAt.toISOString(),
    totals: { scanned: results.length, ok, failed, blocked, clean, bySeverity },
    // Input order already; sorting by id keeps output stable if a caller
    // assembles results from several batches.
    results: [...entries].sort((a, b) => a.sourceId.localeCompare(b.sourceId)),
    packages: analysis.packages,
    findings: analysis.findings,
  };
}

function csvCell(value: string | number | boolean | null): string {
  const text = value === null ? '' : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

const CSV_COLUMNS = [
  'sourceId',
  'status',
  'package',
  'versionName',
  'versionCode',
  'score',
  'worstSeverity',
  'blockInstall',
  'signerSha256',
  'findingCount',
  'error',
] as const;

/** One row per scanned APK, for spreadsheet triage. */
export function toCsv(report: BatchReport): string {
  const rows: string[] = [CSV_COLUMNS.join(',')];

  for (const entry of report.results) {
    const r = entry.report;
    rows.push(
      [
        entry.sourceId,
        entry.status,
        r?.package ?? null,
        r?.versionName ?? null,
        r?.versionCode ?? null,
        r?.safety.score ?? null,
        r?.safety.worstSeverity ?? null,
        r ? r.safety.blockInstall : null,
        r ? [...new Set(r.certificates.map((c) => c.sha256))].sort().join(' ') : null,
        r?.safety.findings.length ?? null,
        entry.error,
      ]
        .map(csvCell)
        .join(','),
    );
  }

  return `${rows.join('\n')}\n`;
}

/** True when the report contains a finding of exactly this severity. */
function hasSeverity(report: BatchReport, severity: Severity): boolean {
  if (report.totals.bySeverity[severity] > 0) return true;
  if (report.findings.some((f) => f.severity === severity)) return true;
  // Per-APK info findings are not summarised in `bySeverity`, so look directly.
  return report.results.some((entry) =>
    entry.report?.safety.findings.some((f) => f.severity === severity),
  );
}

/** Highest severity present anywhere in the report, or null when clean. */
export function worstSeverityOf(report: BatchReport): Severity | null {
  return SEVERITIES.find((severity) => hasSeverity(report, severity)) ?? null;
}

/** True when anything at or above `threshold` fired — the CLI's exit condition. */
export function meetsThreshold(report: BatchReport, threshold: Severity): boolean {
  const limit = SEVERITIES.indexOf(threshold);
  if (limit < 0) return false;
  return SEVERITIES.slice(0, limit + 1).some((severity) => hasSeverity(report, severity));
}
