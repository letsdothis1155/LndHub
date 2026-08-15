/**
 * Batch scanning over many APKs.
 *
 * The governing constraint is memory: `ApkInspection` holds `archive.bytes`,
 * the entire APK. Retaining inspections across a batch would pin every package
 * in memory at once, so the pipeline is strictly load -> inspect -> project to
 * `ApkJsonReport` -> drop the bytes. Only the JSON survives a scan step.
 */

import { inspectApk, toJsonReport, type ApkInspection, type ApkJsonReport } from './inspect.js';

export interface ApkSource {
  /** Stable identity for the report: a filename, catalog id, or URL. */
  id: string;
  /** Optional, for progress UI only. */
  size?: number;
  /** Called at most once; the returned bytes are released after inspection. */
  load(): Promise<Uint8Array>;
}

export interface ScanOk {
  status: 'ok';
  sourceId: string;
  report: ApkJsonReport;
  durationMs: number;
  /** Only present when `keepInspections` was requested. Holds the APK bytes. */
  inspection?: ApkInspection;
}

export interface ScanFailed {
  status: 'failed';
  sourceId: string;
  error: string;
  durationMs: number;
}

export type ScanResult = ScanOk | ScanFailed;

export interface ScanProgress {
  completed: number;
  total: number;
  sourceId: string;
}

export type InspectFn = typeof inspectApk;

export interface ScanBatchOptions {
  /** Sources inspected at once. Default 4. See the note on parallelism below. */
  concurrency?: number;
  signal?: AbortSignal;
  onProgress?: (progress: ScanProgress) => void;
  /** Swap in a Worker-backed inspector; defaults to the in-process one. */
  inspect?: InspectFn;
  /** Injected clock, so certificate-validity findings are reproducible. */
  now?: Date;
  /**
   * Keep the full `ApkInspection` on each result. Off by default: each one
   * retains the whole APK, so this is only safe for small batches.
   */
  keepInspections?: boolean;
}

/** Thrown when a batch is cancelled; carries whatever finished first. */
export class BatchAbortError extends Error {
  override readonly name = 'AbortError';
  readonly partialResults: ScanResult[];

  constructor(partialResults: ScanResult[]) {
    super('batch scan was aborted');
    this.partialResults = partialResults;
  }
}

function elapsed(since: number): number {
  return Math.max(0, Math.round(Date.now() - since));
}

/**
 * Scans every source, isolating failures.
 *
 * A source that cannot be read yields a `failed` result rather than rejecting
 * the batch — one corrupt package in a catalog must not cost you the other 199.
 * Results come back in input order regardless of completion order, so reports
 * diff cleanly between runs.
 *
 * On parallelism: parsing is CPU-bound and synchronous (inflate in particular),
 * so `concurrency` mainly overlaps `load()` I/O with parsing rather than giving
 * true parallel decode. Real parallelism needs Workers — supply a Worker-backed
 * `inspect` for that; this module deliberately ships no bundler-specific worker.
 */
export async function scanBatch(
  sources: ApkSource[],
  options: ScanBatchOptions = {},
): Promise<ScanResult[]> {
  const {
    concurrency = 4,
    signal,
    onProgress,
    inspect = inspectApk,
    now,
    keepInspections = false,
  } = options;

  const results: (ScanResult | undefined)[] = new Array(sources.length);
  let cursor = 0;
  let completed = 0;

  if (signal?.aborted) throw new BatchAbortError([]);

  const worker = async (): Promise<void> => {
    for (;;) {
      if (signal?.aborted) return;
      const index = cursor++;
      if (index >= sources.length) return;

      const source = sources[index];
      const started = Date.now();
      try {
        const bytes = await source.load();
        const inspection = await inspect(bytes, { now });
        const result: ScanOk = {
          status: 'ok',
          sourceId: source.id,
          report: toJsonReport(inspection),
          durationMs: elapsed(started),
        };
        // Attaching the inspection re-pins the APK bytes, so it is opt-in.
        if (keepInspections) result.inspection = inspection;
        results[index] = result;
      } catch (error) {
        results[index] = {
          status: 'failed',
          sourceId: source.id,
          error: error instanceof Error ? error.message : String(error),
          durationMs: elapsed(started),
        };
      }

      completed++;
      onProgress?.({ completed, total: sources.length, sourceId: source.id });
    }
  };

  const workerCount = Math.max(1, Math.min(Math.floor(concurrency) || 1, sources.length));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));

  const settled = results.filter((r): r is ScanResult => r !== undefined);
  if (signal?.aborted) throw new BatchAbortError(settled);
  return settled;
}

/** Convenience source for in-memory bytes (a browser File, a fetched buffer). */
export function sourceFromBytes(id: string, bytes: Uint8Array): ApkSource {
  return { id, size: bytes.length, load: async () => bytes };
}

/** Convenience source for a browser File / Blob. */
export function sourceFromFile(file: { name: string; size: number; arrayBuffer(): Promise<ArrayBuffer> }): ApkSource {
  return {
    id: file.name,
    size: file.size,
    load: async () => new Uint8Array(await file.arrayBuffer()),
  };
}
