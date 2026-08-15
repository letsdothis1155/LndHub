/**
 * Catalog downloads with hash pinning, resume, and an inspection gate.
 *
 * Transport-agnostic on purpose: `fetch` is injected, so this works against
 * whatever the catalog is served from without this module needing to know.
 * Nothing is handed back to a caller until the bytes match the pinned hash —
 * a download that fails verification returns no bytes at all, so there is no
 * path where unverified content reaches an installer by accident.
 */

import { digest, toHex } from './bytes.js';
import { checkPins, type SignerPins } from './diff.js';
import { inspectApk, toJsonReport, type ApkInspection, type ApkJsonReport } from './inspect.js';
import { defaultQrEncoder, type ErrorCorrectionLevel, type QrCode, type QrEncoder } from './qr.js';
import type { Finding } from './safety.js';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface CatalogEntry {
  /** Stable catalog identity, used as the report's source id. */
  id: string;
  url: string;
  /** Pinned SHA-256 of the APK file. Verified before the bytes are returned. */
  sha256?: string;
  /** Expected byte length, checked before hashing. */
  size?: number;
  packageName?: string;
  versionCode?: number;
  /** Pinned signing certificate fingerprints. */
  signerFingerprints?: string[];
}

export class DownloadError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.status = status;
  }
}

/** Thrown when the bytes do not match the catalog's pinned hash. */
export class HashMismatchError extends DownloadError {
  readonly expected: string;
  readonly actual: string;

  constructor(expected: string, actual: string) {
    super(`downloaded bytes hash to ${actual}, but the catalog pins ${expected}`);
    this.expected = expected;
    this.actual = actual;
  }
}

export interface DownloadProgress {
  received: number;
  /** Total bytes when the server declares them, else null. */
  total: number | null;
  /** 0-1 when the total is known, else null. */
  ratio: number | null;
  attempt: number;
}

export interface DownloadOptions {
  fetch?: FetchLike;
  signal?: AbortSignal;
  onProgress?: (progress: DownloadProgress) => void;
  /** Hard ceiling on bytes accepted. Default 512 MiB. */
  maxBytes?: number;
  /** Resume attempts after a mid-stream failure. Default 2. */
  retries?: number;
  headers?: Record<string, string>;
}

export interface DownloadResult {
  bytes: Uint8Array;
  sha256: string;
  contentLength: number | null;
  attempts: number;
  /** True when a Range request picked up after an interrupted stream. */
  resumed: boolean;
}

const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;

function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

/**
 * Downloads an APK, verifying it against the catalog entry.
 *
 * A stream that breaks part-way is resumed with a Range request when the server
 * advertised `Accept-Ranges: bytes`; if the server ignores the Range header and
 * replies 200, the partial buffer is discarded and the download restarts rather
 * than splicing two different responses together.
 */
export async function downloadApk(
  entry: CatalogEntry,
  options: DownloadOptions = {},
): Promise<DownloadResult> {
  const {
    fetch: fetchImpl = globalThis.fetch as FetchLike | undefined,
    signal,
    onProgress,
    maxBytes = DEFAULT_MAX_BYTES,
    retries = 2,
    headers = {},
  } = options;

  if (typeof fetchImpl !== 'function') {
    throw new DownloadError('no fetch implementation available — pass options.fetch');
  }

  let chunks: Uint8Array[] = [];
  let received = 0;
  let contentLength: number | null = null;
  let acceptsRanges = false;
  let resumed = false;
  let attempt = 0;
  let lastError: unknown = null;

  while (attempt <= retries) {
    attempt++;
    if (signal?.aborted) throw new DownloadError('download aborted');

    const requestHeaders: Record<string, string> = { ...headers };
    const resuming = received > 0 && acceptsRanges;
    if (resuming) requestHeaders.Range = `bytes=${received}-`;

    let response: Response;
    try {
      response = await fetchImpl(entry.url, { headers: requestHeaders, signal });
    } catch (error) {
      if (isAbort(error)) throw error;
      lastError = error;
      continue;
    }

    if (!response.ok) {
      // 4xx is a statement about the request; retrying will not change it.
      if (response.status >= 400 && response.status < 500) {
        throw new DownloadError(
          `${entry.url} returned ${response.status} ${response.statusText}`,
          response.status,
        );
      }
      lastError = new DownloadError(
        `${entry.url} returned ${response.status} ${response.statusText}`,
        response.status,
      );
      continue;
    }

    if (resuming && response.status !== 206) {
      // The server ignored the Range header, so the body is the whole file.
      chunks = [];
      received = 0;
      resumed = false;
    } else if (resuming) {
      resumed = true;
    }

    if (response.headers.get('accept-ranges') === 'bytes') acceptsRanges = true;

    const declared = response.headers.get('content-length');
    if (declared !== null && Number.isFinite(Number(declared))) {
      contentLength = Number(declared) + (response.status === 206 ? received : 0);
    }
    if (contentLength !== null && contentLength > maxBytes) {
      throw new DownloadError(
        `${entry.url} declares ${contentLength} bytes, over the ${maxBytes} byte limit`,
      );
    }

    try {
      if (response.body) {
        const reader = response.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            received += value.length;
            if (received > maxBytes) {
              await reader.cancel().catch(() => undefined);
              throw new DownloadError(`${entry.url} exceeded the ${maxBytes} byte limit`);
            }
            chunks.push(value);
            onProgress?.({
              received,
              total: contentLength,
              ratio: contentLength === null ? null : Math.min(1, received / contentLength),
              attempt,
            });
          }
        }
      } else {
        const buffer = new Uint8Array(await response.arrayBuffer());
        if (buffer.length > maxBytes) {
          throw new DownloadError(`${entry.url} exceeded the ${maxBytes} byte limit`);
        }
        chunks.push(buffer);
        received += buffer.length;
        onProgress?.({ received, total: contentLength, ratio: 1, attempt });
      }
    } catch (error) {
      if (isAbort(error) || error instanceof DownloadError) throw error;
      // A broken stream is worth resuming; anything else falls through too,
      // but only while attempts remain.
      lastError = error;
      continue;
    }

    const bytes = concatChunks(chunks, received);

    if (entry.size !== undefined && bytes.length !== entry.size) {
      throw new DownloadError(
        `${entry.id} is ${bytes.length} bytes, but the catalog says ${entry.size}`,
      );
    }

    const sha256 = toHex(await digest('SHA-256', bytes));
    if (entry.sha256 !== undefined && sha256 !== entry.sha256.toLowerCase()) {
      // Deliberately no bytes in the error: nothing unverified escapes.
      throw new HashMismatchError(entry.sha256.toLowerCase(), sha256);
    }

    return { bytes, sha256, contentLength, attempts: attempt, resumed };
  }

  throw new DownloadError(
    `${entry.url} failed after ${attempt} attempt(s): ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

export interface VerifiedDownload {
  download: DownloadResult;
  inspection: ApkInspection;
  report: ApkJsonReport;
  /** 'blocked' when the safety report blocks, or a pinned signer did not match. */
  verdict: 'ok' | 'blocked';
  /** Everything that argues against installing, worst-first. */
  reasons: Finding[];
}

export interface DownloadAndInspectOptions extends DownloadOptions {
  /** Injected clock, for reproducible certificate-validity findings. */
  now?: Date;
}

/**
 * Downloads, verifies the pinned hash, inspects, and checks pinned signers.
 *
 * The hash proves you got the file the catalog meant; the inspection and signer
 * pin are what say whether that file should be installed.
 */
export async function downloadAndInspect(
  entry: CatalogEntry,
  options: DownloadAndInspectOptions = {},
): Promise<VerifiedDownload> {
  const download = await downloadApk(entry, options);
  const inspection = await inspectApk(download.bytes, { now: options.now });
  const report = toJsonReport(inspection);

  const reasons: Finding[] = report.safety.findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .map((f) => ({ ...f, evidence: f.evidence ?? undefined }));

  if (entry.signerFingerprints !== undefined && report.package !== null) {
    const pins: SignerPins = { [report.package]: entry.signerFingerprints };
    for (const finding of checkPins([{ sourceId: entry.id, report }], pins)) {
      if (finding.id === 'pin.signer-mismatch') reasons.push(finding);
    }
  }

  if (entry.packageName !== undefined && report.package !== entry.packageName) {
    reasons.push({
      id: 'catalog.package-mismatch',
      severity: 'critical',
      title: 'Downloaded package is not the one the catalog lists',
      detail: `${entry.id} was expected to contain ${entry.packageName}, but the APK declares ${report.package ?? 'no package'}.`,
      evidence: entry.id,
    });
  }

  if (entry.versionCode !== undefined && report.versionCode !== entry.versionCode) {
    reasons.push({
      id: 'catalog.version-mismatch',
      severity: 'high',
      title: 'Downloaded version does not match the catalog',
      detail: `${entry.id} was expected to be versionCode ${entry.versionCode}, but the APK declares ${report.versionCode ?? 'none'}.`,
      evidence: entry.id,
    });
  }

  return {
    download,
    inspection,
    report,
    verdict: reasons.length > 0 ? 'blocked' : 'ok',
    reasons,
  };
}

export interface SideloadQrOptions {
  /** Supply your own encoder; defaults to the built-in one. */
  encoder?: QrEncoder;
  errorCorrectionLevel?: ErrorCorrectionLevel;
  /**
   * Append `#sha256=…` so a companion app can verify what it fetched.
   * Off by default: a bare URL is what a generic camera app handles best, and
   * fragments are never sent to the server anyway.
   */
  includeHash?: boolean;
}

/** Builds the QR a phone scans to fetch the APK directly. */
export function sideloadQr(entry: CatalogEntry, options: SideloadQrOptions = {}): QrCode {
  const { encoder = defaultQrEncoder, errorCorrectionLevel = 'M', includeHash = false } = options;
  const text =
    includeHash && entry.sha256 !== undefined
      ? `${entry.url}#sha256=${entry.sha256.toLowerCase()}`
      : entry.url;
  return encoder.encode(text, { errorCorrectionLevel });
}

/** The text a `sideloadQr` code carries, useful for a "copy link" affordance. */
export function sideloadUrl(entry: CatalogEntry, includeHash = false): string {
  return includeHash && entry.sha256 !== undefined
    ? `${entry.url}#sha256=${entry.sha256.toLowerCase()}`
    : entry.url;
}
