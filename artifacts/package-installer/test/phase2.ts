/**
 * QR encoding and catalog downloads.
 *
 * The QR checks are cross-implementation: matrices are compared module-for-
 * module against the `qrcode` reference encoder, and every code this library
 * produces is decoded back with `jsQR`. Both are devDependencies — nothing is
 * pulled in at runtime.
 */

import QRCode from 'qrcode';
import * as jsqrModule from 'jsqr';

/** jsqr ships CJS with `exports.default`, so the namespace is not callable. */
type JsQrResult = { data: string } | null;
const jsQR = (jsqrModule as unknown as {
  default: (data: Uint8ClampedArray, width: number, height: number) => JsQrResult;
}).default;

/**
 * The reference encoder's typings model byte-mode segment data as binary and
 * mask patterns as a narrow union; both casts are about its types, not values.
 */
const byteSegment = (text: string): QRCode.QRCodeSegment[] =>
  [{ data: new TextEncoder().encode(text), mode: 'byte' }] as unknown as QRCode.QRCodeSegment[];

const maskPattern = (mask: number): QRCode.QRCodeMaskPattern =>
  mask as QRCode.QRCodeMaskPattern;
import { encodeQr, qrPenaltyScore, qrToAscii, qrToImageData, qrToSvg, QrError } from '../src/qr.js';
import {
  downloadApk,
  downloadAndInspect,
  sideloadQr,
  sideloadUrl,
  DownloadError,
  HashMismatchError,
  type CatalogEntry,
  type FetchLike,
} from '../src/download.js';
import { digest, toHex } from '../src/bytes.js';
import { buildApk, buildCertificate } from './fixtures.js';

type Check = (name: string, condition: boolean, detail?: string) => void;
type Equal = <T>(name: string, actual: T, expected: T) => void;

const FIXED_NOW = new Date('2025-06-01T00:00:00Z');

const SAMPLE_TEXTS = [
  'https://cdn.smartrealty.example/apks/com.smartrealty.demo-42.apk',
  'hello world',
  `https://cdn.smartrealty.example/d?pkg=com.smartrealty.demo&vc=42&sig=${'a'.repeat(120)}`,
  'x'.repeat(300),
  'y'.repeat(700),
  'unicode: café ünïcödé 日本語 🏠',
];

const LEVELS = ['L', 'M', 'Q', 'H'] as const;

function testQr(check: Check, equal: Equal): void {
  // --- Matrix equality against the reference encoder -----------------------
  // Byte mode is forced on both sides: this encoder is byte-only by design,
  // while the reference auto-selects numeric/alphanumeric for suitable input.
  let identical = 0;
  let differing = 0;
  for (const text of SAMPLE_TEXTS) {
    for (const ecl of LEVELS) {
      for (const mask of [0, 3, 7]) {
        const reference = QRCode.create(byteSegment(text), {
          errorCorrectionLevel: ecl,
          maskPattern: maskPattern(mask),
        });
        const mine = encodeQr(text, { errorCorrectionLevel: ecl, mask, boostEcc: false });
        const n = reference.modules.size;
        let diff = mine.size === n ? 0 : -1;
        if (diff === 0) {
          for (let y = 0; y < n; y++) {
            for (let x = 0; x < n; x++) {
              if (Boolean(reference.modules.data[y * n + x]) !== mine.modules[y][x]) diff++;
            }
          }
        }
        if (diff === 0) identical++;
        else differing++;
      }
    }
  }
  equal('qr: every forced-mask matrix matches the reference encoder', differing, 0);
  check('qr: cross-check actually ran', identical === SAMPLE_TEXTS.length * 4 * 3);

  // --- Round-trip through a real decoder -----------------------------------
  let decoded = 0;
  const undecodable: string[] = [];
  for (const text of SAMPLE_TEXTS) {
    for (const ecl of LEVELS) {
      const qr = encodeQr(text, { errorCorrectionLevel: ecl });
      const image = qrToImageData(qr, { scale: 4, margin: 4 });
      const result = jsQR(image.data, image.width, image.height);
      if (result?.data === text) decoded++;
      else undecodable.push(`${text.slice(0, 20)} @ ${ecl}`);
    }
  }
  equal('qr: every auto-masked code decodes back to its input', undecodable.length, 0);
  check('qr: decode round-trip ran', decoded === SAMPLE_TEXTS.length * 4);

  // --- Mask selection -------------------------------------------------------
  // Selection is spec-driven and usually agrees with the reference, but the
  // reference's penalty rule 4 is non-standard: it uses |ceil(pct/5) - 10|,
  // which over-penalises any percentage that is not a multiple of five. At
  // 52.15% dark the spec scores 0 (the 50% bracket is zero away) while the
  // reference scores 10. So agreement is asserted as "usually", and
  // correctness is carried by the decode round-trip above.
  let agree = 0;
  let total = 0;
  for (const text of SAMPLE_TEXTS) {
    for (const ecl of LEVELS) {
      total++;
      const reference = QRCode.create(byteSegment(text), {
        errorCorrectionLevel: ecl,
      });
      const mine = encodeQr(text, { errorCorrectionLevel: ecl, boostEcc: false });
      if (reference.maskPattern === mine.mask) agree++;
    }
  }
  check(
    'qr: mask selection agrees with the reference on the large majority',
    agree >= total - 2,
    `${agree}/${total} agreed`,
  );

  // The chosen mask must genuinely be the lowest-penalty one.
  const text = SAMPLE_TEXTS[0];
  const auto = encodeQr(text, { errorCorrectionLevel: 'M', boostEcc: false });
  let best = Infinity;
  let bestMask = -1;
  for (let mask = 0; mask < 8; mask++) {
    const score = qrPenaltyScore(
      encodeQr(text, { errorCorrectionLevel: 'M', mask, boostEcc: false }).modules,
    );
    if (score < best) {
      best = score;
      bestMask = mask;
    }
  }
  equal('qr: auto mask is the lowest-penalty mask', auto.mask, bestMask);

  // --- Structure and options ------------------------------------------------
  const small = encodeQr('A', { errorCorrectionLevel: 'L', boostEcc: false });
  equal('qr: smallest version chosen for a tiny payload', small.version, 1);
  equal('qr: version 1 is 21 modules', small.size, 21);
  check(
    'qr: finder pattern present at the origin',
    small.modules[0][0] && small.modules[0][6] && !small.modules[1][1] && small.modules[2][2],
  );
  check(
    'qr: quiet-zone-independent dark module is set',
    small.modules[small.size - 8][8],
  );

  equal(
    'qr: larger payloads select larger versions',
    encodeQr('z'.repeat(1200), { errorCorrectionLevel: 'L' }).version > 20,
    true,
  );
  check(
    'qr: boostEcc raises the level when there is room',
    encodeQr('A', { errorCorrectionLevel: 'L', boostEcc: true }).errorCorrectionLevel === 'H',
  );
  equal(
    'qr: boostEcc off leaves the level alone',
    encodeQr('A', { errorCorrectionLevel: 'L', boostEcc: false }).errorCorrectionLevel,
    'L',
  );

  let overflowed = false;
  try {
    encodeQr('a'.repeat(3000), { errorCorrectionLevel: 'H', maxVersion: 10 });
  } catch (error) {
    overflowed = error instanceof QrError;
  }
  check('qr: payload that cannot fit is rejected', overflowed);

  let badMask = false;
  try {
    encodeQr('hi', { mask: 9 });
  } catch (error) {
    badMask = error instanceof QrError;
  }
  check('qr: out-of-range mask is rejected', badMask);

  // --- Renderers -------------------------------------------------------------
  const svg = qrToSvg(small, { scale: 3, margin: 4 });
  check('qr: SVG is self-contained', svg.startsWith('<svg') && svg.includes('</svg>'));
  check('qr: SVG carries a viewBox sized with the quiet zone', svg.includes('viewBox="0 0 29 29"'));
  // A CSP-restricted artifact host blocks any outbound request, so the SVG
  // must reference nothing beyond its own path data.
  check('qr: SVG references no external resources', !/href=|<image|url\(/.test(svg));

  const image = qrToImageData(small, { scale: 2, margin: 4 });
  equal('qr: image data dimensions include the margin', image.width, (21 + 8) * 2);
  equal('qr: image data is RGBA', image.data.length, image.width * image.height * 4);

  const ascii = qrToAscii(small, { margin: 2 });
  equal('qr: ascii art has one line per two module rows', ascii.split('\n').length, Math.ceil(25 / 2));
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

/** Builds a fetch that serves fixed bytes, optionally failing part-way once. */
function makeFetch(
  body: Uint8Array,
  options: {
    failAfter?: number;
    acceptRanges?: boolean;
    ignoreRange?: boolean;
    status?: number;
    chunkSize?: number;
  } = {},
): { fetch: FetchLike; calls: { range: string | null }[] } {
  const { failAfter, acceptRanges = true, ignoreRange = false, status = 200, chunkSize = 64 } = options;
  const calls: { range: string | null }[] = [];
  let failuresLeft = failAfter === undefined ? 0 : 1;

  const fetchImpl: FetchLike = async (_url, init) => {
    const rangeHeader = (init?.headers as Record<string, string> | undefined)?.Range ?? null;
    calls.push({ range: rangeHeader });

    if (status >= 400) {
      return new Response(null, { status, statusText: 'Nope' });
    }

    let start = 0;
    let responseStatus = 200;
    if (rangeHeader !== null && !ignoreRange) {
      start = Number(/bytes=(\d+)-/.exec(rangeHeader)?.[1] ?? 0);
      responseStatus = 206;
    }
    const slice = body.subarray(start);

    let sent = 0;
    const shouldFail = failuresLeft > 0 && failAfter !== undefined;
    if (shouldFail) failuresLeft--;

    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (shouldFail && sent >= failAfter!) {
          controller.error(new Error('connection reset'));
          return;
        }
        if (sent >= slice.length) {
          controller.close();
          return;
        }
        const chunk = slice.subarray(sent, Math.min(sent + chunkSize, slice.length));
        sent += chunk.length;
        controller.enqueue(new Uint8Array(chunk));
      },
    });

    const headers: Record<string, string> = { 'content-length': String(slice.length) };
    if (acceptRanges) headers['accept-ranges'] = 'bytes';
    return new Response(stream, { status: responseStatus, headers });
  };

  return { fetch: fetchImpl, calls };
}

async function testDownload(check: Check, equal: Equal): Promise<void> {
  const signer = buildCertificate({
    commonName: 'Smart Realty',
    organization: 'Smart Realty Inc',
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter: new Date('2044-01-01T00:00:00Z'),
  });
  const apk = buildApk({ certificate: signer, debuggable: false, exportedProvider: false, targetSdk: 29 });
  const apkHash = toHex(await digest('SHA-256', apk));

  const entry: CatalogEntry = {
    id: 'com.smartrealty.demo-42',
    url: 'https://cdn.example/demo.apk',
    sha256: apkHash,
    size: apk.length,
  };

  // --- Happy path ------------------------------------------------------------
  const progress: number[] = [];
  const plain = makeFetch(apk);
  const result = await downloadApk(entry, {
    fetch: plain.fetch,
    onProgress: (p) => progress.push(p.received),
  });
  equal('download: byte length', result.bytes.length, apk.length);
  equal('download: hash matches the pin', result.sha256, apkHash);
  equal('download: single attempt', result.attempts, 1);
  equal('download: not resumed', result.resumed, false);
  check('download: progress was reported', progress.length > 1);
  equal('download: progress ends at the full size', progress[progress.length - 1], apk.length);
  check(
    'download: progress is monotonic',
    progress.every((v, i) => i === 0 || v >= progress[i - 1]),
  );

  // --- Hash pinning ----------------------------------------------------------
  let mismatch: unknown = null;
  try {
    await downloadApk({ ...entry, sha256: '00'.repeat(32) }, { fetch: makeFetch(apk).fetch });
  } catch (error) {
    mismatch = error;
  }
  check('download: hash mismatch is rejected', mismatch instanceof HashMismatchError);
  check(
    'download: mismatch error names both hashes',
    mismatch instanceof HashMismatchError &&
      mismatch.actual === apkHash &&
      mismatch.expected === '00'.repeat(32),
  );
  check(
    'download: no bytes are exposed on mismatch',
    mismatch instanceof HashMismatchError && !('bytes' in mismatch),
  );

  check(
    'download: uppercase pinned hashes are accepted',
    (await downloadApk({ ...entry, sha256: apkHash.toUpperCase() }, { fetch: makeFetch(apk).fetch }))
      .sha256 === apkHash,
  );

  // --- Size and limits -------------------------------------------------------
  let sizeRejected = false;
  try {
    await downloadApk({ ...entry, size: apk.length + 10 }, { fetch: makeFetch(apk).fetch });
  } catch (error) {
    sizeRejected = error instanceof DownloadError;
  }
  check('download: declared size mismatch is rejected', sizeRejected);

  let tooBig = false;
  try {
    await downloadApk(entry, { fetch: makeFetch(apk).fetch, maxBytes: 100 });
  } catch (error) {
    tooBig = error instanceof DownloadError;
  }
  check('download: maxBytes is enforced', tooBig);

  // --- Resume ----------------------------------------------------------------
  const flaky = makeFetch(apk, { failAfter: 256, acceptRanges: true });
  const resumedResult = await downloadApk(entry, { fetch: flaky.fetch, retries: 3 });
  equal('download: resumed transfer still verifies', resumedResult.sha256, apkHash);
  equal('download: resume took a second attempt', resumedResult.attempts, 2);
  equal('download: resume flag set', resumedResult.resumed, true);
  check(
    'download: the retry sent a Range header',
    flaky.calls.length === 2 && flaky.calls[1].range?.startsWith('bytes=') === true,
  );

  // A server that ignores Range must not have two responses spliced together.
  const ignoring = makeFetch(apk, { failAfter: 256, acceptRanges: true, ignoreRange: true });
  const restarted = await downloadApk(entry, { fetch: ignoring.fetch, retries: 3 });
  equal('download: ignored Range restarts cleanly', restarted.sha256, apkHash);
  equal('download: restart is not reported as resumed', restarted.resumed, false);

  // --- Failures --------------------------------------------------------------
  const notFoundFetch = makeFetch(apk, { status: 404 });
  let notFound: unknown = null;
  try {
    await downloadApk(entry, { fetch: notFoundFetch.fetch, retries: 3 });
  } catch (error) {
    notFound = error;
  }
  check('download: 404 is surfaced', notFound instanceof DownloadError);
  equal('download: 404 status is carried', (notFound as DownloadError).status, 404);
  // A 4xx describes the request, so retrying it only wastes the user's data.
  equal('download: 404 is not retried', notFoundFetch.calls.length, 1);

  const serverErrorFetch = makeFetch(apk, { status: 503 });
  let serverError = false;
  try {
    await downloadApk(entry, { fetch: serverErrorFetch.fetch, retries: 2 });
  } catch (error) {
    serverError = error instanceof DownloadError;
  }
  check('download: 5xx is surfaced after retries', serverError);
  equal('download: 5xx is retried', serverErrorFetch.calls.length, 3);

  let noFetch = false;
  try {
    await downloadApk(entry, { fetch: undefined as unknown as FetchLike });
  } catch (error) {
    noFetch = error instanceof DownloadError;
  }
  check('download: missing fetch implementation is reported', noFetch);

  // --- downloadAndInspect ----------------------------------------------------
  const clean = await downloadAndInspect(
    { ...entry, packageName: 'com.smartrealty.demo', versionCode: 42 },
    { fetch: makeFetch(apk).fetch, now: FIXED_NOW },
  );
  equal('verify: clean package passes', clean.verdict, 'ok');
  equal('verify: report carries the package', clean.report.package, 'com.smartrealty.demo');
  equal('verify: no blocking reasons', clean.reasons.length, 0);

  const hostileApk = buildApk({
    certificate: signer,
    extraEntries: [
      { name: '../../../etc/cron.d/backdoor', data: new TextEncoder().encode('* * * * * root sh') },
    ],
  });
  const hostileEntry: CatalogEntry = {
    id: 'hostile',
    url: 'https://cdn.example/hostile.apk',
    sha256: toHex(await digest('SHA-256', hostileApk)),
  };
  const hostile = await downloadAndInspect(hostileEntry, {
    fetch: makeFetch(hostileApk).fetch,
    now: FIXED_NOW,
  });
  equal('verify: hostile package is blocked', hostile.verdict, 'blocked');
  check(
    'verify: traversal is among the reasons',
    hostile.reasons.some((r) => r.id === 'zip.unsafe-path'),
  );

  const wrongSigner = buildCertificate({
    commonName: 'Someone Else',
    organization: 'Other Ltd',
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter: new Date('2044-01-01T00:00:00Z'),
  });
  const otherApk = buildApk({ certificate: wrongSigner, debuggable: false, exportedProvider: false, targetSdk: 29 });
  const pinnedEntry: CatalogEntry = {
    id: 'pinned',
    url: 'https://cdn.example/pinned.apk',
    sha256: toHex(await digest('SHA-256', otherApk)),
    signerFingerprints: [clean.report.certificates[0].sha256],
  };
  const wrongKey = await downloadAndInspect(pinnedEntry, {
    fetch: makeFetch(otherApk).fetch,
    now: FIXED_NOW,
  });
  equal('verify: unpinned signer blocks the install', wrongKey.verdict, 'blocked');
  check(
    'verify: signer mismatch is the reason',
    wrongKey.reasons.some((r) => r.id === 'pin.signer-mismatch'),
  );

  const wrongPackage = await downloadAndInspect(
    { ...entry, packageName: 'com.example.somethingelse' },
    { fetch: makeFetch(apk).fetch, now: FIXED_NOW },
  );
  equal('verify: package-name mismatch blocks', wrongPackage.verdict, 'blocked');
  check(
    'verify: package mismatch is explained',
    wrongPackage.reasons.some((r) => r.id === 'catalog.package-mismatch'),
  );

  const wrongVersion = await downloadAndInspect(
    { ...entry, versionCode: 999 },
    { fetch: makeFetch(apk).fetch, now: FIXED_NOW },
  );
  equal('verify: version mismatch blocks', wrongVersion.verdict, 'blocked');

  // --- Sideload QR -----------------------------------------------------------
  const qr = sideloadQr(entry);
  const image = qrToImageData(qr, { scale: 4, margin: 4 });
  const scanned = jsQR(image.data, image.width, image.height);
  equal('sideload: QR decodes to the download URL', scanned?.data, entry.url);
  equal('sideload: url helper matches', sideloadUrl(entry), entry.url);

  const withHash = sideloadQr(entry, { includeHash: true });
  const hashImage = qrToImageData(withHash, { scale: 4, margin: 4 });
  equal(
    'sideload: hash fragment is carried when asked',
    jsQR(hashImage.data, hashImage.width, hashImage.height)?.data,
    `${entry.url}#sha256=${apkHash}`,
  );

  let usedCustomEncoder = false;
  sideloadQr(entry, {
    encoder: {
      encode: (text, options) => {
        usedCustomEncoder = true;
        return encodeQr(text, options);
      },
    },
  });
  check('sideload: a custom encoder can be substituted', usedCustomEncoder);
}

export async function testPhase2(check: Check, equal: Equal): Promise<void> {
  testQr(check, equal);
  await testDownload(check, equal);
}
