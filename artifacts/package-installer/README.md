# APK inspection for the Package Installer

Dependency-free TypeScript that reads an APK's **binary manifest** and **signing
certificates** directly, then turns what it finds into ranked safety findings.

This is the Safe Extract upgrade: instead of scanning an archive for
recognizable strings, it parses the actual platform formats, so
`android:debuggable`, `android:exported`, the requested permissions and the
signer's certificate are read as the installer itself would read them.

Runs unchanged in a browser (main thread or worker) and in Node ≥ 18. No
runtime dependencies — only `crypto.subtle`, which both provide.

---

## Dropping it in

Copy `src/` into the App Builder project (e.g. `src/lib/apk/`). Imports use
explicit `.js` extensions, so it works under bundlers and native ESM alike. If
the project's `tsconfig.json` uses `"moduleResolution": "bundler"`, the
extensions are still fine.

```ts
import { inspectApk, toJsonReport } from './lib/apk/index.js';

const bytes = new Uint8Array(await file.arrayBuffer());
const result = await inspectApk(bytes);

result.manifest?.package;            // "com.smartrealty.demo"
result.manifest?.versionName;        // "1.4.2"
result.manifest?.application.label;  // resolved through resources.arsc
result.sha256;                       // pin this in the catalog
result.report.blockInstall;          // true when anything critical/high fired
result.report.findings;              // sorted worst-first
```

For a catalog entry or a downloadable report, `toJsonReport(result)` returns an
`ApkJsonReport` — a plain, typed, JSON-safe object holding no reference to the
archive bytes.

Large APKs should be inspected off the main thread:

```ts
// worker.ts
self.onmessage = async (event: MessageEvent<ArrayBuffer>) => {
  const { toJsonReport, inspectApk } = await import('./lib/apk/index.js');
  self.postMessage(toJsonReport(await inspectApk(new Uint8Array(event.data))));
};
```

`inspectApk` throws only when the bytes are not a readable archive at all. A
missing or corrupt manifest is reported through `manifestError` plus a finding,
so a hostile package still produces a report rather than an exception.

---

## Scanning many packages

One APK at a time answers "is this safe to install". A catalog needs the
comparative questions too: did the signing key change between versions, did the
update quietly add SMS access, do two entries claim the same identity with
different bytes. `scanBatch` + `analyzeBatch` answer those.

```ts
import { scanBatch, buildBatchReport, sourceFromFile } from './lib/apk/index.js';

const results = await scanBatch([...files].map(sourceFromFile), {
  concurrency: 4,
  onProgress: ({ completed, total }) => setProgress(completed / total),
  signal: controller.signal,
});

const report = buildBatchReport(results, { pins });
report.totals;     // scanned / ok / failed / blocked / clean
report.packages;   // grouped by package, versions ordered by versionCode
report.findings;   // cross-version, cross-package and pinning findings
```

A source is anything that can produce bytes on demand:

```ts
interface ApkSource {
  id: string;                    // filename, catalog id, URL — used in the report
  size?: number;
  load(): Promise<Uint8Array>;
}
```

`sourceFromFile`, `sourceFromBytes`, and (Node only) `fromPath` / `fromDirectory`
/ `fromPaths` cover the usual cases.

**Memory.** `ApkInspection` holds the entire APK via `archive.bytes`. Keeping an
array of them would pin every package in memory at once, so `scanBatch` projects
each result to `ApkJsonReport` and drops the bytes. Pass
`keepInspections: true` only for small batches where you need the archive back.

**Parallelism, honestly.** Parsing is CPU-bound and synchronous — inflate in
particular — so `concurrency` mostly overlaps `load()` I/O with parsing rather
than decoding in parallel. Real parallelism needs Workers; supply your own
Worker-backed function via the `inspect` option. This library deliberately ships
no bundler-specific worker file.

**Failure isolation.** A corrupt or non-archive input becomes
`{ status: 'failed', error }` and the batch continues — one bad package in a
catalog never costs you the rest. Results come back in input order regardless of
completion order.

**Cancellation.** Pass an `AbortSignal`. In-flight items finish, the remainder
are never started, and `scanBatch` rejects with a `BatchAbortError`
(`name === 'AbortError'`) carrying `partialResults`.

### Pinning signing keys

Signatures are parsed, not verified (see Limitations), so the guarantee worth
having is *"this is the same key that signed the build I already trusted"*:

```ts
import { checkPins } from './lib/apk/index.js';

const pins = { 'com.smartrealty.demo': ['63a9640e5114c92e…'] };
checkPins(entries, pins);   // critical finding when a package is signed by another key
```

Fingerprints may be bare lowercase hex or colon-separated uppercase — the form
`keytool` prints. A package with no pin entry produces an `info` finding, so
gaps in the pin file are visible rather than silent.

### Batch findings

Same `Finding` shape as the per-APK rules, so the same UI renders both.

- `diff.signer-changed` — **high** when the key sets are disjoint, **medium**
  when they overlap. Android rejects such an update unless the new key carries a
  valid v3 rotation lineage; this tool does not parse or verify that lineage, and
  the finding text says so.
- `diff.permissions-added` / `diff.permissions-removed` — severity lifted when
  an added permission is sensitive, reusing the same descriptions as the
  single-APK rules.
- `diff.target-sdk-decreased`, `diff.min-sdk-decreased`,
  `diff.debuggable-introduced`, `diff.cleartext-introduced`,
  `diff.exported-components-added`.
- `batch.identity-collision` — **critical**; same package and versionCode, two
  different file hashes.
- `batch.shared-signer` — **info**; distinct packages signed by one key, useful
  for grouping a catalog by publisher.
- `pin.signer-mismatch` — **critical**. `pin.unpinned` — **info**.

### Reports are reproducible

`buildBatchReport` output is byte-identical across runs given the same inputs and
`generatedAt`, so reports can be committed and diffed. Wall-clock durations are
excluded unless you ask for them with `includeTimings: true`. `toCsv(report)`
gives one row per APK for spreadsheet triage.

---

## Command line

```bash
npm run build
node dist/src/node/cli.js ./apks --out reports/ --pins pins.json --fail-on high
```

Paths may be APK files or directories (searched recursively). Exits **1** when a
finding at or above `--fail-on` fires and **2** on a usage error, so it works as
a CI gate for the catalog.

| Flag | Meaning |
| --- | --- |
| `--out <dir>` | Write `batch.json`/`batch.csv` plus one report per APK |
| `--pins <file>` | JSON map of package name → `[expected signer SHA-256]` |
| `--concurrency <n>` | Sources scanned at once (default 4) |
| `--format json\|csv` | Batch report format (default json) |
| `--fail-on <severity>` | `critical\|high\|medium\|low\|info\|none` (default none) |
| `--generated-at <iso>` | Fixed timestamp, for reproducible output |
| `--timings` | Include per-source durations (breaks reproducibility) |
| `--quiet` | Suppress progress output |

Node-only helpers live behind the `./node` subpath so a browser bundle never
pulls `node:fs`:

```ts
import { fromDirectory } from '@smart-realty/apk-inspect/node';
```

---

## Downloading and sideloading

`downloadApk` is transport-agnostic — `fetch` is injected, so it works against
whatever the catalog is served from without this module knowing anything about
the hosting.

```ts
import { downloadAndInspect, sideloadQr, qrToSvg } from './lib/apk/index.js';

const entry = {
  id: 'com.smartrealty.demo-42',
  url: 'https://cdn.example/demo.apk',
  sha256: '…',                       // pinned file hash
  packageName: 'com.smartrealty.demo',
  versionCode: 42,
  signerFingerprints: ['…'],          // pinned signing key
};

const { verdict, reasons, report } = await downloadAndInspect(entry, {
  onProgress: ({ ratio }) => setBar(ratio),
  signal: controller.signal,
});

if (verdict === 'blocked') showReasons(reasons);
```

**Nothing unverified escapes.** If the bytes do not match the pinned `sha256`,
`downloadApk` throws `HashMismatchError` and returns no bytes at all — there is
no path where unverified content reaches an installer because a caller forgot to
check a flag. The hash proves you got the file the catalog meant; the inspection
and the signer pin are what decide whether it should be installed.

`downloadAndInspect` blocks on any critical or high finding, a signer outside
`signerFingerprints`, or a package name / versionCode that disagrees with the
catalog (`catalog.package-mismatch`, `catalog.version-mismatch`).

**Resume.** A stream that breaks part-way is retried with a `Range` request when
the server advertised `Accept-Ranges: bytes`. If the server ignores the range and
replies `200`, the partial buffer is discarded and the download restarts rather
than splicing two different responses together. 4xx responses are not retried —
they describe the request, and retrying only wastes the user's data.

### QR sideload

```ts
const qr = sideloadQr(entry);          // encodes entry.url
element.innerHTML = qrToSvg(qr, { scale: 6 });
```

The encoder is built in — dependency-free, byte mode, versions 1-40, all four
error-correction levels — because a sideload QR that needs an external library
would undercut the rest of the package. `qrToSvg`, `qrToImageData` (canvas) and
`qrToAscii` (terminal) render it; `sideloadQr(entry, { encoder })` accepts your
own `QrEncoder` if you already have one.

`{ includeHash: true }` appends `#sha256=…` so a companion app can verify what it
fetched. It is off by default: a bare URL is what a generic camera app handles
best, and fragments are never sent to the server anyway.

---

## What it parses

| Module | Format | Notes |
| --- | --- | --- |
| `zip.ts` | ZIP / ZIP64 central directory | Central-directory driven; local headers are treated as untrusted |
| `inflate.ts` | raw DEFLATE (RFC 1951) | Synchronous, so Safe Extract needs no async fallback |
| `axml.ts` | Android binary XML | String pool (UTF-8 and UTF-16), resource map, typed values |
| `arsc.ts` | `resources.arsc` | Enough to resolve `@0x7f……` references to strings |
| `manifest.ts` | AndroidManifest model | Components, permissions, effective `exported` |
| `asn1.ts` | DER | Rejects BER indefinite-length encodings |
| `x509.ts` | X.509 | Subject/issuer, validity, key size, signature algorithm, fingerprints |
| `signing.ts` | v1 (PKCS#7) + v2/v3/v3.1 signing block | Detects which schemes are present, and every signer's certificate |
| `safety.ts` | — | Per-APK findings and score |
| `batch.ts` | — | Concurrency-bounded scanning with failure isolation |
| `diff.ts` | — | Cross-version and cross-package comparison, signer pinning |
| `report.ts` | — | Reproducible batch report, CSV export, threshold checks |
| `qr.ts` | QR Code (ISO/IEC 18004) | Byte mode, versions 1-40, L/M/Q/H; SVG, canvas and terminal renderers |
| `download.ts` | — | Injected-`fetch` downloads with hash pinning, resume, and an inspection gate |

### Attribute lookup

Attribute values are found by android-namespace name first and by **resource
id** second. Release builds normally keep framework attribute names in the
string pool, but some obfuscators blank them; the resource map survives that
because the platform needs it. The id table in `manifest.ts` covers the
attributes these rules depend on and is best-effort by design — an unknown id
falls back to the pool name rather than guessing.

---

## Findings

Each finding carries `id`, `severity`, `title`, `detail` and usually
`evidence`. `report.score` starts at 100 and subtracts a weight per finding;
`report.blockInstall` is true when anything `critical` or `high` fired.

**Archive integrity**
- `zip.unsafe-path` (critical) — an entry name that would escape the extraction
  directory: `..` segments, absolute paths, drive letters, backslashes, control
  characters, or a name that is not valid UTF-8.
- `zip.duplicate-entry` (high) — the same name twice, so different readers can
  pick different copies.
- `zip.compression-bomb` (high) — an entry over 1 MiB expanding at more than
  200:1.

**Signing**
- `sig.unsigned` (critical) — no v1, v2 or v3 signature.
- `sig.v1-only` (high when `targetSdk ≥ 30`, else medium) — Android 11+ refuses
  to install a v1-only package at that target, and v1 leaves the archive
  structure itself unsigned.
- `sig.v1-uncovered-entries` (high) — files absent from `META-INF/MANIFEST.MF`,
  i.e. added after signing.
- `cert.debug-key` (high) — signed with the SDK's debug keystore, whose private
  key is public.
- `cert.weak-hash` (high) — MD5/SHA-1 certificate signature.
- `cert.weak-key` (high/medium) — RSA or DSA key under 2048 bits.
- `cert.expired` / `cert.not-yet-valid` (medium).

**Manifest**
- `manifest.debuggable` (high), `manifest.exported-provider` (high),
  `manifest.exported-unprotected` (medium), `manifest.cleartext-traffic`
  (medium), `manifest.shared-user-id` (medium), `manifest.test-only` (medium),
  `manifest.old-target-sdk` (high under API 23, else medium),
  `manifest.allow-backup` (low).
- `permission.*` — sensitive permissions grouped and explained in plain
  language; SMS, accessibility, device-admin, overlay and installer access are
  medium, the rest low.

A finding is an observation, not a verdict. Plenty of legitimate apps request
camera access or export a provider; the score is for ordering a catalog and
drawing attention, not for deciding intent.

---

## Tests

```bash
npm install
npm test              # 236 assertions, no external tools needed
```

`test/fixtures.ts` builds APKs byte-for-byte to the platform formats — binary
XML, `resources.arsc`, DER certificates, PKCS#7, ZIP — so the parsers are
exercised against real structures. Deflated entries go through Node's `zlib`,
so `inflate.ts` decompresses data it did not produce. `manifestSpec()` and
`buildApk()` are parameterized, so the batch tests compare genuinely different
packages, versions and signers rather than mock objects.

The QR encoder is cross-checked against two independent implementations, both
devDependencies: every matrix is compared module-for-module against the `qrcode`
reference encoder with the mask forced on both sides (72 comparisons, all
identical), and every code this library produces is decoded back with `jsQR`
(24 round-trips, all recovering the exact input). Downloads are tested against a
fake `fetch` built on real `Response` and `ReadableStream` objects, covering
progress, resume after a mid-stream failure, a server that ignores `Range`,
size and `maxBytes` limits, and retry behaviour by status class.

```bash
npm run fixtures      # needs openssl, keytool, jarsigner, zip
npm run test:integration
```

The integration suite cross-checks against independent implementations: RSA and
EC certificates from **openssl**, a PKCS#7 bundle from `openssl crl2pkcs7`, and
a JAR signed by **jarsigner**. Subjects (RFC 2253), serials, validity dates,
key sizes and SHA-256 fingerprints are compared against what `openssl x509` and
`keytool` report — 35 assertions, all passing. It skips cleanly when `test/real/`
is absent, so `npm test` still runs without a JDK.

---

## Limitations

Worth knowing before this gates an install:

- **Signatures are read, not verified.** The certificate chain, the v2/v3
  digests and the JAR digests are parsed and described, but no signature is
  checked. Verifying a self-signed APK certificate against itself proves only
  internal consistency, which is not something an installer should act on. What
  *is* actionable — and what this gives you — is pinning
  `signers[].certificates[].fingerprintSha256` for an app you already trust and
  refusing updates signed by a different key.
- **AXML and ARSC are validated against spec-built fixtures, not aapt2.** The
  certificate and ZIP paths are cross-checked against openssl/keytool/jarsigner
  output; no Android build tools were available here, so the binary XML and
  resource-table readers were tested against fixtures written to the documented
  format. Run them over a handful of real APKs from the catalog before trusting
  them in production — that is the one gap I would close first, and the CLI now
  makes it a one-command exercise:
  `node dist/src/node/cli.js ./real-apks --out reports/`.
- **v4 signatures** (`.apk.idsig`, a sidecar file) are not read.
- **APK Signing Block digests** are located and their algorithms named, but the
  content digests are not recomputed.
- **DEX bytecode is not analysed.** Native libraries under `lib/` are reported
  as present and nothing more.
- **One APK is held in memory at a time.** A batch releases each package's bytes
  after projecting it to JSON, but a single multi-hundred-megabyte APK is still
  fully buffered — inspect those off the main thread.
- **Version diffing assumes `versionCode` ordering.** Packages are compared in
  `versionCode` order; a catalog that reuses or rewinds version codes will diff
  in an order that does not match its release history.
- **The QR encoder is byte mode only.** That is the right mode for URLs, but a
  payload that is entirely numeric or entirely uppercase-alphanumeric will
  produce a slightly larger code than an encoder that switches modes. Mask
  selection follows the spec's four penalty rules, which occasionally picks a
  different mask from the `qrcode` npm package — that library's rule 4 uses
  `|ceil(pct/5) - 10|`, over-penalising percentages that are not multiples of
  five. Both produce valid codes; every code here is decode-tested.
- **Downloads buffer the whole file.** Progress is streamed, but the bytes are
  collected before hashing and inspection, because `crypto.subtle.digest` cannot
  hash incrementally and inspection needs the full archive anyway.
