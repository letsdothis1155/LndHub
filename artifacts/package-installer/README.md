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

For a catalog entry or a downloadable report, `toJsonReport(result)` returns a
plain JSON-safe object.

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
| `safety.ts` | — | Findings and score |

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
npm test              # 110 assertions, no external tools needed
```

`test/fixtures.ts` builds APKs byte-for-byte to the platform formats — binary
XML, `resources.arsc`, DER certificates, PKCS#7, ZIP — so the parsers are
exercised against real structures. Deflated entries go through Node's `zlib`,
so `inflate.ts` decompresses data it did not produce.

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
  them in production — that is the one gap I would close first.
- **v4 signatures** (`.apk.idsig`, a sidecar file) are not read.
- **APK Signing Block digests** are located and their algorithms named, but the
  content digests are not recomputed.
- **DEX bytecode is not analysed.** Native libraries under `lib/` are reported
  as present and nothing more.
- **Everything is held in memory.** For multi-hundred-megabyte APKs, stream or
  inspect off the main thread.
