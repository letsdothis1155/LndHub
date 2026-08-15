/**
 * Test suite. Run with `npm test`.
 *
 * The fixtures are real binary structures, so a passing run means the parsers
 * agree with the platform formats — not merely with each other.
 */

import { deflateRawSync } from 'node:zlib';
import { inflateRaw } from '../src/inflate.js';
import { ZipArchive, checkEntryPath, crc32 } from '../src/zip.js';
import { parseAxml } from '../src/axml.js';
import { ResourceTable } from '../src/arsc.js';
import { parseAndroidManifest } from '../src/manifest.js';
import { parseDer, Asn1Error } from '../src/asn1.js';
import { parseCertificate, formatFingerprint } from '../src/x509.js';
import { extractPkcs7Certificates } from '../src/signing.js';
import { inspectApk, toJsonReport } from '../src/inspect.js';
import {
  buildArsc,
  buildAxml,
  buildApk,
  buildCertificate,
  buildPkcs7,
  manifestSpec,
  buildZip,
} from './fixtures.js';
import { testBatch } from './batch.js';
import { testPhase2 } from './phase2.js';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed++;
  } else {
    failed++;
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function equal<T>(name: string, actual: T, expected: T): void {
  check(name, Object.is(actual, expected), `expected ${String(expected)}, got ${String(actual)}`);
}

// ---------------------------------------------------------------------------
// inflate
// ---------------------------------------------------------------------------

function testInflate(): void {
  const cases: [string, Uint8Array][] = [
    ['empty', new Uint8Array(0)],
    ['single byte', new Uint8Array([0x41])],
    ['highly repetitive', new TextEncoder().encode('smart realty '.repeat(4000))],
    [
      'incompressible',
      Uint8Array.from({ length: 40000 }, (_, i) => (i * 2654435761) % 256),
    ],
    [
      'mixed',
      new TextEncoder().encode(
        JSON.stringify({ listings: Array.from({ length: 500 }, (_, i) => ({ id: i, city: 'Austin' })) }),
      ),
    ],
  ];

  for (const [name, original] of cases) {
    for (const level of [1, 6, 9]) {
      const compressed = new Uint8Array(deflateRawSync(original, { level }));
      const result = inflateRaw(compressed, original.length);
      check(
        `inflate: ${name} at level ${level}`,
        result.length === original.length && result.every((b, i) => b === original[i]),
        `${result.length} bytes back from ${original.length}`,
      );
    }
  }

  // Stored blocks: zlib emits these at level 0.
  const storedInput = new TextEncoder().encode('x'.repeat(1000));
  const stored = new Uint8Array(deflateRawSync(storedInput, { level: 0 }));
  const storedOut = inflateRaw(stored);
  check(
    'inflate: stored blocks',
    storedOut.length === storedInput.length && storedOut.every((b, i) => b === storedInput[i]),
  );

  let threw = false;
  try {
    inflateRaw(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
  } catch {
    threw = true;
  }
  check('inflate: rejects garbage', threw);
}

// ---------------------------------------------------------------------------
// zip
// ---------------------------------------------------------------------------

function testZip(): void {
  const payload = new TextEncoder().encode('listing data '.repeat(500));
  const zip = buildZip([
    { name: 'a.txt', data: payload },
    { name: 'raw.bin', data: new Uint8Array([1, 2, 3, 4]), store: true },
  ]);
  const archive = ZipArchive.parse(zip);
  equal('zip: entry count', archive.entries.length, 2);
  const read = archive.readByName('a.txt');
  check('zip: deflated round-trip', read !== null && read.length === payload.length);
  const raw = archive.readByName('raw.bin');
  check('zip: stored entry', raw !== null && raw.length === 4 && raw[3] === 4);

  // CRC verification must actually reject a flipped byte.
  const tampered = Uint8Array.from(zip);
  const entry = archive.get('raw.bin')!;
  const dataOffset = entry.localHeaderOffset + 30 + 'raw.bin'.length;
  tampered[dataOffset] ^= 0xff;
  let crcRejected = false;
  try {
    ZipArchive.parse(tampered).readByName('raw.bin');
  } catch {
    crcRejected = true;
  }
  check('zip: CRC mismatch is rejected', crcRejected);

  equal('zip: crc32 of "123456789"', crc32(new TextEncoder().encode('123456789')), 0xcbf43926);

  check('path: plain name is safe', checkEntryPath('res/layout/main.xml') === null);
  check('path: traversal is caught', checkEntryPath('../../etc/passwd')?.reason.includes('..') === true);
  check('path: absolute is caught', checkEntryPath('/etc/passwd') !== null);
  check('path: backslash is caught', checkEntryPath('res\\evil.xml') !== null);
  check('path: nested traversal is caught', checkEntryPath('lib/../../evil.so') !== null);
  check('path: dotted filename is allowed', checkEntryPath('lib/x86_64/lib..so') === null);
}

// ---------------------------------------------------------------------------
// binary XML + resources
// ---------------------------------------------------------------------------

function testAxmlAndResources(): void {
  const axml = buildAxml(manifestSpec());
  const root = parseAxml(axml);
  equal('axml: root element', root.name, 'manifest');
  equal('axml: child count', root.children.length, 4);
  equal('axml: nested depth', root.children[3].children[0].children[0].children.length, 2);

  const resources = ResourceTable.parse(buildArsc('Smart Realty Demo'));
  equal('arsc: label resolves', resources.resolveString(0x7f010000), 'Smart Realty Demo');
  equal('arsc: unknown id resolves to null', resources.resolveString(0x7f020099), null);

  const manifest = parseAndroidManifest(axml, { resources });
  equal('manifest: package', manifest.package, 'com.smartrealty.demo');
  equal('manifest: versionCode', manifest.versionCode, 42);
  equal('manifest: versionName', manifest.versionName, '1.4.2');
  equal('manifest: minSdkVersion', manifest.minSdkVersion, 24);
  equal('manifest: targetSdkVersion', manifest.targetSdkVersion, 34);
  equal('manifest: label from resources', manifest.application.label, 'Smart Realty Demo');
  equal('manifest: debuggable', manifest.application.debuggable, true);
  equal('manifest: allowBackup honours explicit false', manifest.application.allowBackup, false);
  equal('manifest: permission count', manifest.usesPermissions.length, 2);
  check(
    'manifest: permissions read correctly',
    manifest.usesPermissions.some((p) => p.name === 'android.permission.READ_SMS'),
  );

  const activity = manifest.components.find((c) => c.kind === 'activity');
  check('manifest: activity found', activity?.name === '.MainActivity');
  equal('manifest: intent filter count', activity?.intentFilters.length ?? 0, 1);
  equal('manifest: launcher action', activity?.intentFilters[0].actions[0], 'android.intent.action.MAIN');
  equal(
    'manifest: activity exported by intent filter',
    activity?.effectiveExported,
    true,
  );
  equal('manifest: activity exported not declared', activity?.declaredExported, null);

  const provider = manifest.components.find((c) => c.kind === 'provider');
  equal('manifest: provider exported', provider?.effectiveExported, true);
  equal('manifest: provider authority', provider?.authorities[0], 'com.smartrealty.demo.provider');

  // Without a resource table the label stays a readable reference rather than throwing.
  const noResources = parseAndroidManifest(axml);
  equal('manifest: label without resources', noResources.application.label, '@0x7f010000');
}

// ---------------------------------------------------------------------------
// ASN.1 / X.509 / PKCS#7
// ---------------------------------------------------------------------------

async function testCertificates(): Promise<void> {
  const notBefore = new Date('2024-01-01T00:00:00Z');
  const notAfter = new Date('2044-01-01T00:00:00Z');
  const der = buildCertificate({
    commonName: 'Smart Realty',
    organization: 'Smart Realty Inc',
    notBefore,
    notAfter,
  });

  const cert = await parseCertificate(der);
  equal('x509: version', cert.version, 3);
  equal('x509: subject CN', cert.subjectAttributes.CN, 'Smart Realty');
  equal('x509: subject text', cert.subject, 'O=Smart Realty Inc, CN=Smart Realty');
  equal('x509: self-signed', cert.selfSigned, true);
  equal('x509: serial', cert.serialNumberHex, '04D2');
  equal('x509: signature algorithm', cert.signatureAlgorithm.name, 'sha256WithRSAEncryption');
  equal('x509: weak hash flag', cert.signatureAlgorithm.weakHash, false);
  equal('x509: key algorithm', cert.publicKey.algorithm, 'RSA');
  equal('x509: key size', cert.publicKey.keySizeBits, 2048);
  equal('x509: notBefore', cert.notBefore?.toISOString(), notBefore.toISOString());
  equal('x509: notAfter', cert.notAfter?.toISOString(), notAfter.toISOString());
  equal('x509: fingerprint length', cert.fingerprintSha256.length, 64);
  equal('x509: fingerprint formatting', formatFingerprint('ab12').length, 5);

  const weak = await parseCertificate(
    buildCertificate({
      commonName: 'Android Debug',
      organization: 'Android',
      notBefore,
      notAfter,
      modulusLength: 1024,
      weakSignatureAlgorithm: true,
    }),
  );
  equal('x509: weak key size', weak.publicKey.keySizeBits, 1024);
  equal('x509: sha1 flagged weak', weak.signatureAlgorithm.weakHash, true);

  const certificates = extractPkcs7Certificates(buildPkcs7([der]));
  equal('pkcs7: certificate extracted', certificates.length, 1);
  check(
    'pkcs7: certificate bytes match',
    certificates[0].length === der.length && certificates[0].every((b, i) => b === der[i]),
  );

  let rejected = false;
  try {
    // 0x80 length octet is BER's indefinite form and invalid in DER.
    parseDer(new Uint8Array([0x30, 0x80, 0x00, 0x00]));
  } catch (error) {
    rejected = error instanceof Asn1Error;
  }
  check('asn1: indefinite length rejected', rejected);

  let truncated = false;
  try {
    parseDer(new Uint8Array([0x30, 0x20, 0x01]));
  } catch (error) {
    truncated = error instanceof Asn1Error;
  }
  check('asn1: truncated TLV rejected', truncated);
}

// ---------------------------------------------------------------------------
// end-to-end inspection
// ---------------------------------------------------------------------------

async function testInspectHappyPath(): Promise<void> {
  const apk = buildApk();
  const result = await inspectApk(apk, { now: new Date('2025-06-01T00:00:00Z') });

  equal('inspect: package', result.manifest?.package, 'com.smartrealty.demo');
  equal('inspect: label', result.manifest?.application.label, 'Smart Realty Demo');
  equal('inspect: manifest parsed cleanly', result.manifestError, null);
  equal('inspect: sha256 length', result.sha256.length, 64);
  equal('inspect: size', result.size, apk.length);
  equal('inspect: v1 signature detected', result.signatures.v1, true);
  equal('inspect: v2 absent', result.signatures.v2, false);
  equal('inspect: signer count', result.signatures.signers.length, 1);
  equal(
    'inspect: signer certificate subject',
    result.signatures.signers[0].certificates[0].subject,
    'O=Smart Realty Inc, CN=Smart Realty',
  );
  equal('inspect: dex discovered', result.files.dexFiles[0], 'classes.dex');
  equal('inspect: abi discovered', result.files.nativeAbis[0], 'arm64-v8a');

  const ids = new Set(result.report.findings.map((f) => f.id));
  check('report: flags debuggable', ids.has('manifest.debuggable'));
  check('report: flags exported provider', ids.has('manifest.exported-provider'));
  check('report: flags v1-only signing', ids.has('sig.v1-only'));
  check('report: flags SMS permission', ids.has('permission.sms'));
  check('report: no allowBackup finding when disabled', !ids.has('manifest.allow-backup'));
  check('report: no unsafe path findings', !ids.has('zip.unsafe-path'));
  check('report: no uncovered-entry findings', !ids.has('sig.v1-uncovered-entries'));
  check('report: no expired certificate', !ids.has('cert.expired'));
  equal('report: blocks install on high findings', result.report.blockInstall, true);
  check('report: score reduced', result.report.score < 100, `score ${result.report.score}`);
  check(
    'report: findings sorted by severity',
    result.report.findings[0].severity === 'high' ||
      result.report.findings[0].severity === 'critical',
    result.report.findings[0].severity,
  );

  const json = toJsonReport(result);
  check('json: serialises', JSON.stringify(json).length > 100);
  equal('json: package', json.package, 'com.smartrealty.demo');
  equal(
    'json: certificate count',
    json.certificates.length,
    1,
  );
}

async function testInspectHostileApk(): Promise<void> {
  const bomb = new TextEncoder().encode('\0'.repeat(2_000_000));
  const apk = buildApk({
    extraEntries: [
      { name: '../../../etc/cron.d/backdoor', data: new TextEncoder().encode('* * * * * root sh') },
      { name: 'assets/huge.bin', data: bomb },
      { name: 'assets/planted.txt', data: new TextEncoder().encode('added after signing') },
    ],
    omitFromJarManifest: ['assets/planted.txt'],
    weakCertificate: true,
  });

  const result = await inspectApk(apk, { now: new Date('2025-06-01T00:00:00Z') });
  const ids = new Set(result.report.findings.map((f) => f.id));

  check('hostile: path traversal flagged', ids.has('zip.unsafe-path'));
  check('hostile: compression bomb flagged', ids.has('zip.compression-bomb'));
  check('hostile: post-signing entry flagged', ids.has('sig.v1-uncovered-entries'));
  check('hostile: debug key flagged', ids.has('cert.debug-key'));
  check('hostile: weak hash flagged', ids.has('cert.weak-hash'));
  check('hostile: weak key flagged', ids.has('cert.weak-key'));
  equal('hostile: install blocked', result.report.blockInstall, true);
  equal('hostile: worst severity', result.report.worstSeverity, 'critical');
  equal('hostile: score floors at zero', result.report.score, 0);

  const traversal = result.report.findings.find((f) => f.id === 'zip.unsafe-path');
  equal('hostile: traversal evidence', traversal?.evidence, '../../../etc/cron.d/backdoor');
}

async function testUnsignedAndBrokenInput(): Promise<void> {
  const axml = buildAxml(manifestSpec());
  const unsigned = buildZip([
    { name: 'AndroidManifest.xml', data: axml },
    { name: 'classes.dex', data: new TextEncoder().encode('dex') },
  ]);
  const result = await inspectApk(unsigned);
  const ids = new Set(result.report.findings.map((f) => f.id));
  check('unsigned: flagged as unsigned', ids.has('sig.unsigned'));
  equal('unsigned: install blocked', result.report.blockInstall, true);

  const noManifest = buildZip([{ name: 'readme.txt', data: new TextEncoder().encode('hello') }]);
  const bare = await inspectApk(noManifest);
  check('no manifest: reports missing manifest', bare.manifest === null && bare.manifestError !== null);
  check(
    'no manifest: critical finding raised',
    bare.report.findings.some((f) => f.id === 'apk.no-manifest'),
  );

  let rejected = false;
  try {
    await inspectApk(new TextEncoder().encode('this is not an APK at all'));
  } catch {
    rejected = true;
  }
  check('non-archive input is rejected', rejected);
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  testInflate();
  testZip();
  testAxmlAndResources();
  await testCertificates();
  await testInspectHappyPath();
  await testInspectHostileApk();
  await testUnsignedAndBrokenInput();
  await testBatch(check, equal);
  await testPhase2(check, equal);

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    for (const failure of failures) console.log(`  - ${failure}`);
    process.exitCode = 1;
  }
}

void main();
