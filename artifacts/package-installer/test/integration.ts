/**
 * Cross-checks the parsers against artifacts produced by openssl, keytool and
 * jarsigner — independent implementations of the same formats.
 *
 * Run `bash test/make-real-fixtures.sh` first. When test/real/ is absent the
 * suite skips cleanly, so the committed tests stay runnable without the JDK.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ZipArchive } from '../src/zip.js';
import { parseCertificate, formatFingerprint } from '../src/x509.js';
import { collectSignatures, extractPkcs7Certificates, parseJarManifestEntryNames } from '../src/signing.js';

const here = dirname(fileURLToPath(import.meta.url));
// dist/test -> repo root -> test/real
const realDir = join(here, '..', '..', 'test', 'real');

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: string): void {
  if (condition) passed++;
  else {
    failed++;
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function equal<T>(name: string, actual: T, expected: T): void {
  check(name, Object.is(actual, expected), `expected ${String(expected)}, got ${String(actual)}`);
}

function read(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(realDir, name)));
}

/** openssl's RFC2253 output omits the space after each comma. */
function compact(name: string): string {
  return name.replace(/,\s+/g, ',');
}

function stripLeadingZeros(hex: string): string {
  return hex.replace(/^0+/, '').toUpperCase();
}

interface Expected {
  rsaSubject: string;
  rsaIssuer: string;
  rsaSerial: string;
  rsaFingerprintSha256: string;
  rsaNotBefore: string;
  rsaNotAfter: string;
  ecSubject: string;
  ecFingerprintSha256: string;
  jarCertFingerprintSha256: string;
}

async function main(): Promise<void> {
  if (!existsSync(join(realDir, 'expected.json'))) {
    console.log('test/real not found — run `bash test/make-real-fixtures.sh` first. Skipping.');
    return;
  }

  const expected: Expected = JSON.parse(readFileSync(join(realDir, 'expected.json'), 'utf8'));

  // --- openssl-generated RSA certificate ---------------------------------
  const rsa = await parseCertificate(read('rsa-cert.der'));
  equal('openssl RSA: subject matches', compact(rsa.subject), expected.rsaSubject);
  equal('openssl RSA: issuer matches', compact(rsa.issuer), expected.rsaIssuer);
  equal(
    'openssl RSA: serial matches',
    stripLeadingZeros(rsa.serialNumberHex),
    stripLeadingZeros(expected.rsaSerial),
  );
  equal(
    'openssl RSA: SHA-256 fingerprint matches',
    formatFingerprint(rsa.fingerprintSha256),
    expected.rsaFingerprintSha256,
  );
  equal('openssl RSA: notBefore matches', rsa.notBefore?.toISOString().replace('.000', ''), expected.rsaNotBefore);
  equal('openssl RSA: notAfter matches', rsa.notAfter?.toISOString().replace('.000', ''), expected.rsaNotAfter);
  equal('openssl RSA: key algorithm', rsa.publicKey.algorithm, 'RSA');
  equal('openssl RSA: key size', rsa.publicKey.keySizeBits, 2048);
  equal('openssl RSA: signature algorithm', rsa.signatureAlgorithm.name, 'sha256WithRSAEncryption');
  equal('openssl RSA: self-signed detected', rsa.selfSigned, true);
  equal('openssl RSA: version', rsa.version, 3);
  equal('openssl RSA: CN attribute', rsa.subjectAttributes.CN, 'Smart Realty Test');
  equal('openssl RSA: C attribute', rsa.subjectAttributes.C, 'US');

  // --- openssl-generated EC certificate ----------------------------------
  const ec = await parseCertificate(read('ec-cert.der'));
  equal('openssl EC: subject matches', compact(ec.subject), expected.ecSubject);
  equal(
    'openssl EC: SHA-256 fingerprint matches',
    formatFingerprint(ec.fingerprintSha256),
    expected.ecFingerprintSha256,
  );
  equal('openssl EC: key algorithm', ec.publicKey.algorithm, 'EC');
  equal('openssl EC: curve', ec.publicKey.curve, 'P-256');
  equal('openssl EC: field size', ec.publicKey.keySizeBits, 256);
  equal('openssl EC: signature algorithm', ec.signatureAlgorithm.name, 'ecdsa-with-SHA256');

  // --- openssl-generated PKCS#7 ------------------------------------------
  const p7Certs = extractPkcs7Certificates(read('certs.p7b'));
  equal('openssl PKCS#7: one certificate', p7Certs.length, 1);
  const fromP7 = await parseCertificate(p7Certs[0]);
  equal(
    'openssl PKCS#7: certificate matches the standalone DER',
    fromP7.fingerprintSha256,
    rsa.fingerprintSha256,
  );

  // --- Info-ZIP archive, jarsigner v1 signature ---------------------------
  const jarBytes = read('signed.jar');
  const jar = ZipArchive.parse(jarBytes);
  check('signed JAR: entries found', jar.entries.length >= 6, `${jar.entries.length} entries`);

  let readAll = true;
  for (const entry of jar.entries) {
    try {
      jar.read(entry); // CRC-verified by default
    } catch (error) {
      readAll = false;
      failures.push(`could not read ${entry.name}: ${(error as Error).message}`);
    }
  }
  check('signed JAR: every entry inflates and CRC-checks', readAll);

  const signatures = await collectSignatures(jar);
  equal('signed JAR: v1 detected', signatures.v1, true);
  equal('signed JAR: v2 absent', signatures.v2, false);
  equal('signed JAR: one signer', signatures.signers.length, 1);
  equal('signed JAR: signature source', signatures.signers[0].source, 'META-INF/SIGNER.RSA');
  equal('signed JAR: no parse warnings', signatures.warnings.length, 0);

  const jarCert = signatures.signers[0].certificates[0];
  equal(
    'signed JAR: keytool fingerprint matches',
    formatFingerprint(jarCert.fingerprintSha256),
    expected.jarCertFingerprintSha256,
  );
  equal('signed JAR: signer CN', jarCert.subjectAttributes.CN, 'Smart Realty Test');
  equal('signed JAR: signer key size', jarCert.publicKey.keySizeBits, 2048);

  const jarManifest = jar.readByName('META-INF/MANIFEST.MF')!;
  const covered = parseJarManifestEntryNames(jarManifest);
  const uncovered = jar.entries
    .filter((e) => !e.isDirectory && !e.name.startsWith('META-INF/') && !covered.has(e.name))
    .map((e) => e.name);
  equal('signed JAR: every file is covered by MANIFEST.MF', uncovered.length, 0);
  check('signed JAR: manifest lists the payload', covered.has('assets/listings.txt'));

  // --- unsigned archive ---------------------------------------------------
  const unsigned = ZipArchive.parse(read('unsigned.jar'));
  const unsignedSignatures = await collectSignatures(unsigned);
  equal('unsigned JAR: no v1 signature', unsignedSignatures.v1, false);
  equal('unsigned JAR: no signers', unsignedSignatures.signers.length, 0);

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    for (const failure of failures) console.log(`  - ${failure}`);
    process.exitCode = 1;
  }
}

void main();
