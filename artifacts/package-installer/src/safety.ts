/**
 * Safety findings derived from the parsed manifest, signatures, and archive.
 *
 * Each rule states what it saw and why it matters; nothing here is a verdict on
 * intent. The score is a triage aid for ordering a catalog, not a malware
 * judgement — an app can be perfectly legitimate and still trip several rules.
 */

import type { AndroidManifest } from './manifest.js';
import type { ApkSignatureInfo } from './signing.js';
import { checkEntryPath, type ZipArchive } from './zip.js';
import { formatFingerprint } from './x509.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** Where the evidence came from, e.g. a manifest attribute or entry name. */
  evidence?: string;
}

export interface SafetyReport {
  findings: Finding[];
  /** 0-100; 100 means nothing was flagged above `info`. */
  score: number;
  /** Highest severity present, or null when the APK is clean. */
  worstSeverity: Severity | null;
  /** True when a critical or high finding is present. */
  blockInstall: boolean;
  counts: Record<Severity, number>;
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 60,
  high: 25,
  medium: 10,
  low: 3,
  info: 0,
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Permissions that grant access to user data or device control.
 * Grouped so the UI can explain them rather than list bare constant names.
 */
export const SENSITIVE_PERMISSIONS: Record<string, { group: string; note: string }> = {
  'android.permission.READ_SMS': { group: 'SMS', note: 'read the contents of text messages' },
  'android.permission.RECEIVE_SMS': { group: 'SMS', note: 'intercept incoming text messages' },
  'android.permission.SEND_SMS': { group: 'SMS', note: 'send text messages, which can cost money' },
  'android.permission.READ_CONTACTS': { group: 'Contacts', note: 'read the address book' },
  'android.permission.WRITE_CONTACTS': { group: 'Contacts', note: 'modify the address book' },
  'android.permission.READ_CALL_LOG': { group: 'Call log', note: 'read who was called and when' },
  'android.permission.PROCESS_OUTGOING_CALLS': { group: 'Call log', note: 'observe outgoing calls' },
  'android.permission.ACCESS_FINE_LOCATION': { group: 'Location', note: 'read precise location' },
  'android.permission.ACCESS_BACKGROUND_LOCATION': {
    group: 'Location',
    note: 'read location while the app is in the background',
  },
  'android.permission.RECORD_AUDIO': { group: 'Microphone', note: 'record audio' },
  'android.permission.CAMERA': { group: 'Camera', note: 'take pictures and record video' },
  'android.permission.READ_EXTERNAL_STORAGE': { group: 'Storage', note: 'read shared storage' },
  'android.permission.MANAGE_EXTERNAL_STORAGE': {
    group: 'Storage',
    note: 'read and write all shared storage without per-file consent',
  },
  'android.permission.REQUEST_INSTALL_PACKAGES': {
    group: 'Installer',
    note: 'install other apps',
  },
  'android.permission.BIND_ACCESSIBILITY_SERVICE': {
    group: 'Accessibility',
    note: 'observe and act on everything shown on screen',
  },
  'android.permission.BIND_DEVICE_ADMIN': {
    group: 'Device admin',
    note: 'administer the device, including wiping and locking it',
  },
  'android.permission.SYSTEM_ALERT_WINDOW': {
    group: 'Overlay',
    note: 'draw over other apps, the basis of tap-jacking',
  },
  'android.permission.QUERY_ALL_PACKAGES': {
    group: 'Inventory',
    note: 'enumerate every installed app',
  },
  'android.permission.READ_PHONE_STATE': { group: 'Phone', note: 'read phone state and identity' },
  'android.permission.RECEIVE_BOOT_COMPLETED': {
    group: 'Autostart',
    note: 'start automatically when the device boots',
  },
};

/** Below this expanded size a high compression ratio is not worth reporting. */
const BOMB_SIZE_FLOOR = 1024 * 1024;

/** Permission groups worth calling out at medium rather than low severity. */
const HIGH_RISK_GROUPS = new Set(['Accessibility', 'Device admin', 'Installer', 'Overlay', 'SMS']);

export interface AnalyzeInput {
  archive: ZipArchive;
  manifest: AndroidManifest | null;
  signatures: ApkSignatureInfo;
  /** Entry names covered by META-INF/MANIFEST.MF, when v1-signed. */
  v1CoveredEntries?: Set<string> | null;
  /** Compression ratio above which an entry is treated as a decompression bomb. */
  maxCompressionRatio?: number;
  now?: Date;
}

export function analyze(input: AnalyzeInput): SafetyReport {
  const findings: Finding[] = [];
  const now = input.now ?? new Date();
  const maxRatio = input.maxCompressionRatio ?? 200;

  analyzeArchive(input.archive, maxRatio, findings);
  analyzeSignatures(input.signatures, input.manifest, now, findings);
  if (input.manifest) analyzeManifest(input.manifest, findings);
  if (input.v1CoveredEntries) {
    analyzeV1Coverage(input.archive, input.v1CoveredEntries, findings);
  }

  return summarize(findings);
}

function analyzeArchive(archive: ZipArchive, maxRatio: number, findings: Finding[]): void {
  for (const entry of archive.entries) {
    const unsafe = checkEntryPath(entry.name, entry.nameBytes);
    if (unsafe) {
      findings.push({
        id: 'zip.unsafe-path',
        severity: 'critical',
        title: 'Archive entry would escape the extraction directory',
        detail: `Entry name is unsafe (${unsafe.reason}). Extracting it could overwrite files outside the target directory.`,
        evidence: entry.name,
      });
    }
    // Gate on the expanded size, not the compressed size: a 2 KB entry that
    // inflates to 2 MB is the exact shape being guarded against.
    if (
      entry.uncompressedSize > BOMB_SIZE_FLOOR &&
      entry.uncompressedSize / Math.max(entry.compressedSize, 1) > maxRatio
    ) {
      findings.push({
        id: 'zip.compression-bomb',
        severity: 'high',
        title: 'Entry expands to an implausible size',
        detail: `${entry.name} compresses ${entry.uncompressedSize} bytes into ${entry.compressedSize}, a ratio of ${Math.round(entry.uncompressedSize / entry.compressedSize)}:1.`,
        evidence: entry.name,
      });
    }
  }

  const duplicates = archive.duplicateNames();
  for (const name of duplicates) {
    findings.push({
      id: 'zip.duplicate-entry',
      severity: 'high',
      title: 'Archive contains duplicate entry names',
      detail: `"${name}" appears more than once. Different readers can pick different copies, which is how a signed file and an installed file end up differing.`,
      evidence: name,
    });
  }

  if (!archive.has('AndroidManifest.xml')) {
    findings.push({
      id: 'apk.no-manifest',
      severity: 'critical',
      title: 'No AndroidManifest.xml',
      detail: 'The archive has no manifest, so it is not an installable APK.',
    });
  }

  const dexCount = archive.entries.filter((e) => /^classes\d*\.dex$/.test(e.name)).length;
  if (dexCount === 0 && archive.has('AndroidManifest.xml')) {
    findings.push({
      id: 'apk.no-dex',
      severity: 'info',
      title: 'No DEX code in the package',
      detail: 'The package contains no classes.dex. This is normal for resource-only splits.',
    });
  }

  const abis = new Set<string>();
  for (const entry of archive.entries) {
    const match = /^lib\/([^/]+)\//.exec(entry.name);
    if (match) abis.add(match[1]);
  }
  if (abis.size > 0) {
    findings.push({
      id: 'apk.native-code',
      severity: 'info',
      title: 'Package ships native libraries',
      detail: `Native code is present for: ${[...abis].sort().join(', ')}. Native libraries are not visible to DEX-level review.`,
    });
  }
}

function analyzeSignatures(
  signatures: ApkSignatureInfo,
  manifest: AndroidManifest | null,
  now: Date,
  findings: Finding[],
): void {
  if (!signatures.v1 && !signatures.v2 && !signatures.v3 && !signatures.v31) {
    findings.push({
      id: 'sig.unsigned',
      severity: 'critical',
      title: 'Package is not signed',
      detail: 'No v1, v2, or v3 signature was found. Android will refuse to install it, and nothing vouches for its origin.',
    });
    return;
  }

  if (signatures.v1 && !signatures.v2 && !signatures.v3) {
    const targetSdk = manifest?.targetSdkVersion ?? null;
    findings.push({
      id: 'sig.v1-only',
      severity: targetSdk !== null && targetSdk >= 30 ? 'high' : 'medium',
      title: 'Only the legacy v1 signature is present',
      detail:
        targetSdk !== null && targetSdk >= 30
          ? `The package targets API ${targetSdk}, and Android 11+ refuses to install a v1-only package at that target. It also leaves the archive structure itself unsigned.`
          : 'v1 signs individual files, not the archive as a whole, so the ZIP structure around them is unprotected.',
    });
  }

  const seenFingerprints = new Set<string>();
  for (const signer of signatures.signers) {
    for (const cert of signer.certificates) {
      if (seenFingerprints.has(cert.fingerprintSha256)) continue;
      seenFingerprints.add(cert.fingerprintSha256);

      const who = cert.subject || formatFingerprint(cert.fingerprintSha256);

      if (cert.signatureAlgorithm.weakHash) {
        findings.push({
          id: 'cert.weak-hash',
          severity: 'high',
          title: 'Signing certificate uses a broken hash',
          detail: `${who} is signed with ${cert.signatureAlgorithm.name}. ${cert.signatureAlgorithm.hash} is not collision-resistant, so the certificate does not reliably identify one signer.`,
          evidence: formatFingerprint(cert.fingerprintSha256),
        });
      }

      if (
        (cert.publicKey.algorithm === 'RSA' || cert.publicKey.algorithm === 'DSA') &&
        cert.publicKey.keySizeBits !== null &&
        cert.publicKey.keySizeBits < 2048
      ) {
        findings.push({
          id: 'cert.weak-key',
          severity: cert.publicKey.keySizeBits < 1024 ? 'high' : 'medium',
          title: 'Signing key is smaller than current guidance',
          detail: `${who} uses a ${cert.publicKey.keySizeBits}-bit ${cert.publicKey.algorithm} key. 2048 bits is the current minimum.`,
          evidence: formatFingerprint(cert.fingerprintSha256),
        });
      }

      const cn = cert.subjectAttributes.CN ?? '';
      if (/android\s*debug/i.test(cn)) {
        findings.push({
          id: 'cert.debug-key',
          severity: 'high',
          title: 'Signed with the Android debug key',
          detail: 'The debug keystore ships with the SDK and its private key is not secret. Anyone can produce an update that Android will accept as the same app.',
          evidence: cert.subject,
        });
      }

      if (cert.notAfter && cert.notAfter.getTime() < now.getTime()) {
        findings.push({
          id: 'cert.expired',
          severity: 'medium',
          title: 'Signing certificate has expired',
          detail: `${who} expired on ${cert.notAfter.toISOString().slice(0, 10)}. Android still installs it, but the certificate no longer attests to anything current.`,
          evidence: formatFingerprint(cert.fingerprintSha256),
        });
      }
      if (cert.notBefore && cert.notBefore.getTime() > now.getTime()) {
        findings.push({
          id: 'cert.not-yet-valid',
          severity: 'medium',
          title: 'Signing certificate is not valid yet',
          detail: `${who} is not valid until ${cert.notBefore.toISOString().slice(0, 10)}, which suggests a wrong clock or a fabricated certificate.`,
          evidence: formatFingerprint(cert.fingerprintSha256),
        });
      }
    }
  }

  if (seenFingerprints.size > 1) {
    findings.push({
      id: 'sig.multiple-certificates',
      severity: 'info',
      title: 'Package carries more than one signing certificate',
      detail: `${seenFingerprints.size} distinct certificates were found. This is normal after a key rotation, and worth confirming against the publisher you expect.`,
    });
  }

  for (const warning of signatures.warnings) {
    findings.push({
      id: 'sig.parse-warning',
      severity: 'medium',
      title: 'Part of the signature data could not be read',
      detail: warning,
    });
  }
}

function analyzeManifest(manifest: AndroidManifest, findings: Finding[]): void {
  const app = manifest.application;

  if (app.debuggable) {
    findings.push({
      id: 'manifest.debuggable',
      severity: 'high',
      title: 'Application is debuggable',
      detail: 'android:debuggable="true" lets any app with ADB access attach to the process and read its memory. Release builds should never ship this.',
      evidence: 'application@android:debuggable',
    });
  }

  if (app.testOnly) {
    findings.push({
      id: 'manifest.test-only',
      severity: 'medium',
      title: 'Application is marked test-only',
      detail: 'android:testOnly="true" packages are meant for `adb install -t` and are not intended for distribution.',
      evidence: 'application@android:testOnly',
    });
  }

  if (app.usesCleartextTraffic === true) {
    findings.push({
      id: 'manifest.cleartext-traffic',
      severity: 'medium',
      title: 'Cleartext HTTP traffic is allowed',
      detail: 'android:usesCleartextTraffic="true" permits unencrypted HTTP, which any network operator between the device and the server can read or modify.',
      evidence: 'application@android:usesCleartextTraffic',
    });
  }

  if (app.allowBackup) {
    findings.push({
      id: 'manifest.allow-backup',
      severity: 'low',
      title: 'Application data can be backed up',
      detail: 'android:allowBackup defaults to true, so app data can be pulled off the device with adb backup on older releases.',
      evidence: 'application@android:allowBackup',
    });
  }

  if (manifest.sharedUserId) {
    findings.push({
      id: 'manifest.shared-user-id',
      severity: 'medium',
      title: 'Application requests a shared user id',
      detail: `android:sharedUserId="${manifest.sharedUserId}" asks to share a UID — and therefore a sandbox — with other apps signed by the same key.`,
      evidence: manifest.sharedUserId,
    });
  }

  if (manifest.targetSdkVersion !== null && manifest.targetSdkVersion < 30) {
    findings.push({
      id: 'manifest.old-target-sdk',
      severity: manifest.targetSdkVersion < 23 ? 'high' : 'medium',
      title: 'Application targets an old Android version',
      detail:
        manifest.targetSdkVersion < 23
          ? `targetSdkVersion ${manifest.targetSdkVersion} predates runtime permissions, so every requested permission is granted at install time without a prompt.`
          : `targetSdkVersion ${manifest.targetSdkVersion} opts out of platform protections introduced in later releases, such as scoped storage.`,
      evidence: `uses-sdk@android:targetSdkVersion=${manifest.targetSdkVersion}`,
    });
  }

  const groups = new Map<string, string[]>();
  for (const permission of manifest.usesPermissions) {
    const known = SENSITIVE_PERMISSIONS[permission.name];
    if (!known) continue;
    const list = groups.get(known.group) ?? [];
    list.push(`${permission.name} — ${known.note}`);
    groups.set(known.group, list);
  }
  for (const [group, entries] of groups) {
    findings.push({
      id: `permission.${group.toLowerCase().replace(/\s+/g, '-')}`,
      severity: HIGH_RISK_GROUPS.has(group) ? 'medium' : 'low',
      title: `Requests ${group.toLowerCase()} access`,
      detail: entries.join('; '),
      evidence: entries.length === 1 ? entries[0].split(' — ')[0] : `${entries.length} permissions`,
    });
  }

  const exported = manifest.components.filter((c) => c.effectiveExported && c.permission === null);
  const exportedWithoutFilter = exported.filter(
    (c) => c.intentFilters.length === 0 && c.declaredExported === true,
  );
  if (exportedWithoutFilter.length > 0) {
    findings.push({
      id: 'manifest.exported-unprotected',
      severity: 'medium',
      title: 'Components are exported without a permission',
      detail: `${exportedWithoutFilter.length} component(s) are explicitly exported with no android:permission, so any other app on the device can invoke them: ${exportedWithoutFilter
        .slice(0, 5)
        .map((c) => c.name)
        .join(', ')}${exportedWithoutFilter.length > 5 ? ', …' : ''}`,
      evidence: exportedWithoutFilter[0].name,
    });
  }

  const exportedProviders = manifest.components.filter(
    (c) => c.kind === 'provider' && c.effectiveExported && c.permission === null,
  );
  if (exportedProviders.length > 0) {
    findings.push({
      id: 'manifest.exported-provider',
      severity: 'high',
      title: 'Content provider is exported without a permission',
      detail: `${exportedProviders.map((c) => c.name).join(', ')} is reachable by any app on the device, which exposes whatever data it serves.`,
      evidence: exportedProviders[0].authorities.join(', ') || exportedProviders[0].name,
    });
  }

  if (manifest.minSdkVersion !== null && manifest.minSdkVersion < 21) {
    findings.push({
      id: 'manifest.low-min-sdk',
      severity: 'info',
      title: 'Supports very old Android versions',
      detail: `minSdkVersion ${manifest.minSdkVersion} means the app can run on releases that no longer receive security patches.`,
    });
  }
}

function analyzeV1Coverage(
  archive: ZipArchive,
  covered: Set<string>,
  findings: Finding[],
): void {
  const uncovered = archive.entries
    .filter(
      (entry) =>
        !entry.isDirectory &&
        !entry.name.startsWith('META-INF/') &&
        !covered.has(entry.name),
    )
    .map((entry) => entry.name);

  if (uncovered.length > 0) {
    findings.push({
      id: 'sig.v1-uncovered-entries',
      severity: 'high',
      title: 'Files are not covered by the v1 signature',
      detail: `${uncovered.length} entr${uncovered.length === 1 ? 'y is' : 'ies are'} absent from META-INF/MANIFEST.MF, so they were added after signing: ${uncovered.slice(0, 5).join(', ')}${uncovered.length > 5 ? ', …' : ''}`,
      evidence: uncovered[0],
    });
  }
}

function summarize(findings: Finding[]): SafetyReport {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  for (const finding of findings) {
    counts[finding.severity]++;
    penalty += SEVERITY_WEIGHTS[finding.severity];
  }

  const order = (s: Severity): number => SEVERITY_ORDER.indexOf(s);
  const sorted = [...findings].sort((a, b) => order(a.severity) - order(b.severity));
  const worstSeverity = sorted.find((f) => f.severity !== 'info')?.severity ?? null;

  return {
    findings: sorted,
    score: Math.max(0, 100 - penalty),
    worstSeverity,
    blockInstall: counts.critical > 0 || counts.high > 0,
    counts,
  };
}
