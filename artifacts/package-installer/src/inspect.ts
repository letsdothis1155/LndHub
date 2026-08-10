/**
 * Top-level entry point: bytes in, structured inspection out.
 *
 * Nothing here writes to disk or hits the network, so it runs identically in a
 * browser worker (a dropped file, a fetched catalog entry) and in Node.
 */

import { ResourceTable } from './arsc.js';
import { digest, toHex } from './bytes.js';
import { parseAndroidManifest, type AndroidManifest } from './manifest.js';
import { analyze, type SafetyReport } from './safety.js';
import {
  collectSignatures,
  parseJarManifestEntryNames,
  type ApkSignatureInfo,
} from './signing.js';
import { ZipArchive, type ZipEntry } from './zip.js';

export interface ApkFileSummary {
  totalEntries: number;
  totalCompressedSize: number;
  totalUncompressedSize: number;
  dexFiles: string[];
  nativeAbis: string[];
  /** Largest entries by uncompressed size, for the preview pane. */
  largestEntries: { name: string; uncompressedSize: number }[];
}

export interface ApkInspection {
  /** SHA-256 of the whole file — the identity a catalog should pin. */
  sha256: string;
  size: number;
  archive: ZipArchive;
  manifest: AndroidManifest | null;
  /** Why the manifest is null, when it is. */
  manifestError: string | null;
  resources: ResourceTable | null;
  signatures: ApkSignatureInfo;
  files: ApkFileSummary;
  report: SafetyReport;
}

export interface InspectOptions {
  /** Skip resources.arsc parsing when only structural facts are needed. */
  parseResources?: boolean;
  /** Verify CRC-32 when reading the manifest and signature entries. */
  verifyCrc?: boolean;
  /** Injected for deterministic tests of certificate validity windows. */
  now?: Date;
}

/** Parses and analyses an APK held entirely in memory. */
export async function inspectApk(
  data: Uint8Array,
  options: InspectOptions = {},
): Promise<ApkInspection> {
  const archive = ZipArchive.parse(data);
  const readOptions = { verifyCrc: options.verifyCrc !== false };

  let resources: ResourceTable | null = null;
  if (options.parseResources !== false && archive.has('resources.arsc')) {
    try {
      const arsc = archive.readByName('resources.arsc', readOptions);
      if (arsc) resources = ResourceTable.parse(arsc);
    } catch {
      // A damaged resource table only costs us label resolution.
      resources = null;
    }
  }

  let manifest: AndroidManifest | null = null;
  let manifestError: string | null = null;
  try {
    const axml = archive.readByName('AndroidManifest.xml', readOptions);
    if (axml) manifest = parseAndroidManifest(axml, { resources });
    else manifestError = 'AndroidManifest.xml is missing from the archive';
  } catch (error) {
    manifestError = (error as Error).message;
  }

  const signatures = await collectSignatures(archive);

  let v1CoveredEntries: Set<string> | null = null;
  if (signatures.v1) {
    try {
      const jarManifest = archive.readByName('META-INF/MANIFEST.MF', readOptions);
      if (jarManifest) v1CoveredEntries = parseJarManifestEntryNames(jarManifest);
    } catch {
      v1CoveredEntries = null;
    }
  }

  const report = analyze({
    archive,
    manifest,
    signatures,
    v1CoveredEntries,
    now: options.now,
  });

  return {
    sha256: toHex(await digest('SHA-256', data)),
    size: data.length,
    archive,
    manifest,
    manifestError,
    resources,
    signatures,
    files: summarizeFiles(archive.entries),
    report,
  };
}

function summarizeFiles(entries: ZipEntry[]): ApkFileSummary {
  const abis = new Set<string>();
  const dexFiles: string[] = [];
  let totalCompressedSize = 0;
  let totalUncompressedSize = 0;

  for (const entry of entries) {
    totalCompressedSize += entry.compressedSize;
    totalUncompressedSize += entry.uncompressedSize;
    if (/^classes\d*\.dex$/.test(entry.name)) dexFiles.push(entry.name);
    const match = /^lib\/([^/]+)\//.exec(entry.name);
    if (match) abis.add(match[1]);
  }

  const largestEntries = [...entries]
    .filter((e) => !e.isDirectory)
    .sort((a, b) => b.uncompressedSize - a.uncompressedSize)
    .slice(0, 10)
    .map((e) => ({ name: e.name, uncompressedSize: e.uncompressedSize }));

  return {
    totalEntries: entries.length,
    totalCompressedSize,
    totalUncompressedSize,
    dexFiles: dexFiles.sort(),
    nativeAbis: [...abis].sort(),
    largestEntries,
  };
}

/** JSON-safe projection, for catalog storage or a downloadable report. */
export function toJsonReport(inspection: ApkInspection): Record<string, unknown> {
  const { manifest, signatures, report, files } = inspection;
  return {
    sha256: inspection.sha256,
    size: inspection.size,
    package: manifest?.package ?? null,
    versionCode: manifest?.versionCode ?? null,
    versionName: manifest?.versionName ?? null,
    label: manifest?.application.label ?? null,
    minSdkVersion: manifest?.minSdkVersion ?? null,
    targetSdkVersion: manifest?.targetSdkVersion ?? null,
    manifestError: inspection.manifestError,
    permissions: manifest?.usesPermissions.map((p) => p.name) ?? [],
    exportedComponents:
      manifest?.components
        .filter((c) => c.effectiveExported)
        .map((c) => ({ kind: c.kind, name: c.name, permission: c.permission })) ?? [],
    signatureSchemes: {
      v1: signatures.v1,
      v2: signatures.v2,
      v3: signatures.v3,
      v31: signatures.v31,
      sourceStamp: signatures.sourceStamp,
    },
    certificates: signatures.signers.flatMap((signer) =>
      signer.certificates.map((cert) => ({
        scheme: signer.scheme,
        subject: cert.subject,
        issuer: cert.issuer,
        serialNumber: cert.serialNumberHex,
        notBefore: cert.notBefore?.toISOString() ?? null,
        notAfter: cert.notAfter?.toISOString() ?? null,
        signatureAlgorithm: cert.signatureAlgorithm.name,
        keyAlgorithm: cert.publicKey.algorithm,
        keySizeBits: cert.publicKey.keySizeBits,
        selfSigned: cert.selfSigned,
        sha256: cert.fingerprintSha256,
      })),
    ),
    files: {
      totalEntries: files.totalEntries,
      totalUncompressedSize: files.totalUncompressedSize,
      dexFiles: files.dexFiles,
      nativeAbis: files.nativeAbis,
    },
    safety: {
      score: report.score,
      worstSeverity: report.worstSeverity,
      blockInstall: report.blockInstall,
      counts: report.counts,
      findings: report.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        evidence: f.evidence ?? null,
      })),
    },
  };
}
