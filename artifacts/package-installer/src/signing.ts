/**
 * APK signature discovery: v1 (JAR / PKCS#7), and the v2 / v3 / v3.1 blocks.
 *
 * Which schemes are present matters as much as who signed: a v1-only APK
 * cannot be installed by Android 11+ when it targets API 30 or higher, and
 * v1-only is the precondition for the Janus-style class of tampering where the
 * archive and the signed content disagree.
 */

import { ByteReader, bytesEqual, decodeUtf8 } from './bytes.js';
import { CLASS_CONTEXT, isSequence, oidToString, parseDer, type Asn1Node } from './asn1.js';
import { parseCertificate, type CertificateInfo } from './x509.js';
import type { ZipArchive } from './zip.js';

const APK_SIG_BLOCK_MAGIC = new TextEncoder().encode('APK Sig Block 42');

export const BLOCK_ID_V2 = 0x7109871a;
export const BLOCK_ID_V3 = 0xf05368c0;
export const BLOCK_ID_V31 = 0x1b93ad61;
export const BLOCK_ID_SOURCE_STAMP_V2 = 0x6dff800d;
export const BLOCK_ID_PADDING = 0x42726577;

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

/** Signature algorithm ids used inside the v2/v3 signing blocks. */
const SIG_ALGORITHM_NAMES: Record<number, string> = {
  0x0101: 'RSASSA-PSS with SHA-256',
  0x0102: 'RSASSA-PSS with SHA-512',
  0x0103: 'RSASSA-PKCS1-v1_5 with SHA-256',
  0x0104: 'RSASSA-PKCS1-v1_5 with SHA-512',
  0x0201: 'ECDSA with SHA-256',
  0x0202: 'ECDSA with SHA-512',
  0x0301: 'DSA with SHA-256',
  0x0421: 'RSASSA-PKCS1-v1_5 with SHA-256 (verity)',
  0x0423: 'ECDSA with SHA-256 (verity)',
  0x0425: 'DSA with SHA-256 (verity)',
};

export interface SignerInfo {
  /** Which scheme this signer was found under. */
  scheme: 'v1' | 'v2' | 'v3' | 'v3.1';
  certificates: CertificateInfo[];
  signatureAlgorithms: string[];
  /** v3 only: the SDK range this signer is valid for. */
  minSdkVersion: number | null;
  maxSdkVersion: number | null;
  /** For v1, the META-INF file the signature came from. */
  source: string | null;
}

export interface ApkSignatureInfo {
  v1: boolean;
  v2: boolean;
  v3: boolean;
  v31: boolean;
  sourceStamp: boolean;
  signers: SignerInfo[];
  /** Signing-block ids present but not understood here. */
  unknownBlockIds: number[];
  /** Non-fatal problems hit while parsing signatures. */
  warnings: string[];
}

/** Locates the APK Signing Block sitting immediately before the central directory. */
export function findApkSigningBlock(
  bytes: Uint8Array,
  centralDirectoryOffset: number,
): Uint8Array | null {
  if (centralDirectoryOffset < 32) return null;
  const magicStart = centralDirectoryOffset - APK_SIG_BLOCK_MAGIC.length;
  if (!bytesEqual(bytes.subarray(magicStart, centralDirectoryOffset), APK_SIG_BLOCK_MAGIC)) {
    return null;
  }
  const sizeReader = new ByteReader(bytes, magicStart - 8);
  const blockSize = sizeReader.u64();
  const blockStart = centralDirectoryOffset - blockSize - 8;
  if (blockStart < 0 || blockStart + 8 > bytes.length) return null;
  const declared = new ByteReader(bytes, blockStart).u64();
  if (declared !== blockSize) return null;
  // Pairs live between the leading size field and the trailing size+magic.
  return bytes.subarray(blockStart + 8, magicStart - 8);
}

function readLengthPrefixed(r: ByteReader): Uint8Array {
  const length = r.u32();
  return r.take(length);
}

/** Iterates the id/value pairs inside a signing block. */
function* signingBlockPairs(block: Uint8Array): Generator<{ id: number; value: Uint8Array }> {
  const r = new ByteReader(block, 0);
  while (r.remaining >= 12) {
    const pairLength = r.u64();
    if (pairLength < 4 || pairLength - 4 > r.remaining - 4) return;
    const id = r.u32();
    yield { id, value: r.take(pairLength - 4) };
  }
}

interface RawSigner {
  certificates: Uint8Array[];
  signatureAlgorithms: string[];
  minSdkVersion: number | null;
  maxSdkVersion: number | null;
}

/**
 * Parses a v2 or v3 scheme block.
 *
 * Layout is length-prefixed all the way down:
 *   signers -> signer -> { signed data, [v3: min/max sdk], signatures, public key }
 * and signed data holds digests then certificates.
 */
function parseSchemeBlock(value: Uint8Array, isV3: boolean, warnings: string[]): RawSigner[] {
  const signers: RawSigner[] = [];
  try {
    const outer = new ByteReader(readLengthPrefixed(new ByteReader(value, 0)), 0);
    while (outer.remaining >= 4) {
      const signerBytes = readLengthPrefixed(outer);
      const signer = new ByteReader(signerBytes, 0);
      const signedData = new ByteReader(readLengthPrefixed(signer), 0);

      // digests
      const digests = new ByteReader(readLengthPrefixed(signedData), 0);
      const signatureAlgorithms: string[] = [];
      while (digests.remaining >= 4) {
        const digestRecord = new ByteReader(readLengthPrefixed(digests), 0);
        const algorithmId = digestRecord.u32();
        signatureAlgorithms.push(
          SIG_ALGORITHM_NAMES[algorithmId] ?? `0x${algorithmId.toString(16).padStart(4, '0')}`,
        );
      }

      // certificates
      const certificates: Uint8Array[] = [];
      const certs = new ByteReader(readLengthPrefixed(signedData), 0);
      while (certs.remaining >= 4) certificates.push(readLengthPrefixed(certs));

      let minSdkVersion: number | null = null;
      let maxSdkVersion: number | null = null;
      if (isV3 && signedData.remaining >= 8) {
        minSdkVersion = signedData.i32();
        maxSdkVersion = signedData.i32();
      }

      signers.push({ certificates, signatureAlgorithms, minSdkVersion, maxSdkVersion });
    }
  } catch (error) {
    warnings.push(
      `${isV3 ? 'v3' : 'v2'} signing block is malformed: ${(error as Error).message}`,
    );
  }
  return signers;
}

/** Pulls the certificate set out of a PKCS#7 SignedData blob. */
export function extractPkcs7Certificates(der: Uint8Array): Uint8Array[] {
  const contentInfo = parseDer(der);
  if (!isSequence(contentInfo) || contentInfo.children.length < 2) return [];
  const contentType = oidToString(contentInfo.children[0]);
  if (contentType !== OID_SIGNED_DATA) return [];

  const explicit = contentInfo.children[1];
  const signedData = explicit.children[0];
  if (!signedData || !isSequence(signedData)) return [];

  // SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo,
  //                          [0] IMPLICIT certificates OPTIONAL, ... }
  const certificatesNode = signedData.children.find(
    (child: Asn1Node) => child.tagClass === CLASS_CONTEXT && child.tag === 0,
  );
  if (!certificatesNode) return [];

  return certificatesNode.children.filter(isSequence).map((node) => node.raw);
}

const V1_SIGNATURE_FILE = /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i;

export interface CollectSignaturesOptions {
  /** Skip v1 parsing when only the modern schemes matter. */
  includeV1?: boolean;
}

/** Collects every signer the APK declares, across all schemes present. */
export async function collectSignatures(
  archive: ZipArchive,
  options: CollectSignaturesOptions = {},
): Promise<ApkSignatureInfo> {
  const warnings: string[] = [];
  const signers: SignerInfo[] = [];
  const unknownBlockIds: number[] = [];
  const info: ApkSignatureInfo = {
    v1: false,
    v2: false,
    v3: false,
    v31: false,
    sourceStamp: false,
    signers,
    unknownBlockIds,
    warnings,
  };

  const block = findApkSigningBlock(archive.bytes, archive.centralDirectoryOffset);
  if (block) {
    for (const { id, value } of signingBlockPairs(block)) {
      switch (id >>> 0) {
        case BLOCK_ID_V2:
        case BLOCK_ID_V3:
        case BLOCK_ID_V31: {
          const scheme = id >>> 0 === BLOCK_ID_V2 ? 'v2' : id >>> 0 === BLOCK_ID_V3 ? 'v3' : 'v3.1';
          if (scheme === 'v2') info.v2 = true;
          else if (scheme === 'v3') info.v3 = true;
          else info.v31 = true;

          for (const raw of parseSchemeBlock(value, scheme !== 'v2', warnings)) {
            signers.push({
              scheme,
              certificates: await parseCertificates(raw.certificates, warnings),
              signatureAlgorithms: raw.signatureAlgorithms,
              minSdkVersion: raw.minSdkVersion,
              maxSdkVersion: raw.maxSdkVersion,
              source: null,
            });
          }
          break;
        }
        case BLOCK_ID_SOURCE_STAMP_V2:
          info.sourceStamp = true;
          break;
        case BLOCK_ID_PADDING:
          break;
        default:
          unknownBlockIds.push(id >>> 0);
      }
    }
  }

  if (options.includeV1 !== false) {
    for (const entry of archive.entries) {
      if (!V1_SIGNATURE_FILE.test(entry.name)) continue;
      info.v1 = true;
      try {
        const der = archive.read(entry);
        const certificates = await parseCertificates(extractPkcs7Certificates(der), warnings);
        if (certificates.length > 0) {
          signers.push({
            scheme: 'v1',
            certificates,
            signatureAlgorithms: [],
            minSdkVersion: null,
            maxSdkVersion: null,
            source: entry.name,
          });
        }
      } catch (error) {
        warnings.push(`could not read ${entry.name}: ${(error as Error).message}`);
      }
    }
  }

  return info;
}

async function parseCertificates(
  ders: Uint8Array[],
  warnings: string[],
): Promise<CertificateInfo[]> {
  const out: CertificateInfo[] = [];
  for (const der of ders) {
    try {
      out.push(await parseCertificate(der));
    } catch (error) {
      warnings.push(`certificate could not be parsed: ${(error as Error).message}`);
    }
  }
  return out;
}

/**
 * Reads the v1 manifest (META-INF/MANIFEST.MF) entry names.
 *
 * Used to spot files that were added to the archive after signing — under v1
 * those are simply unsigned, and older Android accepts them.
 */
export function parseJarManifestEntryNames(manifestBytes: Uint8Array): Set<string> {
  const text = decodeUtf8(manifestBytes);
  // Continuation lines start with a single space; unfold before matching.
  const unfolded = text.replace(/\r\n|\r/g, '\n').replace(/\n /g, '');
  const names = new Set<string>();
  for (const line of unfolded.split('\n')) {
    const match = /^Name:\s*(.+?)\s*$/.exec(line);
    if (match) names.add(match[1]);
  }
  return names;
}
