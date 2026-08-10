/**
 * X.509 certificate reader.
 *
 * Extracts the fields an installer actually shows or judges: who signed it,
 * how strong the key and signature algorithm are, and whether the validity
 * window makes sense. Signature verification is intentionally out of scope —
 * for a self-signed APK signing certificate, verifying it against itself
 * proves nothing an installer should act on.
 */

import { digest, toHex } from './bytes.js';
import {
  CLASS_CONTEXT,
  TAG_BIT_STRING,
  TAG_INTEGER,
  TAG_OID,
  TAG_SEQUENCE,
  derStringToText,
  derTimeToDate,
  integerBitLength,
  integerToHex,
  integerToNumber,
  oidToString,
  parseDer,
  type Asn1Node,
} from './asn1.js';

const OID_NAMES: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'SERIALNUMBER',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'T',
  '2.5.4.42': 'GN',
  '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.9.1': 'EMAILADDRESS',
};

export interface SignatureAlgorithmInfo {
  oid: string;
  name: string;
  /** The digest the signature is built on, when identifiable. */
  hash: 'MD2' | 'MD5' | 'SHA-1' | 'SHA-224' | 'SHA-256' | 'SHA-384' | 'SHA-512' | 'unknown';
  /** True for digests no longer considered collision-resistant. */
  weakHash: boolean;
}

const SIGNATURE_ALGORITHMS: Record<string, Omit<SignatureAlgorithmInfo, 'oid'>> = {
  '1.2.840.113549.1.1.2': { name: 'md2WithRSAEncryption', hash: 'MD2', weakHash: true },
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', hash: 'MD5', weakHash: true },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', hash: 'SHA-1', weakHash: true },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS', hash: 'unknown', weakHash: false },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', hash: 'SHA-256', weakHash: false },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', hash: 'SHA-384', weakHash: false },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', hash: 'SHA-512', weakHash: false },
  '1.2.840.113549.1.1.14': { name: 'sha224WithRSAEncryption', hash: 'SHA-224', weakHash: false },
  '1.2.840.10040.4.3': { name: 'dsa-with-sha1', hash: 'SHA-1', weakHash: true },
  '2.16.840.1.101.3.4.3.2': { name: 'dsa-with-sha256', hash: 'SHA-256', weakHash: false },
  '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', hash: 'SHA-1', weakHash: true },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', hash: 'SHA-256', weakHash: false },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', hash: 'SHA-384', weakHash: false },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', hash: 'SHA-512', weakHash: false },
};

const CURVE_NAMES: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
  '1.3.132.0.10': 'secp256k1',
};

export interface PublicKeyInfo {
  algorithm: 'RSA' | 'DSA' | 'EC' | 'Ed25519' | 'unknown';
  algorithmOid: string;
  /** Modulus size for RSA/DSA, field size for EC. */
  keySizeBits: number | null;
  curve: string | null;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  subjectAttributes: Record<string, string>;
  serialNumberHex: string;
  version: number;
  notBefore: Date | null;
  notAfter: Date | null;
  signatureAlgorithm: SignatureAlgorithmInfo;
  publicKey: PublicKeyInfo;
  selfSigned: boolean;
  /** Lowercase hex SHA-256 of the DER encoding — the value Play/keytool print. */
  fingerprintSha256: string;
  fingerprintSha1: string;
  der: Uint8Array;
}

function parseName(node: Asn1Node): { text: string; attributes: Record<string, string> } {
  const parts: string[] = [];
  const attributes: Record<string, string> = {};
  // Name ::= RDNSequence ::= SEQUENCE OF SET OF AttributeTypeAndValue
  for (const rdn of node.children) {
    for (const pair of rdn.children) {
      if (pair.children.length < 2) continue;
      const [typeNode, valueNode] = pair.children;
      if (typeNode.tag !== TAG_OID) continue;
      const oid = oidToString(typeNode);
      const label = OID_NAMES[oid] ?? oid;
      const value = derStringToText(valueNode);
      parts.push(`${label}=${value}`);
      if (!(label in attributes)) attributes[label] = value;
    }
  }
  // Convention (and keytool's output) is most-specific-first.
  return { text: parts.reverse().join(', '), attributes };
}

function parsePublicKey(spki: Asn1Node): PublicKeyInfo {
  const algorithmNode = spki.children[0];
  const bitStringNode = spki.children[1];
  const algorithmOid =
    algorithmNode && algorithmNode.children[0]?.tag === TAG_OID
      ? oidToString(algorithmNode.children[0])
      : '';

  const info: PublicKeyInfo = {
    algorithm: 'unknown',
    algorithmOid,
    keySizeBits: null,
    curve: null,
  };

  // BIT STRING content begins with an "unused bits" octet.
  const keyBytes =
    bitStringNode && bitStringNode.tag === TAG_BIT_STRING
      ? bitStringNode.content.subarray(1)
      : new Uint8Array(0);

  try {
    if (algorithmOid === '1.2.840.113549.1.1.1') {
      info.algorithm = 'RSA';
      const rsaKey = parseDer(keyBytes);
      if (rsaKey.children[0]?.tag === TAG_INTEGER) {
        info.keySizeBits = integerBitLength(rsaKey.children[0]);
      }
    } else if (algorithmOid === '1.2.840.10045.2.1') {
      info.algorithm = 'EC';
      const params = algorithmNode?.children[1];
      if (params?.tag === TAG_OID) {
        const curveOid = oidToString(params);
        info.curve = CURVE_NAMES[curveOid] ?? curveOid;
      }
      // Uncompressed point: 0x04 || X || Y, so the field size is half the rest.
      if (keyBytes.length > 1 && keyBytes[0] === 0x04) {
        info.keySizeBits = ((keyBytes.length - 1) / 2) * 8;
      }
    } else if (algorithmOid === '1.2.840.10040.4.1') {
      info.algorithm = 'DSA';
      const params = algorithmNode?.children[1];
      if (params?.tag === TAG_SEQUENCE && params.children[0]?.tag === TAG_INTEGER) {
        info.keySizeBits = integerBitLength(params.children[0]);
      }
    } else if (algorithmOid === '1.3.101.112') {
      info.algorithm = 'Ed25519';
      info.keySizeBits = 256;
    }
  } catch {
    // A key we cannot decode is reported as unknown rather than failing the scan.
  }

  return info;
}

/** Parses a DER-encoded X.509 certificate. Async only because of the fingerprints. */
export async function parseCertificate(der: Uint8Array): Promise<CertificateInfo> {
  const cert = parseDer(der);
  const tbs = cert.children[0];
  if (!tbs) throw new Error('certificate has no tbsCertificate');

  let index = 0;
  let version = 1;
  if (tbs.children[0]?.tagClass === CLASS_CONTEXT && tbs.children[0].tag === 0) {
    const versionNode = tbs.children[0].children[0];
    version = (versionNode ? (integerToNumber(versionNode) ?? 0) : 0) + 1;
    index = 1;
  }

  const serialNode = tbs.children[index++];
  const sigAlgNode = tbs.children[index++];
  const issuerNode = tbs.children[index++];
  const validityNode = tbs.children[index++];
  const subjectNode = tbs.children[index++];
  const spkiNode = tbs.children[index++];

  const issuer = issuerNode ? parseName(issuerNode) : { text: '', attributes: {} };
  const subject = subjectNode ? parseName(subjectNode) : { text: '', attributes: {} };

  const sigOid =
    sigAlgNode?.children[0]?.tag === TAG_OID ? oidToString(sigAlgNode.children[0]) : '';
  const known = SIGNATURE_ALGORITHMS[sigOid];
  const signatureAlgorithm: SignatureAlgorithmInfo = {
    oid: sigOid,
    name: known?.name ?? (sigOid || 'unknown'),
    hash: known?.hash ?? 'unknown',
    weakHash: known?.weakHash ?? false,
  };

  const [sha256, sha1] = await Promise.all([digest('SHA-256', der), digest('SHA-1', der)]);

  return {
    subject: subject.text,
    issuer: issuer.text,
    subjectAttributes: subject.attributes,
    serialNumberHex: serialNode ? integerToHex(serialNode) : '',
    version,
    notBefore: validityNode?.children[0] ? derTimeToDate(validityNode.children[0]) : null,
    notAfter: validityNode?.children[1] ? derTimeToDate(validityNode.children[1]) : null,
    signatureAlgorithm,
    publicKey: spkiNode ? parsePublicKey(spkiNode) : {
      algorithm: 'unknown',
      algorithmOid: '',
      keySizeBits: null,
      curve: null,
    },
    selfSigned: issuer.text !== '' && issuer.text === subject.text,
    fingerprintSha256: toHex(sha256),
    fingerprintSha1: toHex(sha1),
    der,
  };
}

/** Formats a fingerprint as colon-separated uppercase pairs, like keytool. */
export function formatFingerprint(hex: string): string {
  return (hex.match(/../g) ?? []).join(':').toUpperCase();
}
