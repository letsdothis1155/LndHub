/**
 * DER parser — just enough ASN.1 to walk PKCS#7 and X.509 structures.
 *
 * Strictly DER: indefinite-length encodings are rejected rather than guessed
 * at, since a certificate that only parses under BER is itself a red flag.
 */

import { toHex } from './bytes.js';

export class Asn1Error extends Error {}

export const TAG_BOOLEAN = 0x01;
export const TAG_INTEGER = 0x02;
export const TAG_BIT_STRING = 0x03;
export const TAG_OCTET_STRING = 0x04;
export const TAG_NULL = 0x05;
export const TAG_OID = 0x06;
export const TAG_UTF8_STRING = 0x0c;
export const TAG_SEQUENCE = 0x10;
export const TAG_SET = 0x11;
export const TAG_PRINTABLE_STRING = 0x13;
export const TAG_T61_STRING = 0x14;
export const TAG_IA5_STRING = 0x16;
export const TAG_UTC_TIME = 0x17;
export const TAG_GENERALIZED_TIME = 0x18;
export const TAG_BMP_STRING = 0x1e;

export const CLASS_UNIVERSAL = 0;
export const CLASS_APPLICATION = 1;
export const CLASS_CONTEXT = 2;
export const CLASS_PRIVATE = 3;

export interface Asn1Node {
  tagClass: number;
  constructed: boolean;
  tag: number;
  /** Offset of the identifier octet within the source buffer. */
  start: number;
  /** Offset just past the value. */
  end: number;
  contentStart: number;
  contentEnd: number;
  content: Uint8Array;
  /** Full TLV bytes, needed when re-hashing a certificate. */
  raw: Uint8Array;
  children: Asn1Node[];
}

function parseLength(bytes: Uint8Array, offset: number): { length: number; next: number } {
  if (offset >= bytes.length) throw new Asn1Error('truncated length octet');
  const first = bytes[offset];
  if (first < 0x80) return { length: first, next: offset + 1 };
  if (first === 0x80) throw new Asn1Error('indefinite-length encoding is not valid DER');
  const count = first & 0x7f;
  if (count > 4) throw new Asn1Error(`length field of ${count} octets is unsupported`);
  if (offset + 1 + count > bytes.length) throw new Asn1Error('truncated long-form length');
  let length = 0;
  for (let i = 0; i < count; i++) length = length * 256 + bytes[offset + 1 + i];
  return { length, next: offset + 1 + count };
}

/** Parses one TLV at `offset`, recursing into constructed values. */
export function parseDer(bytes: Uint8Array, offset = 0, depth = 0): Asn1Node {
  if (depth > 32) throw new Asn1Error('ASN.1 nesting too deep');
  if (offset >= bytes.length) throw new Asn1Error(`no TLV at offset ${offset}`);

  const identifier = bytes[offset];
  const tagClass = (identifier >> 6) & 0x3;
  const constructed = (identifier & 0x20) !== 0;
  let tag = identifier & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (;;) {
      if (p >= bytes.length) throw new Asn1Error('truncated high-tag-number form');
      const b = bytes[p++];
      tag = (tag << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }

  const { length, next } = parseLength(bytes, p);
  const contentStart = next;
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) {
    throw new Asn1Error(`TLV at ${offset} declares ${length} bytes but only ${bytes.length - contentStart} remain`);
  }

  const node: Asn1Node = {
    tagClass,
    constructed,
    tag,
    start: offset,
    end: contentEnd,
    contentStart,
    contentEnd,
    content: bytes.subarray(contentStart, contentEnd),
    raw: bytes.subarray(offset, contentEnd),
    children: [],
  };

  if (constructed) {
    let child = contentStart;
    while (child < contentEnd) {
      const parsed = parseDer(bytes, child, depth + 1);
      node.children.push(parsed);
      if (parsed.end <= child) throw new Asn1Error('zero-length TLV would loop');
      child = parsed.end;
    }
  }

  return node;
}

/** Parses a run of concatenated TLVs, as found in a SignedData certificates set. */
export function parseDerSequenceOf(bytes: Uint8Array): Asn1Node[] {
  const nodes: Asn1Node[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const node = parseDer(bytes, offset);
    nodes.push(node);
    offset = node.end;
  }
  return nodes;
}

export function isSequence(node: Asn1Node): boolean {
  return node.tagClass === CLASS_UNIVERSAL && node.tag === TAG_SEQUENCE;
}

export function isContext(node: Asn1Node, tag: number): boolean {
  return node.tagClass === CLASS_CONTEXT && node.tag === tag;
}

/** Decodes an OBJECT IDENTIFIER to dotted-decimal form. */
export function oidToString(node: Asn1Node): string {
  const b = node.content;
  if (b.length === 0) return '';
  const parts: number[] = [];
  const first = b[0];
  parts.push(Math.floor(first / 40), first % 40);
  let value = 0;
  for (let i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Reads an INTEGER as a JS number, or null when it does not fit safely. */
export function integerToNumber(node: Asn1Node): number | null {
  const b = node.content;
  if (b.length === 0 || b.length > 7) return null;
  let value = 0;
  const negative = (b[0] & 0x80) !== 0;
  for (const byte of b) value = value * 256 + (negative ? byte ^ 0xff : byte);
  return negative ? -(value + 1) : value;
}

/** Renders an INTEGER as an uppercase hex string, the usual form for serials. */
export function integerToHex(node: Asn1Node): string {
  let b = node.content;
  let i = 0;
  while (i < b.length - 1 && b[i] === 0x00) i++; // strip DER sign padding
  b = b.subarray(i);
  return toHex(b).toUpperCase();
}

/** Bit length of a non-negative INTEGER — used for RSA modulus sizes. */
export function integerBitLength(node: Asn1Node): number {
  let b = node.content;
  let i = 0;
  while (i < b.length && b[i] === 0x00) i++;
  b = b.subarray(i);
  if (b.length === 0) return 0;
  return (b.length - 1) * 8 + (32 - Math.clz32(b[0]));
}

const TEXT_TAGS = new Set([
  TAG_UTF8_STRING,
  TAG_PRINTABLE_STRING,
  TAG_T61_STRING,
  TAG_IA5_STRING,
  TAG_UTC_TIME,
  TAG_GENERALIZED_TIME,
]);

/** Decodes a DirectoryString-ish value, handling BMPString's UTF-16BE. */
export function derStringToText(node: Asn1Node): string {
  if (node.tag === TAG_BMP_STRING) {
    let out = '';
    for (let i = 0; i + 1 < node.content.length; i += 2) {
      out += String.fromCharCode((node.content[i] << 8) | node.content[i + 1]);
    }
    return out;
  }
  if (TEXT_TAGS.has(node.tag)) return new TextDecoder('utf-8').decode(node.content);
  return toHex(node.content);
}

/** Parses UTCTime / GeneralizedTime into a Date. */
export function derTimeToDate(node: Asn1Node): Date | null {
  const text = new TextDecoder('utf-8').decode(node.content).trim();
  const m =
    node.tag === TAG_UTC_TIME
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/.exec(text)
      : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z?$/.exec(text);
  if (!m) return null;
  let year = Number(m[1]);
  if (node.tag === TAG_UTC_TIME) year += year < 50 ? 2000 : 1900;
  const date = new Date(
    Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? '0')),
  );
  return Number.isNaN(date.getTime()) ? null : date;
}
