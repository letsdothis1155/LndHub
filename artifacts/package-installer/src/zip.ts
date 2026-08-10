/**
 * ZIP central-directory reader tuned for APKs.
 *
 * Deliberately central-directory-driven: local file headers are treated as
 * untrusted, because a mismatch between the two is the basis of several APK
 * masquerading tricks. Entry names are checked for traversal before any caller
 * gets a chance to write them to disk.
 */

import { ByteReader, decodeUtf8, toHex } from './bytes.js';
import { inflateRaw } from './inflate.js';

export class ZipError extends Error {}

const SIG_LOCAL_HEADER = 0x04034b50;
const SIG_CENTRAL_HEADER = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;

export const COMPRESSION_STORED = 0;
export const COMPRESSION_DEFLATE = 8;

export interface ZipEntry {
  name: string;
  /** Raw name bytes, kept so callers can detect non-UTF-8 or control characters. */
  nameBytes: Uint8Array;
  compressionMethod: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
  generalPurposeFlags: number;
  externalAttributes: number;
  isDirectory: boolean;
  /** DOS timestamp decoded to a local-time Date, or null when unset/invalid. */
  lastModified: Date | null;
  comment: string;
}

let crcTable: Int32Array | null = null;

function getCrcTable(): Int32Array {
  if (crcTable) return crcTable;
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c;
  }
  crcTable = table;
  return table;
}

export function crc32(bytes: Uint8Array): number {
  const table = getCrcTable();
  let c = -1;
  for (let i = 0; i < bytes.length; i++) c = table[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function decodeDosTime(dosTime: number, dosDate: number): Date | null {
  if (dosDate === 0 && dosTime === 0) return null;
  const year = 1980 + ((dosDate >> 9) & 0x7f);
  const month = (dosDate >> 5) & 0x0f;
  const day = dosDate & 0x1f;
  const hours = (dosTime >> 11) & 0x1f;
  const minutes = (dosTime >> 5) & 0x3f;
  const seconds = (dosTime & 0x1f) * 2;
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  return new Date(year, month - 1, day, hours, minutes, seconds);
}

/** Reads ZIP64 extended-information from the extra field when a size is 0xFFFFFFFF. */
function applyZip64Extra(
  extra: Uint8Array,
  entry: { uncompressedSize: number; compressedSize: number; localHeaderOffset: number },
): void {
  const r = new ByteReader(extra);
  while (r.remaining >= 4) {
    const headerId = r.u16();
    const size = r.u16();
    if (r.remaining < size) return;
    const end = r.offset + size;
    if (headerId === 0x0001) {
      if (entry.uncompressedSize === 0xffffffff && end - r.offset >= 8) {
        entry.uncompressedSize = r.u64();
      }
      if (entry.compressedSize === 0xffffffff && end - r.offset >= 8) {
        entry.compressedSize = r.u64();
      }
      if (entry.localHeaderOffset === 0xffffffff && end - r.offset >= 8) {
        entry.localHeaderOffset = r.u64();
      }
      return;
    }
    r.seek(end);
  }
}

export interface ZipReadOptions {
  /** Verify the CRC-32 of the decompressed bytes (default true). */
  verifyCrc?: boolean;
  /** Refuse entries whose declared uncompressed size exceeds this (default 512 MiB). */
  maxUncompressedSize?: number;
}

const DEFAULT_MAX_ENTRY_SIZE = 512 * 1024 * 1024;

export class ZipArchive {
  readonly bytes: Uint8Array;
  readonly entries: ZipEntry[];
  readonly centralDirectoryOffset: number;
  readonly centralDirectorySize: number;
  readonly comment: string;

  private readonly byName: Map<string, ZipEntry>;

  private constructor(
    bytes: Uint8Array,
    entries: ZipEntry[],
    centralDirectoryOffset: number,
    centralDirectorySize: number,
    comment: string,
  ) {
    this.bytes = bytes;
    this.entries = entries;
    this.centralDirectoryOffset = centralDirectoryOffset;
    this.centralDirectorySize = centralDirectorySize;
    this.comment = comment;
    this.byName = new Map();
    // First occurrence wins; duplicates are surfaced separately as a finding.
    for (const entry of entries) if (!this.byName.has(entry.name)) this.byName.set(entry.name, entry);
  }

  static parse(bytes: Uint8Array): ZipArchive {
    const eocdOffset = findEocd(bytes);
    const r = new ByteReader(bytes, eocdOffset + 4);
    r.u16(); // disk number
    r.u16(); // disk with central directory
    r.u16(); // entries on this disk
    let entryCount = r.u16();
    let cdSize = r.u32();
    let cdOffset = r.u32();
    const commentLength = r.u16();
    const comment = commentLength > 0 ? decodeUtf8(r.take(Math.min(commentLength, r.remaining))) : '';

    if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const zip64 = findZip64Eocd(bytes, eocdOffset);
      if (zip64) {
        entryCount = zip64.entryCount;
        cdSize = zip64.centralDirectorySize;
        cdOffset = zip64.centralDirectoryOffset;
      }
    }

    if (cdOffset + cdSize > bytes.length) {
      throw new ZipError('central directory extends past end of file');
    }

    const cd = new ByteReader(bytes, cdOffset);
    const entries: ZipEntry[] = [];
    for (let i = 0; i < entryCount; i++) {
      if (cd.remaining < 46 || cd.peekU32() !== SIG_CENTRAL_HEADER) {
        throw new ZipError(`central directory record ${i} has a bad signature`);
      }
      cd.skip(4);
      cd.u16(); // version made by
      cd.u16(); // version needed
      const flags = cd.u16();
      const method = cd.u16();
      const dosTime = cd.u16();
      const dosDate = cd.u16();
      const crc = cd.u32();
      const compressedSize = cd.u32();
      const uncompressedSize = cd.u32();
      const nameLength = cd.u16();
      const extraLength = cd.u16();
      const entryCommentLength = cd.u16();
      cd.u16(); // disk number start
      cd.u16(); // internal attributes
      const externalAttributes = cd.u32();
      const localHeaderOffset = cd.u32();
      const nameBytes = cd.take(nameLength);
      const extra = cd.take(extraLength);
      const entryComment = entryCommentLength > 0 ? decodeUtf8(cd.take(entryCommentLength)) : '';

      const sizes = { uncompressedSize, compressedSize, localHeaderOffset };
      if (
        uncompressedSize === 0xffffffff ||
        compressedSize === 0xffffffff ||
        localHeaderOffset === 0xffffffff
      ) {
        applyZip64Extra(extra, sizes);
      }

      const name = decodeUtf8(nameBytes);
      entries.push({
        name,
        nameBytes,
        compressionMethod: method,
        crc32: crc,
        compressedSize: sizes.compressedSize,
        uncompressedSize: sizes.uncompressedSize,
        localHeaderOffset: sizes.localHeaderOffset,
        generalPurposeFlags: flags,
        externalAttributes,
        isDirectory: name.endsWith('/'),
        lastModified: decodeDosTime(dosTime, dosDate),
        comment: entryComment,
      });
    }

    return new ZipArchive(bytes, entries, cdOffset, cdSize, comment);
  }

  get(name: string): ZipEntry | undefined {
    return this.byName.get(name);
  }

  has(name: string): boolean {
    return this.byName.has(name);
  }

  /** Entry names appearing more than once — a classic masquerading signal. */
  duplicateNames(): string[] {
    const seen = new Set<string>();
    const duplicates = new Set<string>();
    for (const entry of this.entries) {
      if (seen.has(entry.name)) duplicates.add(entry.name);
      seen.add(entry.name);
    }
    return [...duplicates];
  }

  /** Decompresses an entry, validating the local header against the directory. */
  read(entry: ZipEntry, options: ZipReadOptions = {}): Uint8Array {
    const maxSize = options.maxUncompressedSize ?? DEFAULT_MAX_ENTRY_SIZE;
    if (entry.uncompressedSize > maxSize) {
      throw new ZipError(
        `entry "${entry.name}" declares ${entry.uncompressedSize} bytes, over the ${maxSize} byte limit`,
      );
    }

    const r = new ByteReader(this.bytes, entry.localHeaderOffset);
    if (r.remaining < 30 || r.u32() !== SIG_LOCAL_HEADER) {
      throw new ZipError(`entry "${entry.name}" has no local file header at ${entry.localHeaderOffset}`);
    }
    r.skip(2 + 2 + 2 + 2 + 2 + 4 + 4 + 4); // version..sizes, all re-read from the directory
    const nameLength = r.u16();
    const extraLength = r.u16();
    const dataStart = entry.localHeaderOffset + 30 + nameLength + extraLength;
    if (dataStart + entry.compressedSize > this.bytes.length) {
      throw new ZipError(`entry "${entry.name}" data extends past end of file`);
    }

    const raw = this.bytes.subarray(dataStart, dataStart + entry.compressedSize);
    let out: Uint8Array;
    if (entry.compressionMethod === COMPRESSION_STORED) {
      out = raw;
    } else if (entry.compressionMethod === COMPRESSION_DEFLATE) {
      out = inflateRaw(raw, entry.uncompressedSize);
    } else {
      throw new ZipError(
        `entry "${entry.name}" uses unsupported compression method ${entry.compressionMethod}`,
      );
    }

    if (out.length > maxSize) {
      throw new ZipError(`entry "${entry.name}" inflated to ${out.length} bytes, over the limit`);
    }
    if (entry.uncompressedSize !== 0 && out.length !== entry.uncompressedSize) {
      throw new ZipError(
        `entry "${entry.name}" inflated to ${out.length} bytes but the directory declares ${entry.uncompressedSize}`,
      );
    }
    if (options.verifyCrc !== false) {
      const actual = crc32(out);
      if (actual !== entry.crc32) {
        throw new ZipError(
          `entry "${entry.name}" CRC mismatch: expected ${toHex(u32ToBytes(entry.crc32))}, got ${toHex(u32ToBytes(actual))}`,
        );
      }
    }
    return out;
  }

  readByName(name: string, options?: ZipReadOptions): Uint8Array | null {
    const entry = this.get(name);
    return entry ? this.read(entry, options) : null;
  }
}

function u32ToBytes(value: number): Uint8Array {
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function findEocd(bytes: Uint8Array): number {
  // EOCD is 22 bytes plus a comment of at most 65535 bytes.
  const minOffset = Math.max(0, bytes.length - (22 + 0xffff));
  for (let i = bytes.length - 22; i >= minOffset; i--) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      return i;
    }
  }
  throw new ZipError('end of central directory record not found — not a ZIP/APK file');
}

function findZip64Eocd(
  bytes: Uint8Array,
  eocdOffset: number,
): { entryCount: number; centralDirectorySize: number; centralDirectoryOffset: number } | null {
  const locatorOffset = eocdOffset - 20;
  if (locatorOffset < 0) return null;
  const locator = new ByteReader(bytes, locatorOffset);
  if (locator.u32() !== SIG_ZIP64_EOCD_LOCATOR) return null;
  locator.u32(); // disk with zip64 EOCD
  const zip64Offset = locator.u64();
  if (zip64Offset + 56 > bytes.length) return null;

  const r = new ByteReader(bytes, zip64Offset);
  if (r.u32() !== SIG_ZIP64_EOCD) return null;
  r.u64(); // size of zip64 EOCD record
  r.u16(); // version made by
  r.u16(); // version needed
  r.u32(); // this disk
  r.u32(); // disk with central directory
  r.u64(); // entries on this disk
  const entryCount = r.u64();
  const centralDirectorySize = r.u64();
  const centralDirectoryOffset = r.u64();
  return { entryCount, centralDirectorySize, centralDirectoryOffset };
}

export interface UnsafePathReason {
  name: string;
  reason: string;
}

/**
 * Classifies an entry name for extraction safety.
 *
 * Returns null when the name is safe to join onto a destination directory.
 */
export function checkEntryPath(name: string, nameBytes?: Uint8Array): UnsafePathReason | null {
  if (name.length === 0) return { name, reason: 'empty entry name' };
  if (name.length > 1024) return { name, reason: 'entry name longer than 1024 characters' };
  if (name.startsWith('/') || name.startsWith('\\')) {
    return { name, reason: 'absolute path' };
  }
  if (/^[a-zA-Z]:[\\/]/.test(name)) return { name, reason: 'Windows drive-letter path' };
  if (name.includes('\\')) return { name, reason: 'backslash in path separator position' };
  if (name.includes('\0')) return { name, reason: 'NUL byte in entry name' };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    return { name, reason: 'control character in entry name' };
  }
  for (const segment of name.split('/')) {
    if (segment === '..') return { name, reason: 'parent-directory traversal ("..")' };
  }
  if (nameBytes) {
    // A name that does not round-trip through UTF-8 can decode differently in
    // the extractor than it did here.
    const reencoded = new TextEncoder().encode(name);
    if (reencoded.length !== nameBytes.length) {
      return { name, reason: 'entry name is not valid UTF-8' };
    }
  }
  return null;
}
