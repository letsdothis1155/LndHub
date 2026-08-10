/**
 * Little-endian byte reader plus a few encoding helpers.
 *
 * Everything downstream (ZIP, binary XML, ARSC, DER) is length-prefixed and
 * offset-addressed, so a reader that throws loudly on a short read is the
 * cheapest way to keep a malformed APK from being read as a valid one.
 */

export class ByteReaderError extends Error {}

export class ByteReader {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  offset: number;

  constructor(bytes: Uint8Array, offset = 0) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = offset;
  }

  get length(): number {
    return this.bytes.length;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private need(n: number, at = this.offset): void {
    if (at < 0 || at + n > this.bytes.length) {
      throw new ByteReaderError(
        `read of ${n} byte(s) at ${at} runs past end of buffer (${this.bytes.length})`,
      );
    }
  }

  seek(offset: number): this {
    if (offset < 0 || offset > this.bytes.length) {
      throw new ByteReaderError(`seek to ${offset} outside buffer (${this.bytes.length})`);
    }
    this.offset = offset;
    return this;
  }

  skip(n: number): this {
    return this.seek(this.offset + n);
  }

  u8(): number {
    this.need(1);
    return this.view.getUint8(this.offset++);
  }

  u16(): number {
    this.need(2);
    const v = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }

  i32(): number {
    this.need(4);
    const v = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return v;
  }

  /** Reads a 64-bit LE value, refusing anything past Number.MAX_SAFE_INTEGER. */
  u64(): number {
    const lo = this.u32();
    const hi = this.u32();
    if (hi > 0x1fffff) {
      throw new ByteReaderError(`64-bit value at ${this.offset - 8} exceeds safe integer range`);
    }
    return hi * 0x100000000 + lo;
  }

  /** Big-endian u32 — DER and the APK signing block are big-endian in places. */
  u32be(): number {
    this.need(4);
    const v = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return v;
  }

  peekU16(at: number = this.offset): number {
    this.need(2, at);
    return this.view.getUint16(at, true);
  }

  peekU32(at: number = this.offset): number {
    this.need(4, at);
    return this.view.getUint32(at, true);
  }

  /** Returns a view (not a copy) of the next `n` bytes. */
  take(n: number): Uint8Array {
    this.need(n);
    const out = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  /** Returns a view of an absolute range without moving the cursor. */
  slice(start: number, end: number): Uint8Array {
    if (start < 0 || end > this.bytes.length || end < start) {
      throw new ByteReaderError(`slice [${start}, ${end}) outside buffer (${this.bytes.length})`);
    }
    return this.bytes.subarray(start, end);
  }
}

const utf8Decoder = new TextDecoder('utf-8');
const utf16Decoder = new TextDecoder('utf-16le');

export function decodeUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

export function decodeUtf16le(bytes: Uint8Array): string {
  return utf16Decoder.decode(bytes);
}

export function toHex(bytes: Uint8Array, separator = ''): string {
  const parts: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) parts[i] = bytes[i].toString(16).padStart(2, '0');
  return parts.join(separator);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** SubtleCrypto digest, available in browsers and Node >= 16 via globalThis.crypto. */
export async function digest(
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512',
  bytes: Uint8Array,
): Promise<Uint8Array> {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto (crypto.subtle) is not available in this runtime');
  // Copy into a standalone buffer: subarray views carry the whole parent buffer.
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  const out = await subtle.digest(algorithm, copy);
  return new Uint8Array(out);
}
