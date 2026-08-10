/**
 * Raw DEFLATE (RFC 1951) decompressor.
 *
 * The runtime's DecompressionStream('deflate-raw') is faster but async and not
 * universally available (Safari < 16.4, older Node). Safe Extract needs a
 * synchronous, dependency-free path it can trust, so this is a direct port of
 * the canonical "puff" algorithm: bit-at-a-time Huffman walking, no lookup
 * tables to get subtly wrong.
 */

const LENGTH_BASE = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258,
];
const LENGTH_EXTRA = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

export class InflateError extends Error {}

interface Huffman {
  /** counts[n] = number of symbols with code length n */
  counts: Int32Array;
  /** symbols sorted by code length, then by symbol value */
  symbols: Int32Array;
}

function buildHuffman(lengths: Uint8Array, n: number): Huffman {
  const counts = new Int32Array(16);
  for (let i = 0; i < n; i++) counts[lengths[i]]++;
  if (counts[0] === n) return { counts, symbols: new Int32Array(0) };

  // Reject over-subscribed code sets; incomplete sets are legal only for a
  // single-symbol distance tree, which decode() catches naturally.
  let left = 1;
  for (let len = 1; len <= 15; len++) {
    left <<= 1;
    left -= counts[len];
    if (left < 0) throw new InflateError('over-subscribed Huffman code');
  }

  const offsets = new Int32Array(16);
  for (let len = 1; len < 15; len++) offsets[len + 1] = offsets[len] + counts[len];

  const symbols = new Int32Array(n);
  for (let symbol = 0; symbol < n; symbol++) {
    if (lengths[symbol] !== 0) symbols[offsets[lengths[symbol]]++] = symbol;
  }
  return { counts, symbols };
}

class State {
  readonly src: Uint8Array;
  pos = 0;
  bitBuf = 0;
  bitCnt = 0;
  out: Uint8Array;
  outLen = 0;

  constructor(src: Uint8Array, initialCapacity: number) {
    this.src = src;
    this.out = new Uint8Array(Math.max(1024, initialCapacity));
  }

  bits(need: number): number {
    let val = this.bitBuf;
    while (this.bitCnt < need) {
      if (this.pos >= this.src.length) throw new InflateError('unexpected end of deflate stream');
      val |= this.src[this.pos++] << this.bitCnt;
      this.bitCnt += 8;
    }
    this.bitBuf = val >>> need;
    this.bitCnt -= need;
    return val & ((1 << need) - 1);
  }

  ensure(extra: number): void {
    const needed = this.outLen + extra;
    if (needed <= this.out.length) return;
    let cap = this.out.length * 2;
    while (cap < needed) cap *= 2;
    const grown = new Uint8Array(cap);
    grown.set(this.out.subarray(0, this.outLen));
    this.out = grown;
  }

  push(byte: number): void {
    this.ensure(1);
    this.out[this.outLen++] = byte;
  }
}

function decodeSymbol(s: State, h: Huffman): number {
  let code = 0;
  let first = 0;
  let index = 0;
  for (let len = 1; len <= 15; len++) {
    code |= s.bits(1);
    const count = h.counts[len];
    if (code - first < count) return h.symbols[index + (code - first)];
    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }
  throw new InflateError('invalid Huffman code');
}

function inflateStored(s: State): void {
  // Discard the partial bit buffer; whole buffered bytes must be un-read.
  s.pos -= s.bitCnt >> 3;
  s.bitBuf = 0;
  s.bitCnt = 0;

  if (s.pos + 4 > s.src.length) throw new InflateError('truncated stored block header');
  const len = s.src[s.pos] | (s.src[s.pos + 1] << 8);
  const nlen = s.src[s.pos + 2] | (s.src[s.pos + 3] << 8);
  s.pos += 4;
  if ((len ^ 0xffff) !== nlen) throw new InflateError('stored block length check failed');
  if (s.pos + len > s.src.length) throw new InflateError('truncated stored block');

  s.ensure(len);
  s.out.set(s.src.subarray(s.pos, s.pos + len), s.outLen);
  s.outLen += len;
  s.pos += len;
}

function inflateCodes(s: State, lenCode: Huffman, distCode: Huffman): void {
  for (;;) {
    const symbol = decodeSymbol(s, lenCode);
    if (symbol < 256) {
      s.push(symbol);
      continue;
    }
    if (symbol === 256) return;

    const lenIndex = symbol - 257;
    if (lenIndex >= LENGTH_BASE.length) throw new InflateError(`invalid length symbol ${symbol}`);
    const length = LENGTH_BASE[lenIndex] + s.bits(LENGTH_EXTRA[lenIndex]);

    const distSymbol = decodeSymbol(s, distCode);
    if (distSymbol >= DIST_BASE.length) {
      throw new InflateError(`invalid distance symbol ${distSymbol}`);
    }
    const distance = DIST_BASE[distSymbol] + s.bits(DIST_EXTRA[distSymbol]);
    if (distance > s.outLen) throw new InflateError('distance points before start of output');

    s.ensure(length);
    let from = s.outLen - distance;
    for (let i = 0; i < length; i++) s.out[s.outLen++] = s.out[from++];
  }
}

let fixedTables: { lenCode: Huffman; distCode: Huffman } | null = null;

function getFixedTables(): { lenCode: Huffman; distCode: Huffman } {
  if (fixedTables) return fixedTables;
  const lengths = new Uint8Array(288);
  lengths.fill(8, 0, 144);
  lengths.fill(9, 144, 256);
  lengths.fill(7, 256, 280);
  lengths.fill(8, 280, 288);
  const distLengths = new Uint8Array(30).fill(5);
  fixedTables = {
    lenCode: buildHuffman(lengths, 288),
    distCode: buildHuffman(distLengths, 30),
  };
  return fixedTables;
}

function inflateDynamic(s: State): void {
  const nlen = s.bits(5) + 257;
  const ndist = s.bits(5) + 1;
  const ncode = s.bits(4) + 4;
  if (nlen > 286 || ndist > 30) throw new InflateError('too many length or distance codes');

  const codeLengths = new Uint8Array(19);
  for (let i = 0; i < ncode; i++) codeLengths[CODE_LENGTH_ORDER[i]] = s.bits(3);
  const lengthCode = buildHuffman(codeLengths, 19);

  const lengths = new Uint8Array(nlen + ndist);
  let index = 0;
  while (index < nlen + ndist) {
    const symbol = decodeSymbol(s, lengthCode);
    if (symbol < 16) {
      lengths[index++] = symbol;
      continue;
    }
    let repeatValue = 0;
    let repeat: number;
    if (symbol === 16) {
      if (index === 0) throw new InflateError('repeat with no previous code length');
      repeatValue = lengths[index - 1];
      repeat = 3 + s.bits(2);
    } else if (symbol === 17) {
      repeat = 3 + s.bits(3);
    } else {
      repeat = 11 + s.bits(7);
    }
    if (index + repeat > nlen + ndist) throw new InflateError('code length repeat overflows');
    while (repeat-- > 0) lengths[index++] = repeatValue;
  }
  if (lengths[256] === 0) throw new InflateError('missing end-of-block code');

  const lenCode = buildHuffman(lengths.subarray(0, nlen), nlen);
  const distCode = buildHuffman(lengths.subarray(nlen), ndist);
  inflateCodes(s, lenCode, distCode);
}

/**
 * Inflates a raw DEFLATE stream.
 *
 * @param expectedSize hint used to pre-size the output buffer; not enforced.
 */
export function inflateRaw(src: Uint8Array, expectedSize?: number): Uint8Array {
  const s = new State(src, expectedSize ?? src.length * 4);
  let last = 0;
  do {
    last = s.bits(1);
    const type = s.bits(2);
    if (type === 0) inflateStored(s);
    else if (type === 1) {
      const { lenCode, distCode } = getFixedTables();
      inflateCodes(s, lenCode, distCode);
    } else if (type === 2) inflateDynamic(s);
    else throw new InflateError('invalid block type 3');
  } while (!last);

  return s.out.subarray(0, s.outLen);
}
