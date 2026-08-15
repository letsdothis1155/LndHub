/**
 * QR Code encoder (ISO/IEC 18004), byte mode, versions 1-40.
 *
 * Dependency-free on purpose: the rest of this library needs no runtime
 * packages, and a sideload QR that cannot render without pulling in an external
 * encoder would undo that. Callers who already have an encoder can still swap
 * this out through the `QrEncoder` interface.
 *
 * Structure follows the reference algorithm: build the bit stream, split into
 * blocks, append Reed-Solomon parity over GF(256) with the QR primitive
 * polynomial 0x11D, interleave, lay out the matrix, then pick the mask with the
 * lowest penalty.
 */

export type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';

/** Format-info bit patterns; note this is not the L < M < Q < H ordering. */
const EC_FORMAT_BITS: Record<ErrorCorrectionLevel, number> = { L: 1, M: 0, Q: 3, H: 2 };
const EC_ORDER: ErrorCorrectionLevel[] = ['L', 'M', 'Q', 'H'];

export class QrError extends Error {}

/**
 * Error-correction codewords per block, indexed [ecLevel][version].
 * Index 0 of each row is unused padding.
 */
const ECC_CODEWORDS_PER_BLOCK: Record<ErrorCorrectionLevel, number[]> = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};

/** Error-correction blocks, indexed [ecLevel][version]. */
const NUM_ERROR_CORRECTION_BLOCKS: Record<ErrorCorrectionLevel, number[]> = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [-1, 1, 1, 2, 4, 4, 4, 5, 5, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};

const MIN_VERSION = 1;
const MAX_VERSION = 40;

const PENALTY_N1 = 3;
const PENALTY_N2 = 3;
const PENALTY_N3 = 40;
const PENALTY_N4 = 10;

export interface QrCode {
  version: number;
  /** Width and height in modules, `version * 4 + 17`. */
  size: number;
  errorCorrectionLevel: ErrorCorrectionLevel;
  mask: number;
  /** `modules[y][x]`, true meaning dark. */
  modules: boolean[][];
}

/** Lets a caller substitute their own encoder. */
export interface QrEncoder {
  encode(text: string, options?: EncodeQrOptions): QrCode;
}

export interface EncodeQrOptions {
  errorCorrectionLevel?: ErrorCorrectionLevel;
  minVersion?: number;
  maxVersion?: number;
  /** Force a mask (0-7) instead of choosing the lowest-penalty one. */
  mask?: number;
  /**
   * Raise the error-correction level for free when the chosen version has room.
   * On by default, matching the reference encoder.
   */
  boostEcc?: boolean;
}

/** Total data modules for a version, before error correction. */
function getNumRawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

/** Data codewords available at a version and EC level. */
function getNumDataCodewords(version: number, ecl: ErrorCorrectionLevel): number {
  return (
    Math.floor(getNumRawDataModules(version) / 8) -
    ECC_CODEWORDS_PER_BLOCK[ecl][version] * NUM_ERROR_CORRECTION_BLOCKS[ecl][version]
  );
}

/** Character-count indicator width for byte mode. */
function byteModeCountBits(version: number): number {
  return version <= 9 ? 8 : 16;
}

function multiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

/** Generator polynomial coefficients for the given number of parity bytes. */
function reedSolomonComputeDivisor(degree: number): Uint8Array {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = multiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = multiply(root, 0x02);
  }
  return result;
}

function reedSolomonComputeRemainder(data: Uint8Array, divisor: Uint8Array): Uint8Array {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) result[i] ^= multiply(divisor[i], factor);
  }
  return result;
}

/** Splits data into blocks, appends parity, and interleaves per the spec. */
function addEccAndInterleave(
  data: Uint8Array,
  version: number,
  ecl: ErrorCorrectionLevel,
): Uint8Array {
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecl][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecl][version];
  const rawCodewords = Math.floor(getNumRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const divisor = reedSolomonComputeDivisor(blockEccLen);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dataLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const chunk = data.subarray(k, k + dataLen);
    k += dataLen;
    const ecc = reedSolomonComputeRemainder(chunk, divisor);
    const block = [...chunk];
    // Short blocks carry a placeholder so the interleave loop stays uniform;
    // it is skipped when emitting.
    if (i < numShortBlocks) block.push(0);
    blocks.push([...block, ...ecc]);
  }

  const result: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result.push(blocks[j][i]);
    }
  }
  return Uint8Array.from(result);
}

function getAlignmentPatternPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

class Matrix {
  readonly size: number;
  readonly modules: boolean[][];
  readonly isFunction: boolean[][];

  constructor(size: number) {
    this.size = size;
    this.modules = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.isFunction = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }

  setFunction(x: number, y: number, dark: boolean): void {
    if (x < 0 || y < 0 || x >= this.size || y >= this.size) return;
    this.modules[y][x] = dark;
    this.isFunction[y][x] = true;
  }
}

function drawFinderPattern(m: Matrix, x: number, y: number): void {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      m.setFunction(x + dx, y + dy, dist !== 2 && dist !== 4);
    }
  }
}

function drawAlignmentPattern(m: Matrix, x: number, y: number): void {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      m.setFunction(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
}

function drawFormatBits(m: Matrix, ecl: ErrorCorrectionLevel, mask: number): void {
  const data = (EC_FORMAT_BITS[ecl] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i: number): boolean => ((bits >>> i) & 1) !== 0;

  // Copy near the top-left finder.
  for (let i = 0; i <= 5; i++) m.setFunction(8, i, bit(i));
  m.setFunction(8, 7, bit(6));
  m.setFunction(8, 8, bit(7));
  m.setFunction(7, 8, bit(8));
  for (let i = 9; i < 15; i++) m.setFunction(14 - i, 8, bit(i));

  // Second copy, split across the other two finders.
  for (let i = 0; i < 8; i++) m.setFunction(m.size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) m.setFunction(8, m.size - 15 + i, bit(i));
  m.setFunction(8, m.size - 8, true); // the always-dark module
}

function drawVersionBits(m: Matrix, version: number): void {
  if (version < 7) return;
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  const bits = (version << 12) | rem;

  for (let i = 0; i < 18; i++) {
    const dark = ((bits >>> i) & 1) !== 0;
    const a = m.size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    m.setFunction(a, b, dark);
    m.setFunction(b, a, dark);
  }
}

function drawFunctionPatterns(m: Matrix, version: number, ecl: ErrorCorrectionLevel): void {
  // Timing patterns.
  for (let i = 0; i < m.size; i++) {
    m.setFunction(6, i, i % 2 === 0);
    m.setFunction(i, 6, i % 2 === 0);
  }

  drawFinderPattern(m, 3, 3);
  drawFinderPattern(m, m.size - 4, 3);
  drawFinderPattern(m, 3, m.size - 4);

  const positions = getAlignmentPatternPositions(version);
  for (let i = 0; i < positions.length; i++) {
    for (let j = 0; j < positions.length; j++) {
      // Skip the three corners, which the finder patterns already occupy.
      const corner =
        (i === 0 && j === 0) ||
        (i === 0 && j === positions.length - 1) ||
        (i === positions.length - 1 && j === 0);
      if (!corner) drawAlignmentPattern(m, positions[i], positions[j]);
    }
  }

  drawFormatBits(m, ecl, 0); // rewritten once the mask is chosen
  drawVersionBits(m, version);
}

/** Lays codewords into the matrix in the spec's upward/downward zigzag. */
function drawCodewords(m: Matrix, data: Uint8Array): void {
  let i = 0;
  for (let right = m.size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // the vertical timing pattern is skipped
    for (let vert = 0; vert < m.size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? m.size - 1 - vert : vert;
        if (!m.isFunction[y][x] && i < data.length * 8) {
          m.modules[y][x] = ((data[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
          i++;
        }
      }
    }
  }
}

function maskCondition(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      throw new QrError(`mask ${mask} is out of range (0-7)`);
  }
}

function applyMask(m: Matrix, mask: number): void {
  for (let y = 0; y < m.size; y++) {
    for (let x = 0; x < m.size; x++) {
      if (!m.isFunction[y][x] && maskCondition(mask, x, y)) m.modules[y][x] = !m.modules[y][x];
    }
  }
}

/** Counts 1:1:3:1:1 finder-like patterns with a 4-module light margin. */
function countFinderLike(line: boolean[]): number {
  const pattern = [true, false, true, true, true, false, true];
  let count = 0;
  for (let i = 0; i + 7 <= line.length; i++) {
    let matches = true;
    for (let j = 0; j < 7; j++) {
      if (line[i + j] !== pattern[j]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    const lightBefore = i >= 4 && line.slice(i - 4, i).every((v) => !v);
    const lightAfter =
      i + 11 <= line.length && line.slice(i + 7, i + 11).every((v) => !v);
    if (lightBefore || lightAfter) count++;
  }
  return count;
}

/**
 * The spec's four mask-penalty rules. Exported so tests can compare mask
 * selection against a reference implementation.
 */
export function qrPenaltyScore(modules: boolean[][]): number {
  let result = 0;
  const size = modules.length;

  const scoreLine = (line: boolean[]): number => {
    let score = 0;
    let runColor = line[0];
    let runLength = 1;
    for (let i = 1; i < line.length; i++) {
      if (line[i] === runColor) {
        runLength++;
      } else {
        if (runLength >= 5) score += PENALTY_N1 + (runLength - 5);
        runColor = line[i];
        runLength = 1;
      }
    }
    if (runLength >= 5) score += PENALTY_N1 + (runLength - 5);
    return score + countFinderLike(line) * PENALTY_N3;
  };

  for (let y = 0; y < size; y++) result += scoreLine(modules[y]);
  for (let x = 0; x < size; x++) {
    result += scoreLine(modules.map((row) => row[x]));
  }

  // Rule 2: same-coloured 2x2 blocks.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) {
        result += PENALTY_N2;
      }
    }
  }

  // Rule 4, stated as the spec does: take the multiples of five either side of
  // the dark-module percentage, subtract 50 from each, and use the smaller
  // absolute value divided by five. The commonly seen
  // `ceil(|dark*20 - total*10| / total) - 1` shortcut agrees everywhere except
  // when the percentage lands exactly on a multiple of five.
  let dark = 0;
  for (const row of modules) for (const cell of row) if (cell) dark++;
  const total = size * size;
  const percent = (dark * 100) / total;
  const lower = Math.floor(percent / 5) * 5;
  const upper = Math.ceil(percent / 5) * 5;
  const k = Math.min(Math.abs(lower - 50), Math.abs(upper - 50)) / 5;
  return result + k * PENALTY_N4;
}

/** Encodes text as a QR code, choosing the smallest version that fits. */
export function encodeQr(text: string, options: EncodeQrOptions = {}): QrCode {
  const {
    errorCorrectionLevel = 'M',
    minVersion = MIN_VERSION,
    maxVersion = MAX_VERSION,
    mask: forcedMask,
    boostEcc = true,
  } = options;

  if (minVersion < MIN_VERSION || maxVersion > MAX_VERSION || minVersion > maxVersion) {
    throw new QrError(`version range ${minVersion}-${maxVersion} is invalid`);
  }
  if (forcedMask !== undefined && (forcedMask < 0 || forcedMask > 7)) {
    throw new QrError(`mask ${forcedMask} is out of range (0-7)`);
  }

  const data = new TextEncoder().encode(text);

  let version = minVersion;
  for (; ; version++) {
    if (version > maxVersion) {
      throw new QrError(
        `${data.length} bytes do not fit in a version-${maxVersion} code at level ${errorCorrectionLevel}`,
      );
    }
    const capacityBits = getNumDataCodewords(version, errorCorrectionLevel) * 8;
    const usedBits = 4 + byteModeCountBits(version) + data.length * 8;
    if (usedBits <= capacityBits) break;
  }

  // Spend leftover capacity on stronger error correction where it is free.
  let ecl = errorCorrectionLevel;
  if (boostEcc) {
    const usedBits = 4 + byteModeCountBits(version) + data.length * 8;
    for (const candidate of EC_ORDER) {
      if (
        EC_ORDER.indexOf(candidate) > EC_ORDER.indexOf(errorCorrectionLevel) &&
        usedBits <= getNumDataCodewords(version, candidate) * 8
      ) {
        ecl = candidate;
      }
    }
  }

  // Build the bit stream: mode, length, payload, terminator, padding.
  const bits: number[] = [];
  const appendBits = (value: number, length: number): void => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };

  appendBits(0b0100, 4); // byte mode
  appendBits(data.length, byteModeCountBits(version));
  for (const byte of data) appendBits(byte, 8);

  const dataCapacityBits = getNumDataCodewords(version, ecl) * 8;
  appendBits(0, Math.min(4, dataCapacityBits - bits.length));
  appendBits(0, (8 - (bits.length % 8)) % 8);
  for (let padByte = 0xec; bits.length < dataCapacityBits; padByte ^= 0xec ^ 0x11) {
    appendBits(padByte, 8);
  }

  const dataCodewords = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i++) {
    dataCodewords[i >>> 3] |= bits[i] << (7 - (i & 7));
  }

  const allCodewords = addEccAndInterleave(dataCodewords, version, ecl);

  const size = version * 4 + 17;
  const matrix = new Matrix(size);
  drawFunctionPatterns(matrix, version, ecl);
  drawCodewords(matrix, allCodewords);

  let bestMask = forcedMask ?? 0;
  if (forcedMask === undefined) {
    let minPenalty = Infinity;
    for (let candidate = 0; candidate < 8; candidate++) {
      applyMask(matrix, candidate);
      drawFormatBits(matrix, ecl, candidate);
      const penalty = qrPenaltyScore(matrix.modules);
      if (penalty < minPenalty) {
        minPenalty = penalty;
        bestMask = candidate;
      }
      applyMask(matrix, candidate); // masking is its own inverse
    }
  }

  applyMask(matrix, bestMask);
  drawFormatBits(matrix, ecl, bestMask);

  return {
    version,
    size,
    errorCorrectionLevel: ecl,
    mask: bestMask,
    modules: matrix.modules,
  };
}

/** The built-in encoder, as a `QrEncoder`. */
export const defaultQrEncoder: QrEncoder = { encode: encodeQr };

export interface QrRenderOptions {
  /** Quiet-zone width in modules. The spec requires 4; scanners rely on it. */
  margin?: number;
  /** Pixels per module. */
  scale?: number;
  dark?: string;
  light?: string;
}

/** Renders to a standalone SVG string. */
export function qrToSvg(qr: QrCode, options: QrRenderOptions = {}): string {
  const { margin = 4, scale = 4, dark = '#000000', light = '#ffffff' } = options;
  const dimension = (qr.size + margin * 2) * scale;

  const parts: string[] = [];
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.modules[y][x]) parts.push(`M${x + margin},${y + margin}h1v1h-1z`);
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${dimension}" height="${dimension}" ` +
    `viewBox="0 0 ${qr.size + margin * 2} ${qr.size + margin * 2}" shape-rendering="crispEdges">` +
    `<rect width="100%" height="100%" fill="${light}"/>` +
    `<path fill="${dark}" d="${parts.join('')}"/>` +
    `</svg>`
  );
}

/** Renders to RGBA pixels, for a canvas or an image encoder. */
export function qrToImageData(
  qr: QrCode,
  options: { margin?: number; scale?: number } = {},
): { width: number; height: number; data: Uint8ClampedArray } {
  const { margin = 4, scale = 4 } = options;
  const width = (qr.size + margin * 2) * scale;
  const data = new Uint8ClampedArray(width * width * 4).fill(0xff);

  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (!qr.modules[y][x]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = (x + margin) * scale + dx;
          const py = (y + margin) * scale + dy;
          const offset = (py * width + px) * 4;
          data[offset] = 0;
          data[offset + 1] = 0;
          data[offset + 2] = 0;
        }
      }
    }
  }
  return { width, height: width, data };
}

/**
 * Renders to text using half-block characters, so one line covers two rows.
 *
 * Useful for a terminal handoff — the CLI can print a scannable code.
 */
export function qrToAscii(qr: QrCode, options: { margin?: number } = {}): string {
  const { margin = 2 } = options;
  const total = qr.size + margin * 2;
  const dark = (x: number, y: number): boolean => {
    const mx = x - margin;
    const my = y - margin;
    if (mx < 0 || my < 0 || mx >= qr.size || my >= qr.size) return false;
    return qr.modules[my][mx];
  };

  const lines: string[] = [];
  for (let y = 0; y < total; y += 2) {
    let line = '';
    for (let x = 0; x < total; x++) {
      const top = dark(x, y);
      const bottom = y + 1 < total ? dark(x, y + 1) : false;
      // Dark modules render as light glyphs against a dark terminal, so invert.
      if (top && bottom) line += ' ';
      else if (top) line += '▄';
      else if (bottom) line += '▀';
      else line += '█';
    }
    lines.push(line);
  }
  return lines.join('\n');
}
