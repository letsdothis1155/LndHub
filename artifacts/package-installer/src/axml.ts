/**
 * Android binary XML (AXML) parser.
 *
 * A compiled AndroidManifest.xml is a chunked binary format, not text. Reading
 * it directly — rather than regex-scanning the APK for recognizable strings —
 * is what makes attribute values (exported, debuggable, permissions) actually
 * trustworthy.
 */

import { ByteReader, decodeUtf16le, decodeUtf8 } from './bytes.js';

export class AxmlError extends Error {}

const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_TYPE = 0x0003;
const RES_XML_START_NAMESPACE_TYPE = 0x0100;
const RES_XML_END_NAMESPACE_TYPE = 0x0101;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const RES_XML_END_ELEMENT_TYPE = 0x0103;
const RES_XML_CDATA_TYPE = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE = 0x0180;

export const TYPE_NULL = 0x00;
export const TYPE_REFERENCE = 0x01;
export const TYPE_ATTRIBUTE = 0x02;
export const TYPE_STRING = 0x03;
export const TYPE_FLOAT = 0x04;
export const TYPE_DIMENSION = 0x05;
export const TYPE_FRACTION = 0x06;
export const TYPE_INT_DEC = 0x10;
export const TYPE_INT_HEX = 0x11;
export const TYPE_INT_BOOLEAN = 0x12;
export const TYPE_INT_COLOR_ARGB8 = 0x1c;
export const TYPE_INT_COLOR_RGB8 = 0x1d;
export const TYPE_INT_COLOR_ARGB4 = 0x1e;
export const TYPE_INT_COLOR_RGB4 = 0x1f;

export const ANDROID_NAMESPACE = 'http://schemas.android.com/apk/res/android';

export interface AxmlAttribute {
  namespace: string | null;
  name: string;
  /** Resource id from the resource map, when the attribute is a framework attr. */
  resourceId: number | null;
  /** The string-pool raw value, present for author-written string literals. */
  rawValue: string | null;
  type: number;
  data: number;
  /** Human-readable rendering of the typed value. */
  value: string;
}

export interface AxmlElement {
  name: string;
  namespace: string | null;
  line: number;
  attributes: AxmlAttribute[];
  children: AxmlElement[];
  text: string;
}

export interface StringPool {
  strings: string[];
  isUtf8: boolean;
}

/** Parses a RES_STRING_POOL chunk starting at `start`. */
export function parseStringPool(bytes: Uint8Array, start: number): StringPool {
  const r = new ByteReader(bytes, start);
  const type = r.u16();
  if (type !== RES_STRING_POOL_TYPE) {
    throw new AxmlError(`expected string pool chunk at ${start}, found type 0x${type.toString(16)}`);
  }
  const headerSize = r.u16();
  const chunkSize = r.u32();
  const stringCount = r.u32();
  const styleCount = r.u32();
  const flags = r.u32();
  const stringsStart = r.u32();
  r.u32(); // stylesStart

  const isUtf8 = (flags & (1 << 8)) !== 0;
  if (start + chunkSize > bytes.length) {
    throw new AxmlError('string pool chunk extends past end of buffer');
  }

  const offsets: number[] = new Array(stringCount);
  r.seek(start + headerSize);
  for (let i = 0; i < stringCount; i++) offsets[i] = r.u32();
  // styleCount offsets follow; we do not need styles.
  void styleCount;

  const dataStart = start + stringsStart;
  const dataEnd = start + chunkSize;
  const strings: string[] = new Array(stringCount);
  for (let i = 0; i < stringCount; i++) {
    const at = dataStart + offsets[i];
    if (at < dataStart || at >= dataEnd) {
      strings[i] = '';
      continue;
    }
    strings[i] = isUtf8
      ? readUtf8String(bytes, at, dataEnd)
      : readUtf16String(bytes, at, dataEnd);
  }
  return { strings, isUtf8 };
}

/** UTF-8 pool strings carry a char count and a byte count, each 1 or 2 bytes. */
function readUtf8String(bytes: Uint8Array, at: number, end: number): string {
  let p = at;
  const readLength = (): number => {
    let len = bytes[p++];
    if (len & 0x80) len = ((len & 0x7f) << 8) | bytes[p++];
    return len;
  };
  readLength(); // character count, unused — byte count is authoritative
  const byteLength = readLength();
  if (p + byteLength > end) return '';
  return decodeUtf8(bytes.subarray(p, p + byteLength));
}

/** UTF-16 pool strings carry a word count, 1 or 2 words. */
function readUtf16String(bytes: Uint8Array, at: number, end: number): string {
  let p = at;
  let len = bytes[p] | (bytes[p + 1] << 8);
  p += 2;
  if (len & 0x8000) {
    const high = len & 0x7fff;
    const low = bytes[p] | (bytes[p + 1] << 8);
    p += 2;
    len = (high << 16) | low;
  }
  const byteLength = len * 2;
  if (p + byteLength > end) return '';
  return decodeUtf16le(bytes.subarray(p, p + byteLength));
}

const COMPLEX_UNITS = ['px', 'dip', 'sp', 'pt', 'in', 'mm'];
const FRACTION_UNITS = ['%', '%p'];

function complexToFloat(data: number): number {
  const mantissa = data & 0xffffff00;
  const radix = (data >> 4) & 0x3;
  const shifts = [23, 16, 8, 0];
  return (mantissa >> shifts[radix]) * (1 / (1 << 8));
}

/** Renders a Res_value the way aapt's XML dump would. */
export function formatTypedValue(type: number, data: number, rawValue: string | null): string {
  switch (type) {
    case TYPE_NULL:
      return '';
    case TYPE_STRING:
      return rawValue ?? '';
    case TYPE_REFERENCE:
      return data === 0 ? '@null' : `@0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case TYPE_ATTRIBUTE:
      return `?0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case TYPE_INT_BOOLEAN:
      return data !== 0 ? 'true' : 'false';
    case TYPE_INT_DEC:
      return String(data | 0);
    case TYPE_INT_HEX:
      return `0x${(data >>> 0).toString(16)}`;
    case TYPE_FLOAT: {
      const buf = new DataView(new ArrayBuffer(4));
      buf.setUint32(0, data >>> 0, true);
      return String(buf.getFloat32(0, true));
    }
    case TYPE_DIMENSION:
      return `${complexToFloat(data)}${COMPLEX_UNITS[data & 0x0f] ?? ''}`;
    case TYPE_FRACTION:
      return `${complexToFloat(data) * 100}${FRACTION_UNITS[data & 0x0f] ?? ''}`;
    case TYPE_INT_COLOR_ARGB8:
    case TYPE_INT_COLOR_RGB8:
    case TYPE_INT_COLOR_ARGB4:
    case TYPE_INT_COLOR_RGB4:
      return `#${(data >>> 0).toString(16).padStart(8, '0')}`;
    default:
      return `0x${(data >>> 0).toString(16)}`;
  }
}

/**
 * Parses a binary XML document and returns its root element.
 *
 * Namespace prefixes are resolved to their URIs, so callers compare against
 * ANDROID_NAMESPACE rather than an "android:" prefix an author could rename.
 */
export function parseAxml(bytes: Uint8Array): AxmlElement {
  const r = new ByteReader(bytes, 0);
  const fileType = r.u16();
  if (fileType !== RES_XML_TYPE) {
    throw new AxmlError(
      `not a binary XML document (chunk type 0x${fileType.toString(16).padStart(4, '0')})`,
    );
  }
  const headerSize = r.u16();
  const fileSize = r.u32();
  const end = Math.min(fileSize === 0 ? bytes.length : fileSize, bytes.length);

  let pool: StringPool | null = null;
  let resourceMap: number[] = [];
  const namespaces = new Map<number, string>(); // prefix index -> uri
  const stack: AxmlElement[] = [];
  let root: AxmlElement | null = null;

  const str = (index: number): string => {
    if (index === 0xffffffff || index === -1) return '';
    return pool?.strings[index] ?? '';
  };

  let offset = headerSize;
  while (offset + 8 <= end) {
    const chunk = new ByteReader(bytes, offset);
    const chunkType = chunk.u16();
    const chunkHeaderSize = chunk.u16();
    const chunkSize = chunk.u32();
    if (chunkSize < 8 || offset + chunkSize > end) {
      throw new AxmlError(`chunk at ${offset} declares an out-of-range size (${chunkSize})`);
    }

    switch (chunkType) {
      case RES_STRING_POOL_TYPE:
        pool = parseStringPool(bytes, offset);
        break;

      case RES_XML_RESOURCE_MAP_TYPE: {
        const count = (chunkSize - chunkHeaderSize) >> 2;
        const map = new ByteReader(bytes, offset + chunkHeaderSize);
        resourceMap = new Array(count);
        for (let i = 0; i < count; i++) resourceMap[i] = map.u32();
        break;
      }

      case RES_XML_START_NAMESPACE_TYPE: {
        const node = new ByteReader(bytes, offset + chunkHeaderSize);
        const prefix = node.u32();
        const uri = node.u32();
        namespaces.set(prefix, str(uri));
        break;
      }

      case RES_XML_END_NAMESPACE_TYPE: {
        const node = new ByteReader(bytes, offset + chunkHeaderSize);
        const prefix = node.u32();
        namespaces.delete(prefix);
        break;
      }

      case RES_XML_START_ELEMENT_TYPE: {
        const lineNumber = new ByteReader(bytes, offset + 8).u32();
        const node = new ByteReader(bytes, offset + chunkHeaderSize);
        const nsIndex = node.u32();
        const nameIndex = node.u32();
        const attributeStart = node.u16();
        const attributeSize = node.u16();
        const attributeCount = node.u16();

        const element: AxmlElement = {
          name: str(nameIndex),
          namespace: nsIndex === 0xffffffff ? null : str(nsIndex),
          line: lineNumber,
          attributes: [],
          children: [],
          text: '',
        };

        const attrBase = offset + chunkHeaderSize + attributeStart;
        for (let i = 0; i < attributeCount; i++) {
          const a = new ByteReader(bytes, attrBase + i * attributeSize);
          const attrNs = a.u32();
          const attrName = a.u32();
          const attrRawValue = a.u32();
          a.u16(); // typed value size
          a.u8(); // res0
          const valueType = a.u8();
          const valueData = a.u32();

          const rawValue = attrRawValue === 0xffffffff ? null : str(attrRawValue);
          const resourceId =
            attrName < resourceMap.length ? resourceMap[attrName] >>> 0 : null;
          element.attributes.push({
            namespace: attrNs === 0xffffffff ? null : str(attrNs),
            name: str(attrName),
            resourceId: resourceId === null || resourceId === 0 ? null : resourceId,
            rawValue,
            type: valueType,
            data: valueData,
            value: formatTypedValue(valueType, valueData, rawValue),
          });
        }

        if (stack.length > 0) stack[stack.length - 1].children.push(element);
        else if (root === null) root = element;
        stack.push(element);
        break;
      }

      case RES_XML_END_ELEMENT_TYPE:
        if (stack.length === 0) throw new AxmlError('end element with no matching start');
        stack.pop();
        break;

      case RES_XML_CDATA_TYPE: {
        const node = new ByteReader(bytes, offset + chunkHeaderSize);
        const dataIndex = node.u32();
        if (stack.length > 0) stack[stack.length - 1].text += str(dataIndex);
        break;
      }

      default:
        // Unknown chunk types are skipped by size, per the platform's own reader.
        break;
    }

    offset += chunkSize;
  }

  if (!root) throw new AxmlError('binary XML document contains no root element');
  return root;
}

/** Finds an attribute by local name, preferring the android namespace. */
export function getAttribute(element: AxmlElement, name: string): AxmlAttribute | undefined {
  return (
    element.attributes.find((a) => a.name === name && a.namespace === ANDROID_NAMESPACE) ??
    element.attributes.find((a) => a.name === name)
  );
}

export function childrenNamed(element: AxmlElement, name: string): AxmlElement[] {
  return element.children.filter((c) => c.name === name);
}
