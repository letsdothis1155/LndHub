/**
 * Minimal resources.arsc reader.
 *
 * Only enough of the resource table to turn a reference such as
 * `@0x7f0f0001` back into a string. Without it the manifest's most
 * user-visible fields — app label, and often versionName — read as opaque
 * hex ids in the installer UI.
 */

import { ByteReader } from './bytes.js';
import { parseStringPool, TYPE_REFERENCE, TYPE_STRING, type StringPool } from './axml.js';

export class ArscError extends Error {}

const RES_TABLE_TYPE = 0x0002;
const RES_TABLE_PACKAGE_TYPE = 0x0200;
const RES_TABLE_TYPE_TYPE = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE = 0x0202;

const FLAG_SPARSE = 0x01;
const FLAG_OFFSET16 = 0x02;
const ENTRY_FLAG_COMPLEX = 0x0001;

interface ResourceValue {
  type: number;
  data: number;
  /** True when this entry came from a configuration with no locale qualifier. */
  isDefaultConfig: boolean;
}

interface ResourcePackage {
  id: number;
  name: string;
  typeNames: string[];
  keyNames: string[];
  /** typeId -> entryIndex -> candidate values */
  values: Map<number, Map<number, ResourceValue[]>>;
}

export class ResourceTable {
  readonly globalStrings: StringPool;
  readonly packages: ResourcePackage[];

  private constructor(globalStrings: StringPool, packages: ResourcePackage[]) {
    this.globalStrings = globalStrings;
    this.packages = packages;
  }

  static parse(bytes: Uint8Array): ResourceTable {
    const r = new ByteReader(bytes, 0);
    const type = r.u16();
    if (type !== RES_TABLE_TYPE) {
      throw new ArscError(`not a resource table (chunk type 0x${type.toString(16)})`);
    }
    const headerSize = r.u16();
    const tableSize = r.u32();
    const packageCount = r.u32();
    const end = Math.min(tableSize === 0 ? bytes.length : tableSize, bytes.length);

    // The global value string pool is the first chunk after the table header.
    const globalStrings = parseStringPool(bytes, headerSize);
    const globalPoolSize = new ByteReader(bytes, headerSize + 4).u32();

    const packages: ResourcePackage[] = [];
    let offset = headerSize + globalPoolSize;
    while (offset + 8 <= end && packages.length < packageCount) {
      const chunk = new ByteReader(bytes, offset);
      const chunkType = chunk.u16();
      chunk.u16(); // header size
      const chunkSize = chunk.u32();
      if (chunkSize < 8 || offset + chunkSize > end) break;
      if (chunkType === RES_TABLE_PACKAGE_TYPE) {
        packages.push(parsePackage(bytes, offset, chunkSize));
      }
      offset += chunkSize;
    }

    return new ResourceTable(globalStrings, packages);
  }

  /**
   * Resolves a resource id to a string, following reference chains.
   *
   * Prefers values from the default (unqualified) configuration so the result
   * matches what a device with no special locale would show.
   */
  resolveString(resourceId: number, depth = 0): string | null {
    if (depth > 5) return null;
    const packageId = (resourceId >>> 24) & 0xff;
    const typeId = (resourceId >>> 16) & 0xff;
    const entryIndex = resourceId & 0xffff;

    const pkg = this.packages.find((p) => p.id === packageId);
    if (!pkg) return null;
    const candidates = pkg.values.get(typeId)?.get(entryIndex);
    if (!candidates || candidates.length === 0) return null;

    const ordered = [...candidates].sort(
      (a, b) => Number(b.isDefaultConfig) - Number(a.isDefaultConfig),
    );
    for (const value of ordered) {
      if (value.type === TYPE_STRING) {
        const s = this.globalStrings.strings[value.data];
        if (s !== undefined) return s;
      } else if (value.type === TYPE_REFERENCE && value.data !== 0) {
        const resolved = this.resolveString(value.data >>> 0, depth + 1);
        if (resolved !== null) return resolved;
      }
    }
    return null;
  }

  /** Resolves an integer-valued resource (used for versionCode references). */
  resolveInt(resourceId: number, depth = 0): number | null {
    if (depth > 5) return null;
    const packageId = (resourceId >>> 24) & 0xff;
    const typeId = (resourceId >>> 16) & 0xff;
    const entryIndex = resourceId & 0xffff;
    const pkg = this.packages.find((p) => p.id === packageId);
    const candidates = pkg?.values.get(typeId)?.get(entryIndex);
    if (!candidates) return null;
    const ordered = [...candidates].sort(
      (a, b) => Number(b.isDefaultConfig) - Number(a.isDefaultConfig),
    );
    for (const value of ordered) {
      if (value.type === TYPE_REFERENCE && value.data !== 0) {
        const resolved = this.resolveInt(value.data >>> 0, depth + 1);
        if (resolved !== null) return resolved;
      } else if (value.type !== TYPE_STRING) {
        return value.data | 0;
      }
    }
    return null;
  }
}

function parsePackage(bytes: Uint8Array, start: number, chunkSize: number): ResourcePackage {
  const r = new ByteReader(bytes, start);
  r.u16(); // type
  const headerSize = r.u16();
  r.u32(); // size
  const id = r.u32();

  // Package name: 128 UTF-16 code units, NUL padded.
  let name = '';
  for (let i = 0; i < 128; i++) {
    const ch = r.u16();
    if (ch === 0) {
      r.skip((127 - i) * 2);
      break;
    }
    name += String.fromCharCode(ch);
  }
  const typeStringsOffset = r.u32();
  r.u32(); // lastPublicType
  const keyStringsOffset = r.u32();
  r.u32(); // lastPublicKey

  const typeNames = typeStringsOffset > 0 ? parseStringPool(bytes, start + typeStringsOffset).strings : [];
  const keyNames = keyStringsOffset > 0 ? parseStringPool(bytes, start + keyStringsOffset).strings : [];

  const pkg: ResourcePackage = { id, name, typeNames, keyNames, values: new Map() };

  const end = start + chunkSize;
  let offset = start + headerSize;
  while (offset + 8 <= end) {
    const chunk = new ByteReader(bytes, offset);
    const chunkType = chunk.u16();
    chunk.u16(); // header size
    const size = chunk.u32();
    if (size < 8 || offset + size > end) break;
    if (chunkType === RES_TABLE_TYPE_TYPE) parseTypeChunk(bytes, offset, size, pkg);
    else if (chunkType === RES_TABLE_TYPE_SPEC_TYPE) {
      // Spec chunks only carry per-entry config flags; nothing we need.
    }
    offset += size;
  }
  return pkg;
}

function parseTypeChunk(
  bytes: Uint8Array,
  start: number,
  chunkSize: number,
  pkg: ResourcePackage,
): void {
  const r = new ByteReader(bytes, start);
  r.u16(); // type
  const headerSize = r.u16();
  r.u32(); // size
  const typeId = r.u8();
  const flags = r.u8();
  r.u16(); // reserved
  const entryCount = r.u32();
  const entriesStart = r.u32();

  // ResTable_config follows; its first u32 is its own size, and the locale
  // language sits at config offset 8. An all-zero language means "default".
  const configStart = r.offset;
  const configSize = r.u32();
  const isDefaultConfig =
    configSize < 10 || (bytes[configStart + 8] === 0 && bytes[configStart + 9] === 0);

  const sparse = (flags & FLAG_SPARSE) !== 0;
  const offset16 = (flags & FLAG_OFFSET16) !== 0;

  const offsets = new ByteReader(bytes, start + headerSize);
  const entryOffsets = new Map<number, number>();
  try {
    if (sparse) {
      for (let i = 0; i < entryCount; i++) {
        const index = offsets.u16();
        const value = offsets.u16();
        entryOffsets.set(index, value * 4);
      }
    } else if (offset16) {
      for (let i = 0; i < entryCount; i++) {
        const value = offsets.u16();
        if (value !== 0xffff) entryOffsets.set(i, value * 4);
      }
    } else {
      for (let i = 0; i < entryCount; i++) {
        const value = offsets.u32();
        if (value !== 0xffffffff) entryOffsets.set(i, value);
      }
    }
  } catch {
    // A truncated offset array means the rest of this type chunk is unusable.
  }

  let byType = pkg.values.get(typeId);
  if (!byType) {
    byType = new Map();
    pkg.values.set(typeId, byType);
  }

  const dataStart = start + entriesStart;
  const end = start + chunkSize;
  for (const [index, entryOffset] of entryOffsets) {
    const at = dataStart + entryOffset;
    if (at + 8 > end) continue;
    const e = new ByteReader(bytes, at);
    const entrySize = e.u16();
    const entryFlags = e.u16();
    e.u32(); // key index
    if (entryFlags & ENTRY_FLAG_COMPLEX) continue; // bags have no single value

    // Newer AAPT2 emits a compact form where the header is 8 bytes and the
    // Res_value follows immediately; the classic form declares entrySize 8 too.
    e.seek(at + Math.max(entrySize, 8));
    if (e.offset + 8 > end) continue;
    e.u16(); // value size
    e.u8(); // res0
    const valueType = e.u8();
    const data = e.u32();

    let list = byType.get(index);
    if (!list) {
      list = [];
      byType.set(index, list);
    }
    list.push({ type: valueType, data, isDefaultConfig });
  }
}
