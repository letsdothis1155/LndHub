/**
 * Synthetic APK builder used by the test suite.
 *
 * Everything is assembled byte-for-byte to the platform formats — binary XML,
 * resources.arsc, DER certificates, PKCS#7, ZIP — so the parsers are exercised
 * against real structures rather than against mocks of themselves.
 */

import { deflateRawSync } from 'node:zlib';
import { generateKeyPairSync } from 'node:crypto';
import { crc32 } from '../src/zip.js';

// ---------------------------------------------------------------------------
// Binary XML
// ---------------------------------------------------------------------------

export interface XmlAttrSpec {
  name: string;
  /** null for the manifest's own un-namespaced attributes such as `package`. */
  android: boolean;
  value: { kind: 'string'; text: string } | { kind: 'int'; value: number } | { kind: 'bool'; value: boolean } | { kind: 'ref'; id: number };
}

export interface XmlNodeSpec {
  name: string;
  attrs?: XmlAttrSpec[];
  children?: XmlNodeSpec[];
}

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

/** Attribute names that get a resource-map entry, in pool order. */
const ATTR_RESOURCE_IDS: [string, number][] = [
  ['name', 0x01010003],
  ['label', 0x01010001],
  ['debuggable', 0x0101000f],
  ['exported', 0x01010010],
  ['authorities', 0x01010018],
  ['allowBackup', 0x01010280],
  ['minSdkVersion', 0x0101020c],
  ['versionCode', 0x0101021b],
  ['versionName', 0x0101021c],
  ['targetSdkVersion', 0x01010270],
];

class Writer {
  private chunks: number[] = [];

  get length(): number {
    return this.chunks.length;
  }

  u8(v: number): this {
    this.chunks.push(v & 0xff);
    return this;
  }

  u16(v: number): this {
    return this.u8(v).u8(v >>> 8);
  }

  u32(v: number): this {
    return this.u16(v & 0xffff).u16(v >>> 16);
  }

  bytes(b: Uint8Array | number[]): this {
    for (const x of b) this.chunks.push(x & 0xff);
    return this;
  }

  patchU32(offset: number, value: number): void {
    this.chunks[offset] = value & 0xff;
    this.chunks[offset + 1] = (value >>> 8) & 0xff;
    this.chunks[offset + 2] = (value >>> 16) & 0xff;
    this.chunks[offset + 3] = (value >>> 24) & 0xff;
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.chunks);
  }
}

class StringPoolBuilder {
  readonly strings: string[] = [];
  private index = new Map<string, number>();

  constructor(reserved: string[] = []) {
    for (const s of reserved) this.add(s);
  }

  add(value: string): number {
    const existing = this.index.get(value);
    if (existing !== undefined) return existing;
    const id = this.strings.length;
    this.strings.push(value);
    this.index.set(value, id);
    return id;
  }

  /** Emits a UTF-8 RES_STRING_POOL chunk, the encoding aapt2 uses for manifests. */
  build(): Uint8Array {
    const encoder = new TextEncoder();
    const data = new Writer();
    const offsets: number[] = [];
    for (const s of this.strings) {
      offsets.push(data.length);
      const encoded = encoder.encode(s);
      // Character count then byte count, each in the 1-byte short form.
      if ([...s].length > 0x7f || encoded.length > 0x7f) {
        throw new Error(`fixture string too long for the short form: ${s}`);
      }
      data.u8([...s].length).u8(encoded.length).bytes(encoded).u8(0);
    }
    while (data.length % 4 !== 0) data.u8(0);

    const headerSize = 28;
    const stringsStart = headerSize + offsets.length * 4;
    const total = stringsStart + data.length;

    const w = new Writer();
    w.u16(0x0001).u16(headerSize).u32(total);
    w.u32(this.strings.length).u32(0);
    w.u32(1 << 8); // UTF8_FLAG
    w.u32(stringsStart).u32(0);
    for (const offset of offsets) w.u32(offset);
    w.bytes(data.toBytes());
    return w.toBytes();
  }
}

/** Compiles an XML tree into an AndroidManifest.xml-style binary document. */
export function buildAxml(root: XmlNodeSpec): Uint8Array {
  const pool = new StringPoolBuilder(ATTR_RESOURCE_IDS.map(([name]) => name));
  const nsPrefix = pool.add('android');
  const nsUri = pool.add(ANDROID_NS);

  const body = new Writer();

  const startNamespace = (): void => {
    body.u16(0x0100).u16(16).u32(24).u32(1).u32(0xffffffff);
    body.u32(nsPrefix).u32(nsUri);
  };
  const endNamespace = (): void => {
    body.u16(0x0101).u16(16).u32(24).u32(1).u32(0xffffffff);
    body.u32(nsPrefix).u32(nsUri);
  };

  const emit = (node: XmlNodeSpec): void => {
    const nameIndex = pool.add(node.name);
    const attrs = node.attrs ?? [];
    const encoded = attrs.map((attr) => {
      const attrName = pool.add(attr.name);
      switch (attr.value.kind) {
        case 'string': {
          const valueIndex = pool.add(attr.value.text);
          return { ns: attr.android, attrName, raw: valueIndex, type: 0x03, data: valueIndex };
        }
        case 'int':
          return { ns: attr.android, attrName, raw: 0xffffffff, type: 0x10, data: attr.value.value };
        case 'bool':
          return {
            ns: attr.android,
            attrName,
            raw: 0xffffffff,
            type: 0x12,
            data: attr.value.value ? 0xffffffff : 0,
          };
        case 'ref':
          return { ns: attr.android, attrName, raw: 0xffffffff, type: 0x01, data: attr.value.id };
      }
    });

    const size = 16 + 20 + encoded.length * 20;
    body.u16(0x0102).u16(16).u32(size).u32(1).u32(0xffffffff);
    body.u32(0xffffffff).u32(nameIndex);
    body.u16(20).u16(20).u16(encoded.length).u16(0).u16(0).u16(0);
    for (const attr of encoded) {
      body.u32(attr.ns ? nsUri : 0xffffffff);
      body.u32(attr.attrName);
      body.u32(attr.raw);
      body.u16(8).u8(0).u8(attr.type).u32(attr.data);
    }

    for (const child of node.children ?? []) emit(child);

    body.u16(0x0103).u16(16).u32(24).u32(1).u32(0xffffffff);
    body.u32(0xffffffff).u32(nameIndex);
  };

  startNamespace();
  emit(root);
  endNamespace();

  // The pool is only final once every string has been interned by emit().
  const poolChunk = pool.build();
  const resourceMap = new Writer();
  resourceMap.u16(0x0180).u16(8).u32(8 + ATTR_RESOURCE_IDS.length * 4);
  for (const [, id] of ATTR_RESOURCE_IDS) resourceMap.u32(id);

  const bodyBytes = body.toBytes();
  const resourceMapBytes = resourceMap.toBytes();
  const total = 8 + poolChunk.length + resourceMapBytes.length + bodyBytes.length;

  const out = new Writer();
  out.u16(0x0003).u16(8).u32(total);
  out.bytes(poolChunk).bytes(resourceMapBytes).bytes(bodyBytes);
  return out.toBytes();
}

// ---------------------------------------------------------------------------
// resources.arsc
// ---------------------------------------------------------------------------

/**
 * Builds a one-entry resource table: package 0x7f, type 1, entry 0 holds
 * `label`. That is the shape the manifest's `@0x7f010000` reference points at.
 */
export function buildArsc(label: string): Uint8Array {
  const globalPool = new StringPoolBuilder([label]).build();
  const typePool = new StringPoolBuilder(['string']).build();
  const keyPool = new StringPoolBuilder(['app_name']).build();

  const packageHeaderSize = 284;
  const typeStringsOffset = packageHeaderSize;
  const keyStringsOffset = typeStringsOffset + typePool.length;

  // RES_TABLE_TYPE chunk: header (76) + one u32 offset + one entry.
  const typeChunk = new Writer();
  const configSize = 56;
  const typeHeaderSize = 8 + 4 + 4 + 4 + configSize;
  const entriesStart = typeHeaderSize + 4;
  const typeChunkSize = entriesStart + 8 + 8;
  typeChunk.u16(0x0201).u16(typeHeaderSize).u32(typeChunkSize);
  typeChunk.u8(1).u8(0).u16(0); // typeId 1, no sparse/offset16 flags
  typeChunk.u32(1); // entryCount
  typeChunk.u32(entriesStart);
  typeChunk.u32(configSize); // ResTable_config.size
  for (let i = 4; i < configSize; i++) typeChunk.u8(0); // default configuration
  typeChunk.u32(0); // entry 0 lives at offset 0
  typeChunk.u16(8).u16(0).u32(0); // entry header: size, flags, key index
  typeChunk.u16(8).u8(0).u8(0x03).u32(0); // Res_value: TYPE_STRING -> global string 0

  const typeChunkBytes = typeChunk.toBytes();
  const packageSize = keyStringsOffset + keyPool.length + typeChunkBytes.length;

  const pkg = new Writer();
  pkg.u16(0x0200).u16(packageHeaderSize).u32(packageSize);
  pkg.u32(0x7f);
  const packageName = 'com.smartrealty.demo';
  for (let i = 0; i < 128; i++) pkg.u16(i < packageName.length ? packageName.charCodeAt(i) : 0);
  pkg.u32(typeStringsOffset).u32(0).u32(keyStringsOffset).u32(0);
  pkg.bytes(typePool).bytes(keyPool).bytes(typeChunkBytes);

  const pkgBytes = pkg.toBytes();
  const table = new Writer();
  table.u16(0x0002).u16(12).u32(12 + globalPool.length + pkgBytes.length).u32(1);
  table.bytes(globalPool).bytes(pkgBytes);
  return table.toBytes();
}

// ---------------------------------------------------------------------------
// DER / X.509 / PKCS#7
// ---------------------------------------------------------------------------

function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function der(tag: number, content: Uint8Array | number[]): Uint8Array {
  const body = content instanceof Uint8Array ? content : new Uint8Array(content);
  return new Uint8Array([tag, ...derLength(body.length), ...body]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function derOid(dotted: string): Uint8Array {
  const parts = dotted.split('.').map(Number);
  const body: number[] = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const stack: number[] = [];
    let n = part;
    do {
      stack.unshift(n & 0x7f);
      n = Math.floor(n / 128);
    } while (n > 0);
    for (let i = 0; i < stack.length - 1; i++) stack[i] |= 0x80;
    body.push(...stack);
  }
  return der(0x06, body);
}

function derInteger(value: number): Uint8Array {
  const bytes: number[] = [];
  let n = value;
  do {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  } while (n > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return der(0x02, bytes);
}

function derUtcTime(date: Date): Uint8Array {
  const pad = (n: number): string => String(n).padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return der(0x17, new TextEncoder().encode(text));
}

function derName(entries: [string, string][]): Uint8Array {
  const rdns = entries.map(([oid, value]) =>
    der(0x31, der(0x30, concat(derOid(oid), der(0x13, new TextEncoder().encode(value))))),
  );
  return der(0x30, concat(...rdns));
}

export interface CertificateSpec {
  commonName: string;
  organization: string;
  notBefore: Date;
  notAfter: Date;
  modulusLength?: number;
  /** Use sha1WithRSAEncryption to exercise the weak-hash rule. */
  weakSignatureAlgorithm?: boolean;
}

/**
 * Builds a syntactically valid self-signed certificate.
 *
 * The signature bytes are filler: the inspector reports what a certificate
 * claims and how strong those claims are, and deliberately does not verify a
 * self-signed signature (which would only prove the file is internally
 * consistent).
 */
export function buildCertificate(spec: CertificateSpec): Uint8Array {
  const { publicKey } = generateKeyPairSync('rsa', {
    modulusLength: spec.modulusLength ?? 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const spki = Uint8Array.from(publicKey as unknown as Uint8Array);

  const sigOid = spec.weakSignatureAlgorithm ? '1.2.840.113549.1.1.5' : '1.2.840.113549.1.1.11';
  const algorithm = der(0x30, concat(derOid(sigOid), der(0x05, [])));
  const name = derName([
    ['2.5.4.3', spec.commonName],
    ['2.5.4.10', spec.organization],
  ]);

  const tbs = der(
    0x30,
    concat(
      der(0xa0, derInteger(2)), // version v3
      derInteger(0x4d2),
      algorithm,
      name, // issuer
      der(0x30, concat(derUtcTime(spec.notBefore), derUtcTime(spec.notAfter))),
      name, // subject — self-signed
      spki,
    ),
  );

  const signature = der(0x03, new Uint8Array([0x00, ...new Uint8Array(256).fill(0xab)]));
  return der(0x30, concat(tbs, algorithm, signature));
}

/** Wraps certificates in a PKCS#7 SignedData, as a META-INF/*.RSA file does. */
export function buildPkcs7(certificates: Uint8Array[]): Uint8Array {
  const signedData = der(
    0x30,
    concat(
      derInteger(1),
      der(0x31, new Uint8Array(0)), // digestAlgorithms
      der(0x30, derOid('1.2.840.113549.1.7.1')), // contentInfo: data
      der(0xa0, concat(...certificates)),
      der(0x31, new Uint8Array(0)), // signerInfos
    ),
  );
  return der(0x30, concat(derOid('1.2.840.113549.1.7.2'), der(0xa0, signedData)));
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

export interface ZipInput {
  name: string;
  data: Uint8Array;
  /** Store rather than deflate; APKs store resources.arsc for mmap alignment. */
  store?: boolean;
}

/** Writes a ZIP archive; deflated entries go through zlib so our inflate is tested. */
export function buildZip(inputs: ZipInput[]): Uint8Array {
  const encoder = new TextEncoder();
  const local = new Writer();
  const central = new Writer();
  const offsets: number[] = [];

  for (const input of inputs) {
    const nameBytes = encoder.encode(input.name);
    const stored = input.store === true;
    const payload = stored ? input.data : new Uint8Array(deflateRawSync(input.data));
    const checksum = crc32(input.data);
    offsets.push(local.length);

    local.u32(0x04034b50).u16(20).u16(0).u16(stored ? 0 : 8).u16(0).u16(0);
    local.u32(checksum).u32(payload.length).u32(input.data.length);
    local.u16(nameBytes.length).u16(0);
    local.bytes(nameBytes).bytes(payload);

    central.u32(0x02014b50).u16(20).u16(20).u16(0).u16(stored ? 0 : 8).u16(0).u16(0);
    central.u32(checksum).u32(payload.length).u32(input.data.length);
    central.u16(nameBytes.length).u16(0).u16(0);
    central.u16(0).u16(0).u32(0);
    central.u32(offsets[offsets.length - 1]);
    central.bytes(nameBytes);
  }

  const localBytes = local.toBytes();
  const centralBytes = central.toBytes();
  const out = new Writer();
  out.bytes(localBytes).bytes(centralBytes);
  out.u32(0x06054b50).u16(0).u16(0);
  out.u16(inputs.length).u16(inputs.length);
  out.u32(centralBytes.length).u32(localBytes.length).u16(0);
  return out.toBytes();
}

// ---------------------------------------------------------------------------
// Whole APKs
// ---------------------------------------------------------------------------

export interface ManifestOptions {
  packageName?: string;
  versionCode?: number;
  versionName?: string;
  permissions?: string[];
  debuggable?: boolean;
  allowBackup?: boolean;
  /** Emitted only when set, so the default manifest stays byte-identical. */
  cleartextTraffic?: boolean;
  targetSdk?: number;
  minSdk?: number;
  exportedProvider?: boolean;
  /** Extra exported activities, to exercise component diffing. */
  extraExportedActivities?: string[];
}

const DEFAULT_PERMISSIONS = ['android.permission.CAMERA', 'android.permission.READ_SMS'];

/** Builds the manifest tree. Defaults reproduce the original fixed fixture. */
export function manifestSpec(options: ManifestOptions = {}): XmlNodeSpec {
  const {
    packageName = 'com.smartrealty.demo',
    versionCode = 42,
    versionName = '1.4.2',
    permissions = DEFAULT_PERMISSIONS,
    debuggable = true,
    allowBackup = false,
    cleartextTraffic,
    targetSdk = 34,
    minSdk = 24,
    exportedProvider = true,
    extraExportedActivities = [],
  } = options;

  const applicationAttrs: XmlAttrSpec[] = [
    { name: 'label', android: true, value: { kind: 'ref', id: 0x7f010000 } },
    { name: 'debuggable', android: true, value: { kind: 'bool', value: debuggable } },
    { name: 'allowBackup', android: true, value: { kind: 'bool', value: allowBackup } },
  ];
  if (cleartextTraffic !== undefined) {
    applicationAttrs.push({
      name: 'usesCleartextTraffic',
      android: true,
      value: { kind: 'bool', value: cleartextTraffic },
    });
  }

  return {
    name: 'manifest',
    attrs: [
      { name: 'package', android: false, value: { kind: 'string', text: packageName } },
      { name: 'versionCode', android: true, value: { kind: 'int', value: versionCode } },
      { name: 'versionName', android: true, value: { kind: 'string', text: versionName } },
    ],
    children: [
      {
        name: 'uses-sdk',
        attrs: [
          { name: 'minSdkVersion', android: true, value: { kind: 'int', value: minSdk } },
          { name: 'targetSdkVersion', android: true, value: { kind: 'int', value: targetSdk } },
        ],
      },
      ...permissions.map((permission) => ({
        name: 'uses-permission',
        attrs: [{ name: 'name', android: true, value: { kind: 'string' as const, text: permission } }],
      })),
      {
        name: 'application',
        attrs: applicationAttrs,
        children: [
          {
            name: 'activity',
            attrs: [{ name: 'name', android: true, value: { kind: 'string', text: '.MainActivity' } }],
            children: [
              {
                name: 'intent-filter',
                children: [
                  {
                    name: 'action',
                    attrs: [
                      {
                        name: 'name',
                        android: true,
                        value: { kind: 'string', text: 'android.intent.action.MAIN' },
                      },
                    ],
                  },
                  {
                    name: 'category',
                    attrs: [
                      {
                        name: 'name',
                        android: true,
                        value: { kind: 'string', text: 'android.intent.category.LAUNCHER' },
                      },
                    ],
                  },
                ],
              },
            ],
          },
          ...extraExportedActivities.map((name) => ({
            name: 'activity',
            attrs: [
              { name: 'name', android: true, value: { kind: 'string' as const, text: name } },
              { name: 'exported', android: true, value: { kind: 'bool' as const, value: true } },
            ],
          })),
          {
            name: 'provider',
            attrs: [
              { name: 'name', android: true, value: { kind: 'string', text: '.DataProvider' } },
              {
                name: 'authorities',
                android: true,
                value: { kind: 'string', text: `${packageName}.provider` },
              },
              { name: 'exported', android: true, value: { kind: 'bool', value: exportedProvider } },
            ],
          },
        ],
      },
    ],
  };
}

export interface ApkOptions extends ManifestOptions {
  extraEntries?: ZipInput[];
  /** Entry names to omit from META-INF/MANIFEST.MF, faking a post-signing add. */
  omitFromJarManifest?: string[];
  weakCertificate?: boolean;
  /** Reuse an exact certificate across versions, so the signer is unchanged. */
  certificate?: Uint8Array;
  label?: string;
  /** Extra bytes in classes.dex, to make otherwise identical APKs differ. */
  salt?: string;
}

/** Builds a complete, v1-signed APK. */
export function buildApk(options: ApkOptions = {}): Uint8Array {
  const axml = buildAxml(manifestSpec(options));
  const arsc = buildArsc(options.label ?? 'Smart Realty Demo');
  const certificate =
    options.certificate ??
    buildCertificate({
      commonName: options.weakCertificate ? 'Android Debug' : 'Smart Realty',
      organization: options.weakCertificate ? 'Android' : 'Smart Realty Inc',
      notBefore: new Date('2024-01-01T00:00:00Z'),
      notAfter: new Date('2044-01-01T00:00:00Z'),
      modulusLength: options.weakCertificate ? 1024 : 2048,
      weakSignatureAlgorithm: options.weakCertificate,
    });

  const content: ZipInput[] = [
    { name: 'AndroidManifest.xml', data: axml },
    { name: 'resources.arsc', data: arsc, store: true },
    {
      name: 'classes.dex',
      data: new TextEncoder().encode(`dex\n035\0${'A'.repeat(2000)}${options.salt ?? ''}`),
    },
    { name: 'lib/arm64-v8a/libsmartrealty.so', data: new TextEncoder().encode('ELF'.repeat(300)) },
    ...(options.extraEntries ?? []),
  ];

  const omitted = new Set(options.omitFromJarManifest ?? []);
  const covered = content.map((e) => e.name).filter((name) => !omitted.has(name));

  return buildZip([
    ...content,
    { name: 'META-INF/MANIFEST.MF', data: buildJarManifest(covered) },
    { name: 'META-INF/CERT.SF', data: new TextEncoder().encode('Signature-Version: 1.0\r\n\r\n') },
    { name: 'META-INF/CERT.RSA', data: buildPkcs7([certificate]), store: true },
  ]);
}

/** Builds a META-INF/MANIFEST.MF listing the given entry names. */
export function buildJarManifest(names: string[]): Uint8Array {
  const lines = ['Manifest-Version: 1.0', 'Created-By: fixtures', ''];
  for (const name of names) {
    lines.push(`Name: ${name}`, 'SHA-256-Digest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', '');
  }
  return new TextEncoder().encode(lines.join('\r\n'));
}
