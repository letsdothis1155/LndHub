/**
 * Typed AndroidManifest.xml model built on top of the AXML parser.
 *
 * Attribute lookup goes by resource id first and local name second. Release
 * builds normally keep framework attribute names in the string pool, but
 * several obfuscators blank them out; the resource map survives that, because
 * the platform itself needs it.
 */

import type { ResourceTable } from './arsc.js';
import {
  ANDROID_NAMESPACE,
  TYPE_INT_BOOLEAN,
  TYPE_INT_DEC,
  TYPE_INT_HEX,
  TYPE_REFERENCE,
  TYPE_STRING,
  parseAxml,
  type AxmlAttribute,
  type AxmlElement,
} from './axml.js';

/**
 * Framework attribute resource ids, used only when the string pool has no
 * usable name. Best-effort by design: an unrecognised id simply falls back to
 * the (possibly empty) pool name.
 */
const ANDROID_ATTR_IDS: Record<number, string> = {
  0x01010000: 'theme',
  0x01010001: 'label',
  0x01010002: 'icon',
  0x01010003: 'name',
  0x01010006: 'permission',
  0x01010007: 'readPermission',
  0x01010008: 'writePermission',
  0x01010009: 'protectionLevel',
  0x0101000c: 'hasCode',
  0x0101000e: 'enabled',
  0x0101000f: 'debuggable',
  0x01010010: 'exported',
  0x01010011: 'process',
  0x01010018: 'authorities',
  0x0101001b: 'grantUriPermissions',
  0x0101020c: 'minSdkVersion',
  0x0101021b: 'versionCode',
  0x0101021c: 'versionName',
  0x01010270: 'targetSdkVersion',
  0x01010271: 'maxSdkVersion',
  0x01010280: 'allowBackup',
  0x010104ea: 'extractNativeLibs',
  0x010104ec: 'usesCleartextTraffic',
  0x01010572: 'compileSdkVersion',
};

export type ComponentKind = 'activity' | 'activity-alias' | 'service' | 'receiver' | 'provider';

export interface IntentFilter {
  actions: string[];
  categories: string[];
  dataSchemes: string[];
  dataHosts: string[];
}

export interface ManifestComponent {
  kind: ComponentKind;
  name: string;
  /** The android:exported value as written, or null when absent. */
  declaredExported: boolean | null;
  /** exported after applying the platform's defaulting rules. */
  effectiveExported: boolean;
  permission: string | null;
  authorities: string[];
  grantUriPermissions: boolean;
  enabled: boolean;
  process: string | null;
  intentFilters: IntentFilter[];
}

export interface DeclaredPermission {
  name: string;
  protectionLevel: string | null;
}

export interface UsesPermission {
  name: string;
  maxSdkVersion: number | null;
}

export interface ApplicationInfo {
  name: string | null;
  label: string | null;
  icon: string | null;
  debuggable: boolean;
  allowBackup: boolean;
  usesCleartextTraffic: boolean | null;
  networkSecurityConfig: string | null;
  hasCode: boolean;
  testOnly: boolean;
  extractNativeLibs: boolean | null;
  appComponentFactory: string | null;
}

export interface AndroidManifest {
  package: string | null;
  versionCode: number | null;
  versionName: string | null;
  compileSdkVersion: number | null;
  minSdkVersion: number | null;
  targetSdkVersion: number | null;
  maxSdkVersion: number | null;
  sharedUserId: string | null;
  installLocation: string | null;
  usesPermissions: UsesPermission[];
  declaredPermissions: DeclaredPermission[];
  usesFeatures: { name: string; required: boolean }[];
  usesLibraries: { name: string; required: boolean }[];
  application: ApplicationInfo;
  components: ManifestComponent[];
  /** The parsed tree, for callers that want to show the full manifest. */
  root: AxmlElement;
}

class AttributeLens {
  constructor(private readonly resources: ResourceTable | null) {}

  /** Attribute lookup by android-namespace name, then resource id, then any name. */
  find(element: AxmlElement, name: string): AxmlAttribute | undefined {
    const byName = element.attributes.find(
      (a) => a.name === name && (a.namespace === ANDROID_NAMESPACE || a.namespace === null),
    );
    if (byName) return byName;
    for (const attr of element.attributes) {
      if (attr.resourceId !== null && ANDROID_ATTR_IDS[attr.resourceId] === name) return attr;
    }
    return element.attributes.find((a) => a.name === name);
  }

  string(element: AxmlElement, name: string): string | null {
    const attr = this.find(element, name);
    if (!attr) return null;
    if (attr.type === TYPE_STRING) return attr.rawValue ?? attr.value;
    if (attr.type === TYPE_REFERENCE && this.resources) {
      const resolved = this.resources.resolveString(attr.data >>> 0);
      if (resolved !== null) return resolved;
    }
    return attr.value;
  }

  int(element: AxmlElement, name: string): number | null {
    const attr = this.find(element, name);
    if (!attr) return null;
    if (attr.type === TYPE_INT_DEC || attr.type === TYPE_INT_HEX) return attr.data | 0;
    if (attr.type === TYPE_REFERENCE && this.resources) {
      const resolved = this.resources.resolveInt(attr.data >>> 0);
      if (resolved !== null) return resolved;
    }
    if (attr.type === TYPE_STRING) {
      const parsed = Number.parseInt(attr.rawValue ?? '', 10);
      return Number.isFinite(parsed) ? parsed : null;
    }
    return null;
  }

  bool(element: AxmlElement, name: string): boolean | null {
    const attr = this.find(element, name);
    if (!attr) return null;
    if (attr.type === TYPE_INT_BOOLEAN) return attr.data !== 0;
    if (attr.type === TYPE_STRING) return (attr.rawValue ?? '').toLowerCase() === 'true';
    if (attr.type === TYPE_REFERENCE && this.resources) {
      const resolved = this.resources.resolveInt(attr.data >>> 0);
      if (resolved !== null) return resolved !== 0;
    }
    return null;
  }
}

function parseIntentFilters(element: AxmlElement, lens: AttributeLens): IntentFilter[] {
  return element.children
    .filter((c) => c.name === 'intent-filter')
    .map((filter) => ({
      actions: filter.children
        .filter((c) => c.name === 'action')
        .map((c) => lens.string(c, 'name') ?? '')
        .filter(Boolean),
      categories: filter.children
        .filter((c) => c.name === 'category')
        .map((c) => lens.string(c, 'name') ?? '')
        .filter(Boolean),
      dataSchemes: filter.children
        .filter((c) => c.name === 'data')
        .map((c) => lens.string(c, 'scheme') ?? '')
        .filter(Boolean),
      dataHosts: filter.children
        .filter((c) => c.name === 'data')
        .map((c) => lens.string(c, 'host') ?? '')
        .filter(Boolean),
    }));
}

const COMPONENT_TAGS: ComponentKind[] = [
  'activity',
  'activity-alias',
  'service',
  'receiver',
  'provider',
];

export interface ParseManifestOptions {
  /** Resource table used to resolve @references such as the app label. */
  resources?: ResourceTable | null;
}

/** Parses a binary AndroidManifest.xml into a typed model. */
export function parseAndroidManifest(
  axmlBytes: Uint8Array,
  options: ParseManifestOptions = {},
): AndroidManifest {
  const root = parseAxml(axmlBytes);
  return buildManifest(root, options.resources ?? null);
}

export function buildManifest(root: AxmlElement, resources: ResourceTable | null): AndroidManifest {
  const lens = new AttributeLens(resources);

  const usesSdk = root.children.find((c) => c.name === 'uses-sdk');
  const applicationEl = root.children.find((c) => c.name === 'application');

  const targetSdkVersion = usesSdk ? lens.int(usesSdk, 'targetSdkVersion') : null;
  const minSdkVersion = usesSdk ? lens.int(usesSdk, 'minSdkVersion') : null;

  const application: ApplicationInfo = applicationEl
    ? {
        name: lens.string(applicationEl, 'name'),
        label: lens.string(applicationEl, 'label'),
        icon: lens.string(applicationEl, 'icon'),
        debuggable: lens.bool(applicationEl, 'debuggable') ?? false,
        allowBackup: lens.bool(applicationEl, 'allowBackup') ?? true,
        usesCleartextTraffic: lens.bool(applicationEl, 'usesCleartextTraffic'),
        networkSecurityConfig: lens.string(applicationEl, 'networkSecurityConfig'),
        hasCode: lens.bool(applicationEl, 'hasCode') ?? true,
        testOnly: lens.bool(applicationEl, 'testOnly') ?? false,
        extractNativeLibs: lens.bool(applicationEl, 'extractNativeLibs'),
        appComponentFactory: lens.string(applicationEl, 'appComponentFactory'),
      }
    : {
        name: null,
        label: null,
        icon: null,
        debuggable: false,
        allowBackup: true,
        usesCleartextTraffic: null,
        networkSecurityConfig: null,
        hasCode: true,
        testOnly: false,
        extractNativeLibs: null,
        appComponentFactory: null,
      };

  const components: ManifestComponent[] = [];
  if (applicationEl) {
    for (const child of applicationEl.children) {
      const kind = COMPONENT_TAGS.find((tag) => tag === child.name);
      if (!kind) continue;
      const intentFilters = parseIntentFilters(child, lens);
      const declaredExported = lens.bool(child, 'exported');
      const effectiveExported =
        declaredExported ??
        (kind === 'provider'
          ? targetSdkVersion === null || targetSdkVersion < 17
          : intentFilters.length > 0);
      const authorities = (lens.string(child, 'authorities') ?? '')
        .split(';')
        .map((s) => s.trim())
        .filter(Boolean);

      components.push({
        kind,
        name: lens.string(child, 'name') ?? '',
        declaredExported,
        effectiveExported,
        permission: lens.string(child, 'permission'),
        authorities,
        grantUriPermissions: lens.bool(child, 'grantUriPermissions') ?? false,
        enabled: lens.bool(child, 'enabled') ?? true,
        process: lens.string(child, 'process'),
        intentFilters,
      });
    }
  }

  return {
    package: lens.string(root, 'package'),
    versionCode: lens.int(root, 'versionCode'),
    versionName: lens.string(root, 'versionName'),
    compileSdkVersion: lens.int(root, 'compileSdkVersion'),
    minSdkVersion,
    targetSdkVersion,
    maxSdkVersion: usesSdk ? lens.int(usesSdk, 'maxSdkVersion') : null,
    sharedUserId: lens.string(root, 'sharedUserId'),
    installLocation: lens.string(root, 'installLocation'),
    usesPermissions: root.children
      .filter((c) => c.name === 'uses-permission' || c.name === 'uses-permission-sdk-23')
      .map((c) => ({
        name: lens.string(c, 'name') ?? '',
        maxSdkVersion: lens.int(c, 'maxSdkVersion'),
      }))
      .filter((p) => p.name !== ''),
    declaredPermissions: root.children
      .filter((c) => c.name === 'permission')
      .map((c) => ({
        name: lens.string(c, 'name') ?? '',
        protectionLevel: lens.string(c, 'protectionLevel'),
      }))
      .filter((p) => p.name !== ''),
    usesFeatures: root.children
      .filter((c) => c.name === 'uses-feature')
      .map((c) => ({ name: lens.string(c, 'name') ?? '', required: lens.bool(c, 'required') ?? true }))
      .filter((f) => f.name !== ''),
    usesLibraries: applicationEl
      ? applicationEl.children
          .filter((c) => c.name === 'uses-library')
          .map((c) => ({
            name: lens.string(c, 'name') ?? '',
            required: lens.bool(c, 'required') ?? true,
          }))
          .filter((l) => l.name !== '')
      : [],
    application,
    components,
    root,
  };
}
