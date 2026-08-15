/**
 * Comparisons that only exist across a set of packages.
 *
 * A single APK can look clean on its own and still be alarming in context: the
 * signing key changed between versions, an update quietly added SMS access, or
 * two catalog entries claim the same identity with different bytes. Everything
 * here emits the same `Finding` shape as the single-APK rules, so the UI needs
 * no second vocabulary.
 */

import type { ApkJsonReport } from './inspect.js';
import { HIGH_RISK_GROUPS, SENSITIVE_PERMISSIONS, sortFindings, type Finding, type Severity } from './safety.js';

export interface ScannedPackage {
  sourceId: string;
  report: ApkJsonReport;
}

export interface PackageVersionSummary {
  sourceId: string;
  versionCode: number | null;
  versionName: string | null;
  sha256: string;
  signerFingerprints: string[];
  score: number;
  worstSeverity: Severity | null;
  blockInstall: boolean;
}

export interface PackageSummary {
  package: string;
  versions: PackageVersionSummary[];
  /** Union of signing certificate fingerprints across every version seen. */
  signerFingerprints: string[];
  /** Findings produced by comparing this package's versions, and by pinning. */
  findings: Finding[];
}

/** Distinct signing-certificate SHA-256 fingerprints, sorted. */
export function signerFingerprints(report: ApkJsonReport): string[] {
  return [...new Set(report.certificates.map((c) => c.sha256))].sort();
}

function short(fingerprint: string): string {
  return fingerprint.slice(0, 16);
}

function versionLabel(report: ApkJsonReport): string {
  const name = report.versionName ?? '?';
  const code = report.versionCode ?? '?';
  return `${name} (${code})`;
}

/**
 * Compares two versions of the same package, oldest first.
 *
 * Only regressions and identity changes are reported; an update that tightens
 * something produces no finding.
 */
export function diffVersions(previous: ApkJsonReport, next: ApkJsonReport): Finding[] {
  const findings: Finding[] = [];
  const from = versionLabel(previous);
  const to = versionLabel(next);
  const pkg = next.package ?? previous.package ?? 'unknown package';

  // --- signing identity ---------------------------------------------------
  const before = signerFingerprints(previous);
  const after = signerFingerprints(next);
  const added = after.filter((f) => !before.includes(f));
  const removed = before.filter((f) => !after.includes(f));
  if ((added.length > 0 || removed.length > 0) && before.length > 0 && after.length > 0) {
    const overlapping = after.some((f) => before.includes(f));
    findings.push({
      id: 'diff.signer-changed',
      severity: overlapping ? 'medium' : 'high',
      title: overlapping
        ? 'Signing certificate set changed between versions'
        : 'Update is signed by a completely different key',
      detail:
        `${pkg} ${from} was signed by ${before.map(short).join(', ')}; ${to} is signed by ` +
        `${after.map(short).join(', ')}. Android rejects such an update unless the new key ` +
        `carries a valid v3 rotation lineage proving it succeeded the old one — this tool ` +
        `does not parse or verify that lineage, so confirm the rotation with the publisher.`,
      evidence: `${pkg}: ${before.map(short).join(',')} -> ${after.map(short).join(',')}`,
    });
  }

  // --- permissions --------------------------------------------------------
  const permissionsAdded = next.permissions.filter((p) => !previous.permissions.includes(p));
  const permissionsRemoved = previous.permissions.filter((p) => !next.permissions.includes(p));

  if (permissionsAdded.length > 0) {
    const sensitive = permissionsAdded
      .map((name) => ({ name, known: SENSITIVE_PERMISSIONS[name] }))
      .filter((p) => p.known !== undefined);
    const highRisk = sensitive.some((p) => HIGH_RISK_GROUPS.has(p.known!.group));
    const described = permissionsAdded.map((name) => {
      const known = SENSITIVE_PERMISSIONS[name];
      return known ? `${name} — ${known.note}` : name;
    });
    findings.push({
      id: 'diff.permissions-added',
      severity: highRisk ? 'medium' : sensitive.length > 0 ? 'low' : 'info',
      title: `Update requests ${permissionsAdded.length} new permission${permissionsAdded.length === 1 ? '' : 's'}`,
      detail: `${pkg} gained between ${from} and ${to}: ${described.join('; ')}`,
      evidence: permissionsAdded.slice(0, 3).join(', '),
    });
  }

  if (permissionsRemoved.length > 0) {
    findings.push({
      id: 'diff.permissions-removed',
      severity: 'info',
      title: `Update drops ${permissionsRemoved.length} permission${permissionsRemoved.length === 1 ? '' : 's'}`,
      detail: `${pkg} no longer requests: ${permissionsRemoved.join(', ')}`,
      evidence: permissionsRemoved.slice(0, 3).join(', '),
    });
  }

  // --- platform posture ---------------------------------------------------
  if (
    previous.targetSdkVersion !== null &&
    next.targetSdkVersion !== null &&
    next.targetSdkVersion < previous.targetSdkVersion
  ) {
    findings.push({
      id: 'diff.target-sdk-decreased',
      severity: 'medium',
      title: 'Update lowers the target SDK',
      detail: `${pkg} moved from targetSdkVersion ${previous.targetSdkVersion} to ${next.targetSdkVersion}, opting back out of platform protections the previous version accepted.`,
      evidence: `${previous.targetSdkVersion} -> ${next.targetSdkVersion}`,
    });
  }

  if (
    previous.minSdkVersion !== null &&
    next.minSdkVersion !== null &&
    next.minSdkVersion < previous.minSdkVersion
  ) {
    findings.push({
      id: 'diff.min-sdk-decreased',
      severity: 'info',
      title: 'Update lowers the minimum SDK',
      detail: `${pkg} moved from minSdkVersion ${previous.minSdkVersion} to ${next.minSdkVersion}, extending support to older, unpatched releases.`,
      evidence: `${previous.minSdkVersion} -> ${next.minSdkVersion}`,
    });
  }

  if (!previous.application.debuggable && next.application.debuggable) {
    findings.push({
      id: 'diff.debuggable-introduced',
      severity: 'high',
      title: 'Update turns on debuggable',
      detail: `${pkg} ${to} sets android:debuggable="true" where ${from} did not. That is normally a build mistake, and it lets anything with ADB access read the process.`,
      evidence: pkg,
    });
  }

  if (previous.application.usesCleartextTraffic !== true && next.application.usesCleartextTraffic === true) {
    findings.push({
      id: 'diff.cleartext-introduced',
      severity: 'medium',
      title: 'Update starts allowing cleartext HTTP',
      detail: `${pkg} ${to} sets android:usesCleartextTraffic="true" where ${from} did not.`,
      evidence: pkg,
    });
  }

  const exportedBefore = new Set(previous.exportedComponents.map((c) => `${c.kind}:${c.name}`));
  const exportedAdded = next.exportedComponents.filter(
    (c) => !exportedBefore.has(`${c.kind}:${c.name}`),
  );
  if (exportedAdded.length > 0) {
    const unprotected = exportedAdded.filter((c) => c.permission === null);
    findings.push({
      id: 'diff.exported-components-added',
      severity: unprotected.length > 0 ? 'medium' : 'info',
      title: `Update exports ${exportedAdded.length} new component${exportedAdded.length === 1 ? '' : 's'}`,
      detail:
        `${pkg} newly exposes: ${exportedAdded.slice(0, 5).map((c) => `${c.kind} ${c.name}`).join(', ')}` +
        `${exportedAdded.length > 5 ? ', …' : ''}. ` +
        (unprotected.length > 0
          ? `${unprotected.length} of them carry no android:permission, so any app on the device can reach them.`
          : 'All are permission-protected.'),
      evidence: exportedAdded[0].name,
    });
  }

  return findings;
}

/** SHA-256 fingerprints a package is expected to be signed by. */
export interface SignerPins {
  [packageName: string]: string[];
}

/**
 * Checks scanned packages against pinned signing keys.
 *
 * This is the actionable use of certificate fingerprints: signatures are parsed
 * but not verified, so the guarantee worth having is "this is the same key that
 * signed the build I already trusted".
 */
export function checkPins(entries: ScannedPackage[], pins: SignerPins): Finding[] {
  return sortFindings([...pinFindingsByPackage(entries, pins).values()].flat());
}

/** Pin findings keyed by package, so summaries can carry their own. */
function pinFindingsByPackage(
  entries: ScannedPackage[],
  pins: SignerPins,
): Map<string, Finding[]> {
  const byPackage = new Map<string, Finding[]>();
  const unpinnedReported = new Set<string>();

  const push = (pkg: string, finding: Finding): void => {
    const list = byPackage.get(pkg) ?? [];
    list.push(finding);
    byPackage.set(pkg, list);
  };

  for (const { sourceId, report } of entries) {
    const pkg = report.package;
    if (pkg === null) continue;

    const expected = pins[pkg];
    const actual = signerFingerprints(report);

    if (expected === undefined) {
      // One notice per package, not per version.
      if (unpinnedReported.has(pkg)) continue;
      unpinnedReported.add(pkg);
      push(pkg, {
        id: 'pin.unpinned',
        severity: 'info',
        title: 'Package has no pinned signing key',
        detail: `${pkg} is not listed in the pin file, so nothing constrains which key may sign it. Its current signer is ${actual.map(short).join(', ') || 'unknown'}.`,
        evidence: pkg,
      });
      continue;
    }

    const normalized = expected.map((f) => f.toLowerCase().replace(/:/g, ''));
    if (!actual.some((f) => normalized.includes(f))) {
      push(pkg, {
        id: 'pin.signer-mismatch',
        severity: 'critical',
        title: 'Package is signed by an unpinned key',
        detail: `${pkg} (${sourceId}) is signed by ${actual.map(short).join(', ') || 'no key'}, which is not among its pinned fingerprints ${normalized.map(short).join(', ')}. Treat this as a different publisher until proven otherwise.`,
        evidence: `${sourceId}: ${actual.map(short).join(',')}`,
      });
    }
  }

  return byPackage;
}

export interface BatchAnalysis {
  packages: PackageSummary[];
  /** Findings spanning the whole batch, worst-first. */
  findings: Finding[];
}

/**
 * Groups scanned packages, diffs consecutive versions, and looks for
 * cross-package integrity problems.
 */
export function analyzeBatch(entries: ScannedPackage[], pins?: SignerPins): BatchAnalysis {
  const byPackage = new Map<string, ScannedPackage[]>();
  for (const entry of entries) {
    const pkg = entry.report.package;
    if (pkg === null) continue; // already carries its own manifest finding
    const list = byPackage.get(pkg) ?? [];
    list.push(entry);
    byPackage.set(pkg, list);
  }

  const pinsByPackage = pins ? pinFindingsByPackage(entries, pins) : new Map<string, Finding[]>();

  const packages: PackageSummary[] = [];
  const batchFindings: Finding[] = [...pinsByPackage.values()].flat();

  for (const [pkg, list] of [...byPackage.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const ordered = [...list].sort(
      (a, b) =>
        (a.report.versionCode ?? 0) - (b.report.versionCode ?? 0) ||
        a.report.sha256.localeCompare(b.report.sha256),
    );

    const findings: Finding[] = [];
    for (let i = 1; i < ordered.length; i++) {
      findings.push(...diffVersions(ordered[i - 1].report, ordered[i].report));
    }

    // Two builds claiming one identity: same package and versionCode, different bytes.
    const byVersionCode = new Map<number | null, Set<string>>();
    for (const entry of ordered) {
      const set = byVersionCode.get(entry.report.versionCode) ?? new Set<string>();
      set.add(entry.report.sha256);
      byVersionCode.set(entry.report.versionCode, set);
    }
    for (const [versionCode, hashes] of byVersionCode) {
      if (hashes.size > 1) {
        findings.push({
          id: 'batch.identity-collision',
          severity: 'critical',
          title: 'Two different builds claim the same package and version',
          detail: `${pkg} versionCode ${versionCode ?? '?'} appears with ${hashes.size} different file hashes: ${[...hashes].sort().map(short).join(', ')}. At most one of these is the build the publisher released.`,
          evidence: `${pkg}@${versionCode ?? '?'}`,
        });
      }
    }

    const unionFingerprints = [
      ...new Set(ordered.flatMap((e) => signerFingerprints(e.report))),
    ].sort();

    packages.push({
      package: pkg,
      versions: ordered.map((entry) => ({
        sourceId: entry.sourceId,
        versionCode: entry.report.versionCode,
        versionName: entry.report.versionName,
        sha256: entry.report.sha256,
        signerFingerprints: signerFingerprints(entry.report),
        score: entry.report.safety.score,
        worstSeverity: entry.report.safety.worstSeverity,
        blockInstall: entry.report.safety.blockInstall,
      })),
      signerFingerprints: unionFingerprints,
      findings: sortFindings([...findings, ...(pinsByPackage.get(pkg) ?? [])]),
    });

    batchFindings.push(...findings);
  }

  // Distinct packages sharing a key — useful for grouping a catalog by publisher.
  const packagesByFingerprint = new Map<string, Set<string>>();
  for (const summary of packages) {
    for (const fingerprint of summary.signerFingerprints) {
      const set = packagesByFingerprint.get(fingerprint) ?? new Set<string>();
      set.add(summary.package);
      packagesByFingerprint.set(fingerprint, set);
    }
  }
  for (const [fingerprint, pkgs] of [...packagesByFingerprint.entries()].sort()) {
    if (pkgs.size > 1) {
      batchFindings.push({
        id: 'batch.shared-signer',
        severity: 'info',
        title: 'Several packages share a signing key',
        detail: `${[...pkgs].sort().join(', ')} are signed by ${short(fingerprint)}. That normally means one publisher, and it means they can share a sandbox if they also share a userId.`,
        evidence: short(fingerprint),
      });
    }
  }

  return { packages, findings: sortFindings(batchFindings) };
}
