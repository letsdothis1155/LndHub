/**
 * Batch scanning, cross-version diffing, pinning and report assembly.
 *
 * Invoked from test/run.ts so `npm test` stays one command.
 */

import { scanBatch, sourceFromBytes, BatchAbortError, type ApkSource, type ScanResult } from '../src/batch.js';
import { analyzeBatch, checkPins, diffVersions, signerFingerprints } from '../src/diff.js';
import { buildBatchReport, meetsThreshold, toCsv, worstSeverityOf } from '../src/report.js';
import { inspectApk, toJsonReport, type ApkJsonReport } from '../src/inspect.js';
import { buildApk, buildCertificate } from './fixtures.js';

type Check = (name: string, condition: boolean, detail?: string) => void;
type Equal = <T>(name: string, actual: T, expected: T) => void;

const FIXED_NOW = new Date('2025-06-01T00:00:00Z');

const SIGNER_A = buildCertificate({
  commonName: 'Smart Realty',
  organization: 'Smart Realty Inc',
  notBefore: new Date('2024-01-01T00:00:00Z'),
  notAfter: new Date('2044-01-01T00:00:00Z'),
});
const SIGNER_B = buildCertificate({
  commonName: 'Someone Else',
  organization: 'Other Publisher Ltd',
  notBefore: new Date('2024-01-01T00:00:00Z'),
  notAfter: new Date('2044-01-01T00:00:00Z'),
});

async function reportFor(bytes: Uint8Array): Promise<ApkJsonReport> {
  return toJsonReport(await inspectApk(bytes, { now: FIXED_NOW }));
}

export async function testBatch(check: Check, equal: Equal): Promise<void> {
  // -------------------------------------------------------------------------
  // scanBatch: isolation, ordering, cancellation, memory
  // -------------------------------------------------------------------------

  const good = buildApk({ certificate: SIGNER_A });
  const alsoGood = buildApk({ packageName: 'com.smartrealty.other', certificate: SIGNER_A });
  const sources: ApkSource[] = [
    sourceFromBytes('a.apk', good),
    sourceFromBytes('broken.apk', new TextEncoder().encode('definitely not an archive')),
    sourceFromBytes('c.apk', alsoGood),
  ];

  const results = await scanBatch(sources, { now: FIXED_NOW });
  equal('batch: every source produces a result', results.length, 3);
  equal('batch: results keep input order', results.map((r) => r.sourceId).join(','), 'a.apk,broken.apk,c.apk');
  equal('batch: good source succeeded', results[0].status, 'ok');
  equal('batch: bad source isolated as failed', results[1].status, 'failed');
  equal('batch: batch continues past the failure', results[2].status, 'ok');
  check(
    'batch: failure carries a message',
    results[1].status === 'failed' && results[1].error.length > 0,
  );

  // The whole point of the JSON projection: no APK bytes retained.
  const ok = results[0];
  check('batch: no inspection retained by default', !('inspection' in ok) || ok.inspection === undefined);
  check(
    'batch: result is JSON-serialisable',
    (() => {
      try {
        return JSON.stringify(ok).includes('com.smartrealty.demo');
      } catch {
        return false;
      }
    })(),
  );

  const kept = await scanBatch([sources[0]], { now: FIXED_NOW, keepInspections: true });
  check(
    'batch: keepInspections returns the inspection',
    kept[0].status === 'ok' && kept[0].inspection !== undefined,
  );

  // Ordering must not depend on completion order.
  const manySources = Array.from({ length: 12 }, (_, i) =>
    sourceFromBytes(`pkg-${String(i).padStart(2, '0')}.apk`, i % 4 === 0 ? alsoGood : good),
  );
  const serial = await scanBatch(manySources, { concurrency: 1, now: FIXED_NOW });
  const parallel = await scanBatch(manySources, { concurrency: 8, now: FIXED_NOW });
  equal(
    'batch: concurrency does not change result order',
    parallel.map((r) => r.sourceId).join(','),
    serial.map((r) => r.sourceId).join(','),
  );
  equal('batch: no results dropped under concurrency', parallel.length, 12);
  equal(
    'batch: no duplicates under concurrency',
    new Set(parallel.map((r) => r.sourceId)).size,
    12,
  );

  // Progress fires once per source.
  let progressCalls = 0;
  let lastCompleted = 0;
  await scanBatch(manySources, {
    concurrency: 4,
    now: FIXED_NOW,
    onProgress: ({ completed, total }) => {
      progressCalls++;
      lastCompleted = completed;
      if (total !== 12) check('batch: progress reports the right total', false);
    },
  });
  equal('batch: progress fires once per source', progressCalls, 12);
  equal('batch: progress ends at the total', lastCompleted, 12);

  // Cancellation: in-flight items finish, the rest are never started.
  const controller = new AbortController();
  let loadCount = 0;
  const slowSources: ApkSource[] = Array.from({ length: 10 }, (_, i) => ({
    id: `slow-${i}.apk`,
    load: async () => {
      loadCount++;
      if (loadCount === 2) controller.abort();
      return good;
    },
  }));
  let aborted = false;
  let partial = 0;
  try {
    await scanBatch(slowSources, { concurrency: 1, signal: controller.signal });
  } catch (error) {
    aborted = error instanceof BatchAbortError && error.name === 'AbortError';
    if (error instanceof BatchAbortError) partial = error.partialResults.length;
  }
  check('batch: abort rejects with AbortError', aborted);
  check('batch: abort stops early', loadCount < 10, `${loadCount} sources loaded`);
  check('batch: abort carries partial results', partial > 0 && partial < 10, `${partial} partial`);

  const preAborted = new AbortController();
  preAborted.abort();
  let refusedUpFront = false;
  try {
    await scanBatch(sources, { signal: preAborted.signal });
  } catch (error) {
    refusedUpFront = error instanceof BatchAbortError;
  }
  check('batch: already-aborted signal starts nothing', refusedUpFront);

  // -------------------------------------------------------------------------
  // diffVersions
  // -------------------------------------------------------------------------

  const v1 = await reportFor(buildApk({ versionCode: 1, versionName: '1.0', certificate: SIGNER_A }));
  const v2SameKey = await reportFor(
    buildApk({ versionCode: 2, versionName: '2.0', certificate: SIGNER_A }),
  );
  equal('diff: identical posture produces no findings', diffVersions(v1, v2SameKey).length, 0);

  const v2NewKey = await reportFor(
    buildApk({ versionCode: 2, versionName: '2.0', certificate: SIGNER_B }),
  );
  const keyFindings = diffVersions(v1, v2NewKey);
  const signerFinding = keyFindings.find((f) => f.id === 'diff.signer-changed');
  check('diff: signer change detected', signerFinding !== undefined);
  equal('diff: disjoint signer change is high', signerFinding?.severity, 'high');
  check(
    'diff: signer finding does not claim to verify rotation',
    signerFinding?.detail.includes('does not parse or verify') === true,
  );

  const v2MorePerms = await reportFor(
    buildApk({
      versionCode: 2,
      certificate: SIGNER_A,
      permissions: [
        'android.permission.CAMERA',
        'android.permission.READ_SMS',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
      ],
    }),
  );
  const permFindings = diffVersions(v1, v2MorePerms);
  const added = permFindings.find((f) => f.id === 'diff.permissions-added');
  check('diff: added permission detected', added !== undefined);
  equal('diff: high-risk permission group lifts severity', added?.severity, 'medium');
  check(
    'diff: added permission is explained',
    added?.detail.includes('everything shown on screen') === true,
  );

  const v2FewerPerms = await reportFor(
    buildApk({ versionCode: 2, certificate: SIGNER_A, permissions: ['android.permission.CAMERA'] }),
  );
  check(
    'diff: removed permission detected',
    diffVersions(v1, v2FewerPerms).some((f) => f.id === 'diff.permissions-removed'),
  );

  const v2OldTarget = await reportFor(
    buildApk({ versionCode: 2, certificate: SIGNER_A, targetSdk: 28 }),
  );
  const regression = diffVersions(v1, v2OldTarget).find((f) => f.id === 'diff.target-sdk-decreased');
  check('diff: target SDK regression detected', regression !== undefined);
  equal('diff: target SDK regression is medium', regression?.severity, 'medium');

  const cleanV1 = await reportFor(
    buildApk({ versionCode: 1, certificate: SIGNER_A, debuggable: false }),
  );
  const debugV2 = await reportFor(
    buildApk({ versionCode: 2, certificate: SIGNER_A, debuggable: true }),
  );
  const debugFinding = diffVersions(cleanV1, debugV2).find(
    (f) => f.id === 'diff.debuggable-introduced',
  );
  check('diff: newly debuggable detected', debugFinding !== undefined);
  equal('diff: newly debuggable is high', debugFinding?.severity, 'high');
  check(
    'diff: debuggable removal is not flagged',
    !diffVersions(debugV2, cleanV1).some((f) => f.id === 'diff.debuggable-introduced'),
  );

  const cleartextV2 = await reportFor(
    buildApk({ versionCode: 2, certificate: SIGNER_A, cleartextTraffic: true }),
  );
  check(
    'diff: newly allowed cleartext detected',
    diffVersions(v1, cleartextV2).some((f) => f.id === 'diff.cleartext-introduced'),
  );

  const moreExported = await reportFor(
    buildApk({
      versionCode: 2,
      certificate: SIGNER_A,
      extraExportedActivities: ['.AdminActivity'],
    }),
  );
  const exportedFinding = diffVersions(v1, moreExported).find(
    (f) => f.id === 'diff.exported-components-added',
  );
  check('diff: newly exported component detected', exportedFinding !== undefined);
  check('diff: exported finding names the component', exportedFinding?.evidence === '.AdminActivity');

  // -------------------------------------------------------------------------
  // analyzeBatch: cross-package
  // -------------------------------------------------------------------------

  const collisionA = buildApk({ versionCode: 7, certificate: SIGNER_A, salt: 'one' });
  const collisionB = buildApk({ versionCode: 7, certificate: SIGNER_A, salt: 'two' });
  const collisionResults = await scanBatch(
    [sourceFromBytes('one.apk', collisionA), sourceFromBytes('two.apk', collisionB)],
    { now: FIXED_NOW },
  );
  const collisionAnalysis = analyzeBatch(
    collisionResults.flatMap((r) => (r.status === 'ok' ? [{ sourceId: r.sourceId, report: r.report }] : [])),
  );
  const collision = collisionAnalysis.findings.find((f) => f.id === 'batch.identity-collision');
  check('batch: identity collision detected', collision !== undefined);
  equal('batch: identity collision is critical', collision?.severity, 'critical');

  const sharedSignerAnalysis = analyzeBatch([
    { sourceId: 'a.apk', report: await reportFor(good) },
    { sourceId: 'c.apk', report: await reportFor(alsoGood) },
  ]);
  check(
    'batch: shared signer across packages detected',
    sharedSignerAnalysis.findings.some((f) => f.id === 'batch.shared-signer'),
  );
  equal('batch: two packages summarised', sharedSignerAnalysis.packages.length, 2);
  equal(
    'batch: packages sorted by name',
    sharedSignerAnalysis.packages.map((p) => p.package).join(','),
    'com.smartrealty.demo,com.smartrealty.other',
  );

  // -------------------------------------------------------------------------
  // Pinning
  // -------------------------------------------------------------------------

  const goodReport = await reportFor(good);
  const expectedFingerprint = signerFingerprints(goodReport)[0];
  const entries = [{ sourceId: 'a.apk', report: goodReport }];

  equal(
    'pins: matching pin produces no findings',
    checkPins(entries, { 'com.smartrealty.demo': [expectedFingerprint] }).length,
    0,
  );
  check(
    'pins: colon-separated uppercase pins are accepted',
    checkPins(entries, {
      'com.smartrealty.demo': [(expectedFingerprint.match(/../g) ?? []).join(':').toUpperCase()],
    }).length === 0,
  );
  const mismatch = checkPins(entries, { 'com.smartrealty.demo': ['00'.repeat(32)] });
  equal('pins: mismatch is critical', mismatch[0]?.severity, 'critical');
  equal('pins: mismatch id', mismatch[0]?.id, 'pin.signer-mismatch');
  const unpinned = checkPins(entries, {});
  equal('pins: unpinned package noted', unpinned[0]?.id, 'pin.unpinned');
  equal('pins: unpinned is info', unpinned[0]?.severity, 'info');

  const pinnedAnalysis = analyzeBatch(entries, { 'com.smartrealty.demo': ['00'.repeat(32)] });
  check(
    'pins: mismatch attaches to its package summary',
    pinnedAnalysis.packages[0].findings.some((f) => f.id === 'pin.signer-mismatch'),
  );

  // -------------------------------------------------------------------------
  // Report assembly, determinism, CSV
  // -------------------------------------------------------------------------

  const reportSources = [
    sourceFromBytes('a.apk', good),
    sourceFromBytes('broken.apk', new TextEncoder().encode('not an archive')),
    sourceFromBytes('c.apk', alsoGood),
  ];
  const runOne = await scanBatch(reportSources, { now: FIXED_NOW });
  const runTwo = await scanBatch(reportSources, { concurrency: 3, now: FIXED_NOW });
  const reportOne = buildBatchReport(runOne, { generatedAt: FIXED_NOW });
  const reportTwo = buildBatchReport(runTwo, { generatedAt: FIXED_NOW });

  equal(
    'report: two runs are byte-identical',
    JSON.stringify(reportOne),
    JSON.stringify(reportTwo),
  );
  equal('report: schema version', reportOne.schemaVersion, 1);
  equal('report: generatedAt is the injected clock', reportOne.generatedAt, FIXED_NOW.toISOString());
  equal('report: totals scanned', reportOne.totals.scanned, 3);
  equal('report: totals ok', reportOne.totals.ok, 2);
  equal('report: totals failed', reportOne.totals.failed, 1);
  check('report: blocked counted', reportOne.totals.blocked >= 1);
  check(
    'report: timings excluded by default',
    reportOne.results.every((r) => r.durationMs === undefined),
  );
  check(
    'report: timings included on request',
    buildBatchReport(runOne, { generatedAt: FIXED_NOW, includeTimings: true }).results.some(
      (r) => typeof r.durationMs === 'number',
    ),
  );
  // These fixtures are v1-signed but not unsigned, so nothing reaches critical.
  equal('report: worst severity surfaced', worstSeverityOf(reportOne), 'high');
  check('report: fail-on high trips', meetsThreshold(reportOne, 'high'));
  check(
    'report: a lower threshold still trips on a high finding',
    meetsThreshold(reportOne, 'low'),
  );
  check(
    'report: a stricter threshold does not trip below it',
    !meetsThreshold(reportOne, 'critical'),
  );

  // v1-only signing is itself a high finding once targetSdk reaches 30, so a
  // fixture with no high findings has to target lower. That interplay is the
  // intended behaviour, not a workaround.
  const belowHigh = buildApk({
    certificate: SIGNER_A,
    debuggable: false,
    exportedProvider: false,
    targetSdk: 29,
    permissions: [],
  });
  const cleanResults = await scanBatch([sourceFromBytes('clean.apk', belowHigh)], { now: FIXED_NOW });
  const cleanReport = buildBatchReport(cleanResults, { generatedAt: FIXED_NOW });
  check(
    'report: a package with no high findings does not trip fail-on high',
    !meetsThreshold(cleanReport, 'high'),
    `worst was ${worstSeverityOf(cleanReport)}`,
  );
  check('report: that package still trips fail-on medium', meetsThreshold(cleanReport, 'medium'));

  // CSV
  const csv = toCsv(reportOne);
  const csvLines = csv.trim().split('\n');
  equal('csv: header plus one row per result', csvLines.length, 4);
  check('csv: header names the columns', csvLines[0].startsWith('sourceId,status,package'));
  check('csv: failed row carries the error', csv.includes('broken.apk,failed'));

  const trickyReport = buildBatchReport(
    [
      {
        status: 'failed',
        sourceId: 'weird, "name".apk',
        error: 'broke\non two lines',
        durationMs: 0,
      } satisfies ScanResult,
    ],
    { generatedAt: FIXED_NOW },
  );
  const trickyCsv = toCsv(trickyReport);
  check('csv: commas and quotes are escaped', trickyCsv.includes('"weird, ""name"".apk"'));
  check('csv: newlines are quoted, not raw', trickyCsv.includes('"broke\non two lines"'));
}
