/**
 * Records the standalone ISMS engine's outputs so the Python port can be held to them
 * (cloud/tests/test_isms_parity.py). Run it from a checkout of the frozen standalone app:
 *
 *   cd <ISMS checkout> && pnpm install
 *   node_modules/.bin/tsx <fenrir>/scripts/isms/parity_fixtures.mts <ISMS checkout> <fenrir>
 *
 * It reads the packs from Fenrir's copy (cloud/fenrir_cloud/isms/packs) and writes
 * cloud/tests/fixtures/isms_parity.json.gz. The cases are random but seeded, so a rerun gives the same file.
 */
import { createRequire } from 'node:module';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

const [ismsDir, fenrirDir] = process.argv.slice(2);
if (!ismsDir || !fenrirDir) throw new Error('usage: parity_fixtures.mts <ISMS checkout> <fenrir checkout>');
const domain = await import(join(ismsDir, 'packages/domain/src/index.ts'));
const { parse } = createRequire(join(ismsDir, 'packages/content/package.json'))('yaml');

// Seeded PRNG (mulberry32).
let seed = 20261125;
const rand = () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T;
const int = (n: number) => Math.floor(rand() * n);

// 1. Expressions ------------------------------------------------------------------------------------------
const VARS = ['a', 'b', 'c', 'n', 'list', 'missing'];
const LITERALS: unknown[] = [
  0, 1, 2, -1, 1.5, 10, 120, '', '0', '1', '10', '1.5', 'a', 'b', 'abc', ' 5 ', '1e2', 'true', 'x,y',
  true, false, null, [], [1], [1, 2], ['a'], ['a', 'b'], [''], [null],
];
const OPS = ['==', '!=', '===', '!==', '<', '<=', '>', '>=', '!', '!!', 'and', 'or', 'in', 'if', 'var'];
const literal = () => structuredClone(pick(LITERALS));
function expr(depth: number): unknown {
  if (depth <= 0 || rand() < 0.3) return rand() < 0.4 ? { var: pick(VARS) } : literal();
  const op = pick(OPS);
  const sub = () => expr(depth - 1);
  switch (op) {
    case 'var':
      return rand() < 0.5 ? { var: pick(VARS) } : { var: [pick(VARS), sub()] };
    case '!':
    case '!!':
      return { [op]: rand() < 0.5 ? [sub()] : sub() };
    case 'and':
    case 'or':
      return { [op]: Array.from({ length: 1 + int(3) }, sub) };
    case 'if':
      return { if: [sub(), sub(), sub()] };
    default:
      return { [op]: [sub(), sub()] };
  }
}
const answers = () =>
  Object.fromEntries(VARS.filter((v) => v !== 'missing' && rand() < 0.85).map((v) => [v, literal()]));

const expressions = [];
for (let i = 0; i < 3000; i++) {
  const e = expr(3);
  const a = answers();
  let result: unknown;
  try {
    result = { value: domain.evaluate(e, a) };
  } catch {
    result = { error: true };
  }
  expressions.push({ expression: e, answers: a, ...(result as object) });
}
// Malformed expressions: the parser must report the same number of issues and the same variables.
const MALFORMED: unknown[] = [{}, { '==': [1] }, { a: 1, b: 2 }, { var: '' }, { var: [3] }, { regex: ['x'] },
  { and: [] }, { if: [1, 2] }, { '!': [1, 2] }, [{ var: 'a' }, { nope: 1 }]];
const parses = MALFORMED.map((e) => ({ expression: e, ...domain.parseExpression(e) }));

// 2. Applicability over the real packs ---------------------------------------------------------------------
const packsRoot = join(fenrirDir, 'cloud/fenrir_cloud/isms/packs');
const readYaml = (p: string) => parse(readFileSync(p, 'utf8'));
const groups: object[] = [];
const requirements: object[] = [];
const mappings: { control: string }[] = [];
const rules: object[] = [];
const questions: { ref: string; type: string; options?: { value: string }[] }[] = [];
const sections: string[] = [];
for (const dir of readdirSync(packsRoot).sort()) {
  const d = join(packsRoot, dir);
  if (!statSync(d).isDirectory() || dir === 'questionnaires') continue;
  const meta = readYaml(join(d, 'pack.yaml'));
  const file = (n: string) => {
    try {
      return readYaml(join(d, `${n}.yaml`)) ?? [];
    } catch {
      return [];
    }
  };
  if (meta.kind === 'templates') {
    for (const f of readdirSync(d).filter((f) => f.endsWith('.md'))) {
      const fm = /^---\n([\s\S]*?)\n---/.exec(readFileSync(join(d, f), 'utf8'));
      sections.push(...((fm && parse(fm[1]).sections) ?? []));
    }
  }
  questions.push(...file('questions'));
  if (meta.kind !== 'framework') continue;
  const fw = meta.framework;
  for (const g of file('groups')) groups.push({ framework: fw, ref: g.ref, parent: g.parent ?? null });
  for (const r of file('requirements'))
    requirements.push({ framework: fw, ref: r.ref, group: r.group, mandatory: r.mandatory ?? false });
  for (const m of file('mappings'))
    mappings.push({ framework: fw, requirement: m.requirement, control: m.control, strength: m.strength });
  for (const r of file('rules'))
    rules.push({ ref: r.ref, framework: fw, when: r.when, effect: r.effect, reason: r.reason, targets: r.targets });
}
const base = {
  groups,
  requirements,
  controls: [...new Set(mappings.map((m) => m.control))].sort(),
  templateSections: [...new Set(sections)].sort(),
  mappings,
  rules,
};
const answerFor = (q: (typeof questions)[number]) => {
  if (q.type === 'bool') return rand() < 0.5;
  if (q.type === 'number') return pick([0, 1, 9, 10, 49, 50, 250, 1000]);
  const values = (q.options ?? []).map((o) => o.value);
  if (q.type === 'single') return pick(values);
  return values.filter(() => rand() < 0.4);
};
const keys = [
  ...requirements.map((r: any) => ({ type: 'requirement', key: `${r.framework}:${r.ref}` })),
  ...base.controls.map((c) => ({ type: 'control', key: c })),
  ...base.templateSections.map((s) => ({ type: 'template_section', key: s })),
];
const serialize = (decisions: Map<string, any>) =>
  [...decisions.entries()].map(([k, d]) => [k, { ...d, justification: d.justification ?? null }]);
const cases = [];
for (let i = 0; i < 30; i++) {
  const a = Object.fromEntries(questions.filter(() => rand() < 0.9).map((q) => [q.ref, answerFor(q)]));
  const overrides = Array.from({ length: int(6) }, () => ({
    ...pick(keys),
    applicable: rand() < 0.5,
    justification: pick(['', '  ', 'Contract requires it.', 'Not used here.']),
  }));
  if (rand() < 0.3) overrides.push({ type: 'control', key: 'CC-NOPE-99', applicable: false, justification: 'x' });
  const result = domain.computeApplicability({ ...base, answers: a, overrides });
  cases.push({ answers: a, overrides, decisions: serialize(result.decisions), rejected: result.rejectedOverrides });
}
const diff = domain
  .diffApplicability(
    domain.computeApplicability({ ...base, answers: cases[0]!.answers }).decisions,
    domain.computeApplicability({ ...base, answers: cases[1]!.answers }).decisions,
  )
  .map((c: any) => ({ ...c }));


// 3. Other domain logic: each case is a function name, its arguments and the recorded result -------------------
const domainCases: { fn: string; args: unknown[]; out: unknown }[] = [];
const record = (fn: string, ...args: unknown[]) => {
  let out: unknown;
  try {
    const r = (domain as Record<string, (...a: unknown[]) => unknown>)[fn]!(...structuredClone(args));
    out = r instanceof Date ? { date: r.toISOString() } : r instanceof Map ? [...r.entries()] : r;
  } catch (e) {
    out = { error: (e as Error).name };
  }
  domainCases.push({ fn, args, out: out === undefined ? null : out });
};
const pad2 = (n: number) => String(n).padStart(2, '0');
const randDay = () => `${2024 + int(5)}-${pad2(1 + int(12))}-${pad2(1 + int(31))}`;
const STATES = ['not_started', 'in_progress', 'implemented', 'implemented_evidenced', 'not_applicable'];
for (let i = 0; i < 300; i++) {
  const reqs = Array.from({ length: int(40) }, (_, k) => ({
    ref: `r${k}`, applicable: rand() < 0.85, controlStates: Array.from({ length: int(4) }, () => pick(STATES)),
  }));
  record('computeReadiness', reqs);
  record('controlCoverage', reqs.flatMap((r) => r.controlStates));
}
const method = () => {
  const m = domain.defaultRiskMethod();
  if (rand() < 0.5) m.likelihoodScale = m.likelihoodScale.slice(0, 2 + int(4));
  if (rand() < 0.3) m.impactScale = [...m.impactScale, { value: rand() < 0.8 ? 6 : 9, label: pick(['', 'X']), description: '' }];
  if (rand() < 0.3) m.levels = pick([[], [{ min: 2, level: 'a', label: 'A' }], [{ min: 1, level: 'a', label: 'A' }, { min: 1, level: 'b', label: 'B' }, { min: 40, level: 'c', label: 'C' }]]);
  if (rand() < 0.3) m.appetite = pick([0, 1, 2.5, 25, 26]);
  if (rand() < 0.2) m.acceptanceCriteria = pick(['', '  ']);
  if (rand() < 0.3) m.reviewMonths = pick([0, 1, 36, 37, 6.5]);
  return m;
};
for (let i = 0; i < 200; i++) {
  const m = method();
  record('validateRiskMethod', m);
  const l = pick([null, 0, 1, 2, 3, 4, 5, 6]);
  const im = pick([null, 0, 1, 2, 3, 4, 5, 6]);
  record('riskScore', m, l, im);
  record('riskLevel', m, pick([null, 0, 1, 4, 5, 9, 10, 15, 16, 25, 30]));
  record('withinAppetite', m, pick([null, 1, 8, 9, 25]));
  record('heatMap', m, Array.from({ length: int(12) }, () => ({ likelihood: pick([null, 0, 1, 2, 3, 4, 5, 6]), impact: pick([null, 0, 1, 2, 3, 5, 6]) })));
}
const RECS = ['daily', 'weekly', 'monthly', 'quarterly', 'six-monthly', 'annual'];
for (let i = 0; i < 400; i++) {
  const d = randDay();
  const today = randDay();
  record('addInterval', d, pick(RECS));
  record('nextDueDate', pick(RECS), rand() < 0.3 ? null : d, today);
  record('taskUrgency', d, today, ...(rand() < 0.5 ? [int(40)] : []));
  record('daysBetween', d, today);
  record('recurrenceFor', pick([...RECS, 'continuous', 'event-driven', null, '']));
  record('competenceStatus', rand() < 0.2 ? null : d, today, ...(rand() < 0.5 ? [int(60)] : []));
  record('reviewPeriodStart', d, rand() < 0.4 ? null : today);
  record('addCalendarMonths', d, int(30));
  record('dsrDeadline', d, ...(rand() < 0.7 ? [pick([0, 1, 2, 3, -1, 1.5])] : []));
  record('nextDigestAt', new Date(Date.UTC(2024 + int(4), int(12), 1 + int(28), int(24), int(60))), pick(['weekly', 'monthly']));
  record('breachDeadline', `${d.slice(0, 8)}${pad2(1 + int(28))}T${pad2(int(24))}:${pad2(int(60))}:00${pick(['Z', '.250Z', '+01:00', '-05:30'])}`);
}
for (let i = 0; i < 200; i++) {
  const users = Array.from({ length: int(8) }, () => `u${int(10)}`);
  record('ackProgress', users, Array.from({ length: int(10) }, () => `u${int(12)}`));
  const values = Array.from({ length: int(6) }, () => ({ measuredOn: randDay(), value: pick([0, 1, 3, 4, 5, 50, 80, 90, 100, 2.5]) }));
  record('summarizeObjective', values, pick(['at_least', 'at_most']), pick([0, 4, 50, 90]), pick(['monthly', 'quarterly', 'six-monthly', 'annual', 'weekly']), randDay());
  record('chartGeometry', values, pick([0, 4, 50, 100]), pick([100, 216, 300]), pick([50, 116]));
  const acts = ['a', 'b', 'c', 'd'].slice(0, 1 + int(4));
  record('raciIssues', acts, Array.from({ length: int(8) }, () => ({ activityId: pick(acts), roleId: `r${int(4)}`, letter: pick(['R', 'A', 'C', 'I']) })));
  const qs = Array.from({ length: 1 + int(6) }, (_, k) => ({ ref: `q${k}`, text: 'Q', weight: 1 + int(5), ...(rand() < 0.3 ? { critical: true } : {}) }));
  record('scoreQuestionnaire', qs, Object.fromEntries(qs.filter(() => rand() < 0.85).map((q) => [q.ref, pick(['yes', 'partly', 'no', 'not_applicable'])])));
  record('supplierTier', pick(['none', 'internal', 'confidential', 'personal']), pick(['low', 'medium', 'high']));
  const sev = pick(['low', 'medium', 'high', 'critical']);
  record('closureBlockers', { severity: sev, rootCause: pick(['', ' ', 'x']), lessonsLearned: pick(['', 'y']), personalData: rand() < 0.5, reportedToAuthorityAt: rand() < 0.5 ? null : '2026-01-01T00:00:00Z' });
  record('canMoveTo', pick(['reported', 'investigating', 'contained', 'resolved', 'closed']), pick(['reported', 'investigating', 'contained', 'resolved', 'closed']));
  const impacts = Object.fromEntries([4, 24, 72, 168, 336].filter(() => rand() < 0.6).map((w) => [w, 1 + int(5)]));
  record('normalizeImpacts', impacts);
  record('suggestedMtpd', impacts);
  record('recoveryPriority', pick([null, 0, 4, 24, 25, 72, 73, 500]));
  record('biaIssues', { mtpdHours: pick([null, 24, 72]), rtoHours: pick([null, 4, 48, 96]), rpoHours: pick([null, 4]), impacts, dependencies: int(3), plans: int(2), lastExercisedOn: rand() < 0.3 ? null : randDay(), today: randDay() });
  record('rtoMet', pick([null, 3, 4, 6]), pick([null, 4]));
  record('dpiaRequired', Object.fromEntries(['automated_decisions', 'profiling', 'tracking', 'matching', 'large_scale'].filter(() => rand() < 0.3).map((k) => [k, true])));
  record('dpiaRiskLevel', pick(['low', 'medium', 'high']), pick(['low', 'medium', 'high']));
  record('aiRiskTier', Object.fromEntries(['manipulation', 'biometric', 'employment', 'interacts', 'generates', 'emotion'].filter(() => rand() < 0.25).map((k) => [k, true])));
  record('aiSystemGaps', { tier: pick(['unacceptable', 'high', 'limited', 'minimal']), status: pick(['planned', 'in_use', 'retired']), purpose: pick(['', 'x']), humanOversight: pick(['', 'y']), personalData: rand() < 0.5, processingLinked: rand() < 0.5, hasApprovedAssessment: rand() < 0.5, supplierLinked: rand() < 0.5, role: pick(['developer', 'provider', 'deployer']) });
  record('processingGaps', { lawfulBasis: pick([null, 'contract']), specialCategory: rand() < 0.5, specialCondition: pick(['', 'x']), transfers: rand() < 0.5, transferSafeguard: pick([null, 'idta']), retention: pick(['', ' ', '6 years']), dataSubjects: rand() < 0.5 ? [] : ['a'], dataCategories: rand() < 0.5 ? [] : ['b'], dpiaRequired: rand() < 0.5, hasApprovedDpia: rand() < 0.5 });
  record('ncStage', { kind: pick(['nonconformity', 'opportunity']), status: pick(['open', 'closed', 'cancelled']), rootCause: pick(['', ' ', 'x']) }, Array.from({ length: int(3) }, () => ({ done: rand() < 0.6 })));
  record('effectivenessBlockers', { kind: pick(['nonconformity', 'opportunity']), status: pick(['open', 'closed', 'cancelled']), rootCause: pick(['', 'x']) }, Array.from({ length: int(3) }, () => ({ done: rand() < 0.6 })));
  record('auditCompletionBlockers', { status: pick(['planned', 'in_progress', 'completed']), independenceNote: pick(['', 'x']), summary: pick(['', 'y']), results: Array.from({ length: int(4) }, () => pick([null, 'conforms', 'minor'])) });
  record('missingInputs', Object.fromEntries(['previous_actions', 'risk', 'audits', 'objectives', 'monitoring'].filter(() => rand() < 0.6).map((k) => [k, pick([null, {}, 0, ''])])));
  record('suggestedSampleSize', int(400));
}
const REQ_GROUPS = ['clause-4', 'clause-6', 'annex-a-5', 'annex-a-8'];
for (let i = 0; i < 60; i++) {
  const reqs = Array.from({ length: int(15) }, (_, k) => ({
    framework: pick(['iso27001', 'cyber-essentials', 'nist-csf-2']), ref: `R${k}`, title: `T${k}`,
    groupRef: pick(REQ_GROUPS), groupTitle: 'G', mandatory: rand() < 0.3, applicable: rand() < 0.7,
    controls: Array.from({ length: int(3) }, () => `CC-X-0${int(9)}`), sort: int(20),
  }));
  record('buildChecklist', reqs, ...(rand() < 0.4 ? [REQ_GROUPS.filter(() => rand() < 0.5)] : []));
  record('programmeCoverage', reqs, reqs.filter(() => rand() < 0.5).map((r) => `${r.framework}:${r.ref}`));
}
// Sampling with plain lower-case keys (the port sorts by code point; see _js.py).
const samples = [];
for (let i = 0; i < 80; i++) {
  const keys = [...new Set(Array.from({ length: int(60) }, () => `k${int(1000)}`))];
  const seedText = pick(['audit-2026', '', 's', 'Zürich £ 🔒', `seed-${int(1e6)}`]);
  const size = pick([0, 1, 5, 10, 25, 100, -3, 2.7]);
  samples.push({ keys, seed: seedText, size, out: domain.drawSample(keys.map((k) => ({ k })), size, seedText, (x: { k: string }) => x.k).map((x: { k: string }) => x.k) });
}
// CSV over a small alphabet that exercises quoting.
const csvs = [];
for (let i = 0; i < 300; i++) {
  const text = Array.from({ length: int(40) }, () => pick(['a', 'b', ' ', ',', '"', '\n', '\r\n', '\r', '﻿', 'Name', 'Owner Email'])).join('');
  let out: unknown;
  try {
    out = { rows: domain.parseCsv(text), records: domain.parseCsvRecords(text) };
  } catch {
    out = { error: true };
  }
  csvs.push({ text, out });
}

writeFileSync(
  join(fenrirDir, 'cloud/tests/fixtures/isms_parity.json.gz'),
  gzipSync(JSON.stringify({ expressions, parses, applicability: { base, cases, diff }, domain: domainCases, samples, csvs }) + '\n', { level: 9 }),
);
console.log(`expressions ${expressions.length}, applicability cases ${cases.length}, domain cases ${domainCases.length}, samples ${samples.length}, csv ${csvs.length}`);
