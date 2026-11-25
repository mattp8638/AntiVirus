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

writeFileSync(
  join(fenrirDir, 'cloud/tests/fixtures/isms_parity.json.gz'),
  gzipSync(JSON.stringify({ expressions, parses, applicability: { base, cases, diff } }) + '\n', { level: 9 }),
);
console.log(`expressions ${expressions.length}, applicability cases ${cases.length}`);
