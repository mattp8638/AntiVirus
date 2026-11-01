import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../tools/endpointui/web/protection-centre.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1]
  .replace('__FENRIR_INITIAL_STATE__', '{}').replace(/render\(\);\s*$/, '');
const context = vm.createContext({
  window: { addEventListener() {} }, document: { addEventListener() {} }, URLSearchParams,
});
vm.runInContext(script, context);

function render(state, filter = 'all') {
  context.fixture = {
    updates: { windowsCount: 0, availableSoftwareCount: state === 'available' ? 1 : 0, softwareCount: 1 },
    softwareUpdates: [{ id: 'app', name: 'Fixture Browser', supported: 1, canInstall: 1,
      state, availableVersion: state === 'available' ? '131.0' : '', summary: 'Provider diagnostic' }],
  };
  context.filter = filter;
  return vm.runInContext('S = fixture; updFilter = filter; pageUpdates()', context);
}

const ready = render('provider_ready');
assert.match(ready, /Updater available/);
assert.match(ready, /Run updater/);
assert.doesNotMatch(ready, /class="badge good">Up to date/);
assert.doesNotMatch(ready, /class="badge warn">Update available/);
assert.doesNotMatch(render('provider_ready', 'available'), /Fixture Browser/);
for (const state of ['provider_failed', 'provider_source_unavailable', 'provider_result_unknown', 'not_checked', 'verification_pending']) {
  const result = render(state);
  assert.match(result, /Check needed/, state);
  assert.doesNotMatch(result, /class="badge good">Up to date/, state);
  assert.match(result, /No confirmed updates/, state);
}
assert.match(render('package_not_found'), /Package not matched/);
assert.match(render('current'), /class="badge good">Up to date/);
assert.match(render('available', 'available'), /Update to 131\.0/);
assert.match(render('available', 'available'), /1 update waiting/);
console.log('Endpoint update UI: confirmed updates, provider capability and failed checks stay distinct.');
