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

// Admin access card (privileged access management).
function elevation(st, mode = 'approval') {
  context.fixture = { experience: { elevationRequests: mode }, elevation: st };
  return vm.runInContext('S = fixture; elevationCard()', context);
}
assert.equal(elevation({}, 'off'), '');
assert.match(elevation({}), /Ask for admin access/);
assert.match(elevation({}, 'auto-approve'), /Get admin access/);
assert.match(elevation({ state: 'pending' }), /Waiting/);
const session = elevation({ state: 'granted', kind: 'session', until: '2026-01-01T10:00:00Z', account: '.\\fadm-jo-1a2b', password: 'pw' });
assert.match(session, /data-act="elevationRun"/);
assert.match(session, /Run as administrator with Fenrir/);
assert.match(session, /fadm-jo-1a2b/);
const opened = elevation({ state: 'granted', kind: 'run', until: '2026-01-01T10:00:00Z', target: 'C:\\Tools\\setup.exe', running: true });
assert.match(opened, /setup\.exe<\/b> is open as administrator/);
assert.doesNotMatch(opened, /Choose <b>Yes<\/b>/);
assert.match(elevation({ state: 'granted', kind: 'run', target: 'C:\\Tools\\setup.exe', launchFailed: true }), /Choose <b>Yes<\/b>/);
console.log('Admin access card: request, waiting, session with run button, and service-opened programs render correctly.');
