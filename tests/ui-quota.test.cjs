const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

const html = readFileSync(new URL('../src/ui.html', `file://${__filename}`), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const context = vm.createContext({ setInterval() {}, document: { getElementById() { return { addEventListener() {}, showModal() {} }; } } });
// Execute the dashboard's actual script, including its startup calls with a minimal DOM.
context.localStorage = { getItem() { return ''; } };
context.fetch = async () => ({ status: 200, json: async () => ({}) });
vm.runInContext(script, context);
const remaining = (account, seconds) => context.formatRemaining(account, seconds).split('<br>')[0];
const codex = (primary, secondary) => ({
  backend: 'codex', usage: { rate_limit: { primary_window: primary, secondary_window: secondary } },
});

test('Claude shows percent left for both windows, including under one percent used', () => {
  const account = { backend: 'claude', observation: {
    five_hour: { utilization: 0.02 }, seven_day: { utilization: 0.84 },
  } };
  assert.equal(remaining(account, 18000), '98% left');
  assert.equal(remaining(account, 604800), '16% left');
  account.observation.five_hour.utilization = 0.005;
  assert.equal(remaining(account, 18000), '100% left');
});

test('Codex windows match duration, even when weekly is the primary or only window', () => {
  const weekly = { limit_window_seconds: 604800, used_percent: 8 };
  const session = { limit_window_seconds: 18000, used_percent: 25 };
  for (const account of [codex(session, weekly), codex(weekly, session)]) {
    assert.equal(remaining(account, 18000), '75% left');
    assert.equal(remaining(account, 604800), '92% left');
  }
  assert.equal(remaining(codex(weekly, null), 18000), '—');
  assert.equal(remaining(codex(weekly, null), 604800), '92% left');
});

test('unknown quota stays unknown; exhausted and out-of-range values stay within 0 to 100', () => {
  for (const account of [{ backend: 'claude' }, { backend: 'codex' }, { backend: 'copilot' }]) {
    assert.equal(remaining(account, 18000), '—');
    assert.equal(remaining(account, 604800), '—');
  }
  for (const used of [null, undefined, '25', NaN, Infinity]) {
    assert.equal(remaining(codex({ limit_window_seconds: 18000, used_percent: used }), 18000), '—');
  }
  for (const [used, expected] of [[100, '0% left'], [120, '0% left'], [-2, '100% left'], [0, '100% left']]) {
    assert.equal(remaining(codex({ limit_window_seconds: 18000, used_percent: used }), 18000), expected);
    assert.equal(remaining({ backend: 'claude', observation: { five_hour: { utilization: used / 100 } } }, 18000), expected);
  }
});

test('Accounts table has shared duration headings instead of provider-specific quota columns', () => {
  const table = html.match(/<table id="accounts">([\s\S]*?)<\/table>/)[1];
  assert.match(table, /<th>5h<\/th><th>1 week<\/th>/);
  assert.doesNotMatch(table, /Codex usage|<th>quota<\/th>|<th>renews in<\/th>/);
});

test('both providers show separate renewal countdowns even when healthy', () => {
  const now = 1800000000000;
  const sessionReset = now + 2 * 3600000 + 15 * 60000;
  const weekReset = now + 3 * 86400000 + 4 * 3600000;
  const accounts = [
    { backend: 'claude', status: 'healthy', observation: {
      five_hour: { utilization: 0.02, resets_at_ms: sessionReset },
      seven_day: { utilization: 0.84, resets_at_ms: weekReset },
    } },
    codex(
      { limit_window_seconds: 604800, used_percent: 84, reset_at: weekReset / 1000 },
      { limit_window_seconds: 18000, used_percent: 2, reset_at: sessionReset / 1000 },
    ),
  ];
  for (const account of accounts) {
    assert.equal(context.formatRemaining(account, 18000, now), '98% left<br><span class="muted">Renews in 2h 15m</span>');
    assert.equal(context.formatRemaining(account, 604800, now), '16% left<br><span class="muted">Renews in 3d 4h</span>');
  }
});

test('renewals distinguish unknown deadlines and elapsed data without negative countdowns', () => {
  const now = 1800000000000;
  for (const deadline of [null, undefined, 0, NaN, Infinity, '1800000000000']) {
    assert.equal(context.formatRenewal(deadline, now), 'Renewal unknown');
  }
  assert.equal(context.formatRenewal(now, now), 'Awaiting renewal update');
  assert.equal(context.formatRenewal(now - 3600000, now), 'Awaiting renewal update');
  assert.equal(context.formatRenewal(now + 1000, now), 'Renews in 1m');
  assert.equal(context.formatRenewal(now + 60000, now), 'Renews in 1m');
  assert.equal(context.formatRenewal(now + 3600000, now), 'Renews in 1h 0m');
  assert.equal(context.formatRenewal(now + 86400000, now), 'Renews in 1d 0h');
  assert.equal(context.formatRemaining(codex(null, null), 18000, now), '—');
  assert.match(context.formatRemaining(codex({ limit_window_seconds: 18000, used_percent: 2 }), 18000, now), /98% left.*Renewal unknown/);
});
