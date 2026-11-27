// Run with node --test internal/gui/webui/smart_proxy_test.mjs
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {strategyGuide, bindSettingsTabs, buildRequest, chartRows, controlValue, readSharedConfig, setControl, syncGroupActivation} from './static/smart-proxy.js';
import {latencySeries, nearestSample, recordSample, seriesPath, trendBands} from './static/smart-proxy-dashboard.js';

test('Imports match profile names and server URLs and keep destination targets aligned', () => {
  const exportFile = {
    version: 1, profiles: {old: 'Office', other: 'West'},
    smart_proxy: {egress: {
      members: [{profile_id: 'old', tunnel: 'web', expected_server: 'https://office.example.net'}],
      enroll: [{profile_id: 'other', expected_server: 'https://west.example.net'}]
    }, routing: {rules: [{members: [{profile_id: 'old', tunnel: 'web'}]}]}}
  };
  const snapshots = new Map([
    ['local', {profile: {ID: 'local', Name: 'Office', Server: 'https://office.example.net/'}}],
    ['west', {profile: {ID: 'west', Name: 'West', Server: 'https://wrong.example.net'}}]
  ]);
  const read = () => readSharedConfig(JSON.stringify(exportFile), snapshots);
  const draft = read();
  assert.equal(draft.egress.members[0].profile_id, 'local');
  assert.equal(draft.routing.rules[0].members[0].profile_id, 'local');
  assert.equal(draft.egress.enroll[0].profile_id, 'other');
  snapshots.set('second', {profile: {ID: 'second', Name: 'Office', Server: 'https://office.example.net'}});
  assert.equal(read().egress.members[0].profile_id, 'old');
  assert.throws(() => readSharedConfig('{"version":2}', snapshots), /version 1/);
});

test('Latency compares setup across tunnels and shows detailed timings for one tunnel', () => {
  const entries = [['west', 'West'], ['east', 'East'], ['new', 'New']];
  const sample = {members: new Map([
    ['east', {setup: 12, rtt: 5, latency: 27}],
    ['west', {setup: 25, rtt: 8}]
  ])};
  const comparison = latencySeries(entries, '');
  assert.deepEqual(comparison.map(line => [line.name, line.measure(sample)]),
    [['East', 12], ['New', undefined], ['West', 25]]);
  assert.equal(new Set(comparison.map(line => line.hue)).size, 3);
  assert.deepEqual(latencySeries([...entries].reverse(), '').map(line => line.hue), comparison.map(line => line.hue));
  assert.deepEqual(latencySeries(entries, 'east').map(line => [line.name, line.measure(sample)]),
    [['Setup', 12], ['Tunnel round trip', 5], ['HTTPS probe', 27]]);
});

test('Chart hover selects the nearest timestamp on an uneven timeline', () => {
  const samples = [{time: 1000}, {time: 2000}, {time: 9000}];
  for (const [time, index] of [[0, 0], [1500, 0], [3000, 1], [8000, 2], [10000, 2]]) {
    assert.equal(nearestSample(samples, time), samples[index]);
  }
  assert.equal(nearestSample([samples[0]], 9000), samples[0]);
});

test('Tray activation updates only saved group flags and leaves other draft edits intact', () => {
  const saved = {enabled: false, groups: {office: {enabled: true, listen: 'before'}}};
  const draft = structuredClone(saved);
  draft.groups.office.listen = 'edited';
  draft.groups.local = {enabled: false};
  assert.equal(syncGroupActivation(saved, draft, {enabled: true, groups: {office: {enabled: false}, local: {enabled: true}}}), true);
  assert.equal(saved.enabled, true);
  assert.equal(draft.enabled, true);
  assert.equal(draft.groups.office.enabled, false);
  assert.equal(draft.groups.office.listen, 'edited');
  assert.equal(draft.groups.local.enabled, false);
  draft.enabled = false;
  assert.equal(syncGroupActivation(saved, draft, {enabled: true, groups: {office: {enabled: false}}}), false);
  assert.equal(draft.enabled, false);
});

test('Traffic charts use cumulative deltas per tunnel and handle resets and missing samples', () => {
  const history = [];
  const member = (profile_id, sent, received) => ({profile_id, tunnel: 'web', sent, received});
  const sample = (time, ...members) => recordSample(history, {listening: '127.0.0.1:1080', active: 2, members}, time);
  sample(0, member('a', 10, 100), member('b', 500, 200));
  sample(2000, member('a', 30, 160), member('b', 5, 220), member('new', 900, 300));
  assert.equal(history[0].sent, undefined);
  assert.equal(history[1].sent, 10);
  assert.equal(history[1].received, 40);
  assert.deepEqual(history[1].members.get('["a","web"]').traffic, {sent: 10, received: 30});
  assert.deepEqual(history[1].members.get('["b","web"]').traffic, {sent: 0, received: 10});
  assert.deepEqual(history[1].members.get('["new","web"]').traffic, {});
  sample(15000, member('a', 80, 180));
  assert.equal(history[2].sent, undefined);
  assert.deepEqual(history[2].members.get('["a","web"]').traffic, {});
  sample(320000, member('a', 100, 200));
  assert.deepEqual(history.map(point => point.time), [320000]);
});

test('Charts break between missing measurements and long gaps', () => {
  const samples = [
    {time: 0, value: 1}, {time: 2000, value: 2}, {time: 4000},
    {time: 6000, value: 0}, {time: 18000, value: 3}
  ];
  assert.equal(seriesPath(samples, sample => sample.value, time => time / 1000, value => value),
    'M0.00,1.00 L2.00,2.00 M6.00,0.00 M18.00,3.00');
});

test('Latency distinguishes reported tunnel reconnects from missing samples and route exclusions', () => {
  const history = [];
  const key = '["office","egress"]';
  const west = {profile_id: 'west', tunnel: 'egress', reason: 'excluded'};
  const office = {profile_id: 'office', tunnel: 'egress', connect_millis: 25};
  const sample = (time, members) => recordSample(history, {listening: true, active: 4, members}, time);
  sample(0, [office, west]);
  sample(2000, [{...office, outage: 'reconnecting'}, west]);
  sample(4000, [office, west]);
  sample(6000, [{...office, connect_millis: undefined}, west]);
  sample(20000, [office, west]);
  const show = point => [...point.members.values()].flatMap(entry => entry.outage ? [entry.outage] : []);
  assert.deepEqual(trendBands(history, show).map(({type, from, to, affected}) => [type, from, to, affected]), [
    ['down', 2000, 4000, ['Reconnecting']], ['gap', 6000, 20000, undefined]
  ]);
  assert.deepEqual(history.map(latencySeries([[key, 'Office']], '')[0].measure), [25, undefined, 25, undefined, 25]);
  assert.deepEqual(history.map(point => point.active), [4, 4, 4, 4, 4]);
});

test('Settings tabs switch one panel at a time and support keyboard navigation', () => {
  const panels = [{}, {}, {}];
  let focused;
  const tabs = panels.map((_, index) => ({
    events: {},
    getAttribute: () => String(index),
    setAttribute(name, value) { this[name] = value; },
    addEventListener(name, fn) { this.events[name] = fn; },
    focus() { focused = index; }
  }));
  bindSettingsTabs({querySelectorAll: () => tabs}, id => panels[id]);
  function selected(index) {
    assert.deepEqual(tabs.map(tab => tab['aria-selected']), tabs.map((_, i) => String(i === index)));
    assert.deepEqual(tabs.map(tab => tab.tabIndex), tabs.map((_, i) => i === index ? 0 : -1));
    assert.deepEqual(panels.map(panel => panel.hidden), panels.map((_, i) => i !== index));
  }
  tabs[1].events.click();
  selected(1);
  for (const [from, key, to] of [[1, 'Home', 0], [0, 'ArrowLeft', 2], [2, 'ArrowRight', 0], [0, 'End', 2]]) {
    let prevented = false;
    tabs[from].events.keydown({key, preventDefault() { prevented = true; }});
    assert.equal(prevented, true);
    assert.equal(focused, to);
    selected(to);
  }
});

test('Live chart rows retain measured zeroes and omit missing or invalid measurements', () => {
  const members = [
    {name: 'idle', active: 0},
    {name: 'east', active: 3, connect_millis: 21.5},
    {name: 'west', active: 1, connect_millis: 42},
    {name: 'invalid', connect_millis: NaN}
  ];
  const label = member => member.name;
  assert.deepEqual(chartRows(members, label, member => member.active ?? 0), [
    {label: 'east', value: 3}, {label: 'west', value: 1}, {label: 'idle', value: 0}, {label: 'invalid', value: 0}
  ]);
  assert.deepEqual(chartRows(members, label, member => member.connect_millis), [
    {label: 'west', value: 42}, {label: 'east', value: 21.5}
  ]);
});

const tunnel = {profile_id: 'office', tunnel: 'web', expected_server: 'https://office.example.net',
  priority: 50, egress_class: 'internet'};
const target = {profile_id: tunnel.profile_id, tunnel: tunnel.tunnel};
const enrollment = {profile_id: 'eu', expected_server: 'https://eu.example.net',
  egress_class: 'internet', priority: 10};

function config() {
  return {
    enabled: true, listen: '127.0.0.1:1080', protocols: ['socks5', 'http'], pac_listen: '[::1]:1082',
    groups: {office: {enabled: false, listen: '127.0.0.1:1081', protocols: ['http'],
      egress: {selection: 'priority', members: []}}},
    egress: {selection: 'sticky-fastest', members: [tunnel], enroll: [enrollment]},
    failover: {enabled: false, max_attempts: 4, attempt_timeout: 1_234_567_891,
      total_timeout: 8_000_000_007, racing: true, race_delay: 200_000_001},
    health: {interval: 31_000_000_003, failure_threshold: 4, recovery_interval: 32_000_000_001,
      probe_targets: ['one.example.net:443', 'https://two.example.net/test?targets=1,2']},
    routing: {affinity_scope: 'group', affinity_ttl: 301_000_000_003, hysteresis_percent: 15,
      udp_associate: true, udp_idle_timeout: 121_000_000_013, unmatched: 'deny',
      rules: [
        {mode: 'selected', hosts: ['one.example.net'], suffixes: ['two.example.net'], cidrs: ['2001:db8::/32'],
          ports: ['443', 8443], members: [target]},
        {mode: 'deny', ports: [25]},
        {mode: 'any', members: [target]}
      ]},
    limits: {connections: 300, concurrent_attempts: 20}
  };
}

test('Saving all fields retains scoped settings, enrollment order, and exact durations', () => {
  const draft = config();
  draft.groups.office.browser_block_local_dns = true;
  draft.groups.office.limits = {auto: true, connections: 900, concurrent_attempts: 64};
  const payload = JSON.parse(JSON.stringify(buildRequest(draft, [], new Set())));
  assert.deepEqual(payload, {
    ...draft,
    routing: {...draft.routing, rules: [
      {hosts: ['one.example.net'], suffixes: ['two.example.net'], cidrs: ['2001:db8::/32'],
        ports: [443, 8443], deny: false, members: [target]},
      {ports: [25], deny: true}, {deny: false}
    ]}
  });
  assert.equal(draft.routing.rules[2].mode, 'any');
  assert.equal(draft.routing.rules[2].members[0], target);
});

test('Restricted rules never become unrestricted when a tunnel is removed', () => {
  const draft = config();
  draft.egress.members = [];
  assert.throws(() => buildRequest(draft, [], new Set()), /Rule 1.*unavailable tunnel/);
  draft.routing.rules[0].members = [];
  assert.throws(() => buildRequest(draft, [], new Set()), /Rule 1.*Select at least one/);
});

test('Saves validate unapproved sources and incompatible controls in every group', () => {
  const draft = config();
  const office = draft.groups.office;
  office.egress.enroll = [enrollment];
  assert.throws(() => buildRequest(draft, [], new Set(['office'])), /office.*Approve/);
  office.protocols = [];
  assert.throws(() => buildRequest(draft, [], new Set()), /office.*at least one proxy protocol/);
  office.protocols = ['http'];
  office.routing = {udp_associate: true};
  assert.throws(() => buildRequest(draft, [], new Set()), /office.*UDP requires SOCKS5/);
  office.routing = {affinity_scope: 'group'};
  assert.throws(() => buildRequest(draft, [], new Set()), /office.*requires Sticky fastest/);
  delete office.routing;
  draft.routing.rules[0].ports = ['0', '1e2'];
  assert.throws(() => buildRequest(draft, [], new Set()), /Rule 1.*port numbers/);
});

test('Duration controls round-trip nanoseconds and retain an empty draft value', () => {
  for (const [unit, fallback, ns] of [
    ['seconds', '30', 3_599_000_000_001], ['milliseconds', '200', 1_234_567_891]
  ]) {
    const control = {type: 'number', dataset: {unit, default: fallback}, hasAttribute: () => false};
    setControl(control, ns);
    control.valueAsNumber = Number(control.value);
    assert.equal(controlValue(control), ns);
    setControl(control, undefined);
    assert.equal(control.value, fallback);
    setControl(control, null);
    assert.equal(control.value, '');
    control.valueAsNumber = NaN;
    assert.equal(controlValue(control), null);
  }
});

test('Every live metric handles sparse and measured tunnel snapshots', async () => {
  const {statusMetrics} = await import('./static/smart-proxy.js');
  for (const fields of Object.values(statusMetrics)) {
    for (const format of Object.values(fields)) {
      assert.notEqual(format({}), undefined);
      assert.notEqual(format({carrier_rtt: 1_500_000, connect_millis: 4, sent: 200, received: 0}), undefined);
    }
  }
  assert.equal(statusMetrics.Timing['Virtual service setup']({}), '—');
  assert.equal(statusMetrics.Timing['Virtual service setup']({virtual_service_millis: 0}), '0.0 ms');
  assert.equal(statusMetrics.Traffic['Carrier packet loss']({carrier_rtt: 1_500_000}), '0.0%');
});

test('Direct and ASN rules survive save and invalid actions stay visible', () => {
  const draft = config();
  draft.routing.unmatched = 'direct';
  draft.routing.rules = [
    {asns: ['AS13335', 15169], action: 'direct', ports: [443]},
    {asns: [16509], action: 'deny'}
  ];
  const result = buildRequest(draft, [], new Set());
  assert.equal(result.routing.unmatched, 'direct');
  assert.deepEqual(result.routing.rules.map(({action, asns}) => [action, asns]),
    [['direct', [13335, 15169]], ['deny', [16509]]]);
  draft.routing.rules[0].asns = ['AS0'];
  assert.throws(() => buildRequest(draft, [], new Set()), /Enter ASNs/);
  draft.routing.rules[0].asns = [13335];
  draft.routing.rules[0].members = draft.egress.members;
  assert.throws(() => buildRequest(draft, [], new Set()), /conflicting routing action/);
});

test('Direct TCP and UDP traffic contribute once to the aggregate', () => {
  const history = [];
  const sample = (time, sent, udp_sent) => recordSample(history, {
    members: [{profile_id: 'office', tunnel: 'web', sent, received: 0}],
    direct: {sent, udp_sent, received: 0, udp_received: 0}
  }, time);
  sample(0, 1, 2);
  sample(1000, 5, 3);
  assert.equal(history[1].members.get('direct').traffic.sent, 5);
  assert.equal(history[1].sent, 9);
});

test('Strategy guide covers every selection strategy the backend accepts', () => {
  assert.deepEqual(strategyGuide.map(([value]) => value).sort(),
    ['adaptive', 'destination-aware', 'fastest-healthy', 'priority', 'round-robin', 'sticky-fastest']);
  for (const entry of strategyGuide) assert.ok(entry.every(text => text.length > 0));
});
