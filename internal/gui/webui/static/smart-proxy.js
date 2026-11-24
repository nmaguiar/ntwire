const proxyPath = '/api/smart-proxy';
const defaultProtocols = ['socks5', 'http'];
const idPattern = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const durationUnits = {seconds: 1e9, milliseconds: 1e6};
const strategyHelp = {
  'sticky-fastest': 'Keep using the same healthy tunnel until another is consistently faster.',
  'fastest-healthy': 'Use the healthy tunnel with the fastest measured setup.',
  'destination-aware': 'Use recent measurements for the requested destination when available.',
  priority: 'Try higher-priority tunnels first. List order breaks ties.',
  'round-robin': 'Rotate new connections through healthy tunnels.'
};
const strategyGuide = [
  ['sticky-fastest', 'Sticky fastest', 'Picks the fastest tunnel, then keeps using it for the same site until another is consistently faster.',
    'Everyday browsing and logins. Keeps a steady exit IP while still choosing a fast tunnel.'],
  ['fastest-healthy', 'Fastest healthy', 'Picks the fastest healthy tunnel for every new connection. The exit IP can change between connections.',
    'Speed matters most and sites do not care which exit IP you use.'],
  ['destination-aware', 'Destination aware', 'Like fastest healthy, but ranks tunnels by how they performed for the specific site and port requested.',
    'Tunnels behave differently per site, for example one is fast for a CDN but blocked by another service.'],
  ['priority', 'Priority', 'Always uses the highest-priority tunnel that is healthy. Speed is ignored. List order breaks ties.',
    'A preferred exit with backups, or predictable routing for cost or policy reasons.'],
  ['round-robin', 'Round robin', 'Rotates new connections through the healthy tunnels in turn.',
    'Spreading load evenly so no single tunnel is saturated.']
];
const displayGroup = name => name === 'default' ? 'Default' : name;
const memberKey = member => JSON.stringify([member.profile_id, member.tunnel]);
function groupAt(config, name) {
  if (name === 'default') return config;
  return config?.groups && Object.hasOwn(config.groups, name) ? config.groups[name] : undefined;
}

// Accept activation changes made in the tray without replacing the open draft.
function syncGroupActivation(saved, draft, status) {
  let changed = false;
  for (const [name, state] of [['default', status], ...Object.entries(status.groups || {})]) {
    const before = groupAt(saved, name);
    const editing = groupAt(draft, name);
    if (!before || typeof state.enabled !== 'boolean' || Boolean(before.enabled) === state.enabled) continue;
    if (editing && Boolean(editing.enabled) === Boolean(before.enabled)) editing.enabled = state.enabled;
    before.enabled = state.enabled;
    changed = true;
  }
  return changed;
}

function readSharedConfig(file, snapshots) {
  const {version, smart_proxy: config, profiles} = JSON.parse(file) ?? {};
  if (version !== 1 || !config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('Choose a version 1 Smart Proxy export.');
  }
  const local = [...snapshots.values()].map(snapshot => snapshot.profile);
  function serverURL(value) {
    if (typeof value !== 'string' || !value.trim()) return '';
    try {
      const input = value.trim();
      return new URL(input.includes('://') ? input : 'https://' + input).href.replace(/\/$/, '');
    } catch {
      return '';
    }
  }
  for (const group of [config, ...Object.values(config.groups || {})]) {
    const links = [...(group.egress?.members || []), ...(group.egress?.enroll || [])];
    const mapping = new Map();
    for (const link of links) {
      const original = link.profile_id;
      const name = profiles && Object.hasOwn(profiles, original) ? profiles[original] : undefined;
      const server = serverURL(link.expected_server);
      if (typeof name !== 'string' || !server ||
          links.some(other => other.profile_id === original && serverURL(other.expected_server) !== server)) continue;
      const matches = local.filter(profile => profile.Name === name && serverURL(profile.Server) === server);
      if (matches.length === 1) mapping.set(original, matches[0].ID);
    }
    // Preserve ambiguous IDs for manual review rather than merging profiles.
    const targetCounts = new Map();
    const originals = new Set(links.map(link => link.profile_id));
    for (const original of originals) {
      const target = mapping.get(original) ?? original;
      targetCounts.set(target, (targetCounts.get(target) ?? 0) + 1);
    }
    for (const [original, target] of mapping) {
      if (targetCounts.get(target) > 1 || (original !== target && originals.has(target))) mapping.delete(original);
    }
    for (const link of links) link.profile_id = mapping.get(link.profile_id) ?? link.profile_id;
    const resolver = group.routing?.asn?.resolver_member;
    if (resolver) resolver.profile_id = mapping.get(resolver.profile_id) ?? resolver.profile_id;
    for (const rule of group.routing?.rules || []) {
      for (const target of rule.members || []) {
        target.profile_id = mapping.get(target.profile_id) ?? target.profile_id;
      }
    }
  }
  return config;
}

const read = (object, path) => path.split('.').reduce((value, key) => value?.[key], object);

function write(object, path, value) {
  const keys = path.split('.');
  const last = keys.pop();
  const parent = keys.reduce((node, key) => (node[key] ??= {}), object);
  parent[last] = value;
}

function tokens(value) {
  return value.split(/[,\n]/).map(entry => entry.trim()).filter(Boolean);
}

function ruleMode(rule) {
  return rule.mode ?? (rule.deny || rule.action === 'deny' ? 'deny' : rule.action === 'direct' ? 'direct' : rule.members?.length ? 'selected' : 'any');
}

const asnNumber = value => /^\d+$/i.test(String(value).replace(/^AS/i, ''))
  ? Number(String(value).replace(/^AS/i, '')) : NaN;

function validateRule(rule, members) {
  if ((rule.asns || []).some(value => !Number.isInteger(asnNumber(value)) || asnNumber(value) < 1 || asnNumber(value) > 4294967295)) {
    return 'Enter ASNs from 1 to 4294967295, such as AS13335.';
  }
  if (!rule.mode && (rule.action && !['proxy', 'direct', 'deny'].includes(rule.action) ||
      rule.deny && rule.action && rule.action !== 'deny' ||
      (rule.deny || ['direct', 'deny'].includes(rule.action)) && rule.members?.length)) {
    return 'Resolve the conflicting routing action and tunnel settings.';
  }
  if ((rule.ports || []).some(port => !/^\d+$/.test(String(port)) || +port < 1 || +port > 65535)) {
    return 'Enter port numbers from 1 to 65535.';
  }
  if (ruleMode(rule) !== 'selected') return '';
  if (!rule.members?.length) return 'Select at least one tunnel for this rule.';
  const allowed = new Set(members.map(memberKey));
  if (rule.members.some(member => !allowed.has(memberKey(member)))) {
    return 'Remove or replace the unavailable tunnel in this rule.';
  }
  return '';
}

function controlValue(control) {
  if (control.type === 'checkbox') return control.checked;
  if (control.hasAttribute('data-list')) {
    return control.value.split('\n').map(line => line.trim()).filter(Boolean);
  }
  if (control.type !== 'number') return control.value.trim();
  const value = control.valueAsNumber;
  const scale = durationUnits[control.dataset.unit];
  if (!Number.isFinite(value)) return null;
  return scale ? Math.round(value * scale) : value;
}

function setControl(control, value) {
  const fallback = control.dataset.default;
  if (control.type === 'checkbox') {
    control.checked = value ?? (fallback === 'true');
  } else if (control.hasAttribute('data-list')) {
    control.value = (value || []).join('\n');
  } else {
    const unit = durationUnits[control.dataset.unit];
    if (value === undefined) control.value = fallback ?? '';
    else control.value = value == null ? '' : unit ? value / unit : value;
  }
}

function buildRequest(draft, controls, unapproved) {
  const config = structuredClone(draft);
  for (const [name, group] of [['default', config], ...Object.entries(config.groups || {})]) {
    const fail = message => { throw new Error(displayGroup(name) + ' · ' + message); };
    const protocols = group.protocols ?? defaultProtocols;
    if (!protocols.length) fail('Select at least one proxy protocol.');
    if (!group.listen) fail('Enter a local address.');
    if (group.routing?.udp_associate && !protocols.includes('socks5')) fail('UDP requires SOCKS5.');
    if (group.routing?.affinity_scope === 'group' && group.egress.selection !== 'sticky-fastest') {
      fail('Whole-group tunnel preference requires Sticky fastest.');
    }
    const members = group.egress.members || [];
    const enrollments = group.egress.enroll || [];
    if ((members.length || enrollments.length) && unapproved.has(name)) fail('Approve the tunnels and enrollments for this group.');
    for (const [index, member] of members.entries()) {
      if (!member.profile_id || !member.expected_server || !member.tunnel || !Number.isSafeInteger(member.priority)) {
        fail('Complete the profile ID, tunnel, expected server, and integer priority for tunnel ' + (index + 1) + '.');
      }
    }
    for (const [index, entry] of enrollments.entries()) {
      if (!entry.profile_id || !entry.expected_server || !entry.egress_class || !Number.isSafeInteger(entry.priority)) {
        fail('Complete the profile ID, trusted server, policy class, and integer priority for enrollment ' + (index + 1) + '.');
      }
    }
    for (const control of controls) {
      if (control.type !== 'number') continue;
      const path = control.dataset.smartField;
      if (path.startsWith('asn_database.') && name !== 'default') continue;
      const value = read(group, path);
      if (value === undefined) continue;
      const scale = durationUnits[control.dataset.unit] ?? 1;
      if (!Number.isSafeInteger(value) || value < Number(control.min) * scale || value > Number(control.max) * scale) {
        const label = control.closest('label').firstChild.textContent.trim();
        fail(label + ' must be between ' + control.min + ' and ' + control.max + '.');
      }
    }
    const asn = group.routing?.asn;
    if (asn) {
      const mode = asn.hostname_resolution || 'disabled';
      if (mode !== 'disabled' && !asn.hosts?.length && !asn.suffixes?.length) fail('Enter a hostname or suffix scope for ASN resolution.');
      const member = asn.resolver_member;
      if ((mode === 'remote' || member) && (!member || !members.some(entry => memberKey(entry) === memberKey(member)))) {
        fail('Select an explicitly approved ASN resolver tunnel.');
      }
    }
    if (group.routing?.rules) {
      group.routing.rules = group.routing.rules.map((rule, index) => {
        const error = validateRule(rule, members);
        if (error) fail('Rule ' + (index + 1) + ' · ' + error);
        const mode = ruleMode(rule);
        return {
          hosts: rule.hosts, suffixes: rule.suffixes, cidrs: rule.cidrs,
          ports: rule.ports?.map(Number), asns: rule.asns?.map(asnNumber),
          action: mode === 'direct' ? 'direct' : rule.action === 'proxy' && ['any', 'selected'].includes(mode) ? 'proxy'
            : mode === 'deny' && rule.action === 'deny' ? 'deny' : undefined,
          deny: mode === 'deny' && rule.action !== 'deny',
          members: mode === 'selected' ? rule.members : undefined
        };
      });
    }
  }
  return config;
}

function make(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function updateText(node, text) {
  if (node.textContent !== text) node.textContent = text;
}

function button(text, callback, description = '') {
  const node = make('button', text, 'secondary');
  node.type = 'button';
  if (description) node.setAttribute('aria-label', description);
  node.onclick = callback;
  return node;
}

function labelFor(text, control, className) {
  const label = make('label', text, className);
  label.append(control);
  return label;
}

function choice(value, text) {
  const option = make('option', text);
  option.value = value;
  return option;
}

function editField(label, value, change, {numeric = false, placeholder = ''} = {}) {
  const input = make('input');
  input.type = numeric ? 'number' : 'text';
  input.value = value ?? '';
  input.placeholder = placeholder;
  input.oninput = () => change(numeric ? (Number.isFinite(input.valueAsNumber) ? input.valueAsNumber : null) : input.value.trim());
  return labelFor(label, input);
}

const milliseconds = value => value == null ? '—' : value.toFixed(1) + ' ms';
const percent = value => value == null ? '—' : (value * 100).toFixed(1) + '%';
const stamp = value => value ? new Date(value).toLocaleString() : '—';
const readable = value => value ? value.replaceAll('_', ' ') : '—';

const statusMetrics = {
  Timing: {
    'Tunnel round trip': member => milliseconds(member.carrier_rtt == null ? undefined : member.carrier_rtt / 1e6),
    'Control round trip': member => milliseconds(member.control_latency_millis),
    'SOCKS connect': member => milliseconds(member.socks_connect_millis),
    'Virtual service setup': member => milliseconds(member.virtual_service_millis),
    'Local attachment overhead': member => milliseconds(member.attachment_overhead_millis),
    'HTTPS probe first byte': member => milliseconds(member.https_ttfb_millis),
    'Setup variability': member => milliseconds(member.variability_millis ?? (member.connect_millis ? 0 : undefined)),
    'Last successful connection': member => stamp(member.last_success),
    'Last health probe': member => stamp(member.last_probe)
  },
  Traffic: {
    'Active connections': member => member.active ?? 0,
    'Bytes sent': member => (member.sent ?? 0).toLocaleString(),
    'Bytes received': member => (member.received ?? 0).toLocaleString(),
    'Connection attempts': member => member.attempts ?? 0,
    'Recent samples': member => member.recent_samples ?? 0,
    'Carrier packet loss': member => percent(member.carrier_loss ?? (member.carrier_rtt ? 0 : undefined))
  },
  Failures: {
    'Circuit state': member => readable(member.circuit),
    'Destination failures': member => member.recent_destination_failures ?? 0,
    'Consecutive infrastructure failures': member => member.consecutive_infrastructure_failures ?? 0,
    'Reconnects': member => member.reconnections ?? 0,
    'Last failure': member => readable(member.last_failure),
    'Last failure stage': member => readable(member.last_failure_stage)
  }
};

function statusCard(prefer, exclude) {
  const card = make('article', undefined, 'smart-card');
  const title = make('h4');
  const summary = make('p', undefined, 'smart-live-primary');
  const actions = make('div', undefined, 'row');
  const preferButton = button('Prefer', () => prefer(row.member));
  const excludeButton = button('Exclude temporarily', () => exclude(row.member, row.member.reason !== 'excluded'));
  actions.append(preferButton, excludeButton);
  const metrics = make('div', undefined, 'smart-metrics');
  const values = [];
  for (const [name, entries] of Object.entries(statusMetrics)) {
    const column = make('div');
    const list = make('dl');
    column.append(make('h4', name), list);
    for (const [label, format] of Object.entries(entries)) {
      const value = make('dd');
      list.append(make('dt', label), value);
      values.push({value, format});
    }
    metrics.append(column);
  }
  card.append(title, summary, actions, metrics);
  const row = {
    card,
    update(member, name, actionsEnabled = true) {
      row.member = member;
      const recent = member.recent_samples ? percent(member.success_rate ?? 0) : '—';
      const reason = readable(member.reason);
      const availability = member.eligible ? 'Available' : 'Unavailable';
      const status = member.reason ? availability + ' (' + reason + ')' : availability;
      updateText(title, name);
      updateText(summary, [status, member.transport || 'No transport',
        'Setup ' + milliseconds(member.connect_millis), 'Recent success ' + recent].join(' · '));
      preferButton.disabled = !actionsEnabled || !member.eligible;
      excludeButton.disabled = !actionsEnabled;
      preferButton.setAttribute('aria-label', 'Prefer ' + name);
      const action = member.reason === 'excluded' ? 'Include' : 'Exclude temporarily';
      updateText(excludeButton, action);
      excludeButton.setAttribute('aria-label', action + ' ' + name);
      for (const {value, format} of values) updateText(value, String(format(member)));
    }
  };
  return row;
}

function bindSettingsTabs(tablist, getPanel) {
  const tabs = [...tablist.querySelectorAll('[role="tab"]')];
  const panels = tabs.map(tab => getPanel(tab.getAttribute('aria-controls')));
  function select(index) {
    for (const [i, tab] of tabs.entries()) {
      const active = i === index;
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
      panels[i].hidden = !active;
    }
  }
  for (const [index, tab] of tabs.entries()) {
    tab.addEventListener('click', () => select(index));
    tab.addEventListener('keydown', event => {
      let next;
      switch (event.key) {
        case 'ArrowLeft': next = (index + tabs.length - 1) % tabs.length; break;
        case 'ArrowRight': next = (index + 1) % tabs.length; break;
        case 'Home': next = 0; break;
        case 'End': next = tabs.length - 1; break;
        default: return;
      }
      event.preventDefault();
      select(next);
      tabs[next].focus();
    });
  }
}

function chartRows(members, label, measure) {
  return members.map(member => ({label: label(member), value: measure(member)}))
    .filter(row => Number.isFinite(row.value) && row.value >= 0)
    .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
}

export function createSmartProxy({api, dashboardURL, exportURL, getProfiles}) {
  const field = name => document.getElementById('smart-proxy-' + name);
  const form = field('form');
  const controls = [...form.querySelectorAll('[data-smart-field]')];
  field('asn-toggle').onclick = () => {
    const panel = field('asn-settings');
    panel.hidden = !panel.hidden;
    field('asn-toggle').setAttribute('aria-expanded', String(!panel.hidden));
  };
  const protocolInputs = [...form.querySelectorAll('[data-smart-protocol]')];
  const copyButtons = [...field('actions').querySelectorAll('[data-copy-proxy]')];
  const selectGroup = field('group');
  const master = field('master');
  const groupEnabled = field('group-enabled');
  const exportLink = field('export');
  const importFile = field('import-file');
  const openLive = field('open-live');
  const tunnelPicker = field('available');
  const approval = field('approve');
  const unapproved = new Set();
  let offers = [];
  let saved, draft;
  let groupName = 'default';
  let live = {};
  let dirty = false;
  let busy = false;
  let changingMaster = false;
  let importing = false;
  let liveError = '';
  let loadError = '';

  bindSettingsTabs(field('tabs'), id => document.getElementById(id));
  openLive.href = dashboardURL(groupName);
  openLive.addEventListener('click', async event => {
    if (typeof window.openSmartProxyDashboard !== 'function') return;
    event.preventDefault();
    try {
      await window.openSmartProxyDashboard(groupName);
    } catch (error) {
      updateText(field('action-status'), String(error));
    }
  });
  exportLink.href = exportURL;
  exportLink.hidden = false;
  exportLink.addEventListener('click', event => {
    if (typeof window.openSmartProxyExport !== 'function') return;
    event.preventDefault();
    window.openSmartProxyExport().catch(error => groupMessage(String(error), true));
  });
  field('import').onclick = () => importFile.click();
  importFile.onchange = async () => {
    const file = importFile.files[0];
    importFile.value = '';
    if (!file || (dirty && !confirm('Replace the unsaved Smart Proxy edits with these imported settings?'))) return;
    importing = true;
    updateDraftIndicator();
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error('The Smart Proxy export is too large.');
      const config = readSharedConfig(await file.text(), getProfiles());
      draft = prepareConfig(await api('POST', proxyPath + '/validate', config));
      unapproved.clear();
      for (const [name, group] of [['default', draft], ...Object.entries(draft.groups || {})]) {
        if (group.egress.members.length || group.egress.enroll.length) unapproved.add(name);
      }
      if (!groupAt(draft, groupName)) groupName = 'default';
      renderGroup();
      groupMessage('Settings imported into the draft. Review local profile IDs, approve trusted tunnels, then select Save changes.');
    } catch (error) {
      groupMessage(error.message, true);
    } finally {
      importing = false;
      updateDraftIndicator();
    }
  };

  const group = () => groupAt(draft, groupName);
  const liveGroup = () => groupAt(live, groupName) || {};
  const members = () => (group().egress.members ??= []);
  const enrollments = () => (group().egress.enroll ??= []);
  const rules = () => (group().routing.rules ??= []);
  function memberLabel(member) {
    const profile = getProfiles().get(member.profile_id)?.profile;
    return (profile?.Name || profile?.name || member.profile_id || 'Profile') + ' / ' + (member.tunnel || 'Tunnel');
  }

  function message(text, error = false) {
    updateText(field('save-status'), text);
    field('save-status').classList.toggle('smart-warning', error);
  }

  function groupMessage(text, error = false) {
    updateText(field('group-status'), text);
    field('group-status').classList.toggle('smart-warning', error);
  }

  function updateDraftIndicator() {
    // Review flags are temporary UI state. The saved configuration is the
    // baseline for all group and global PAC edits.
    dirty = !!draft && (unapproved.size > 0 || JSON.stringify(draft) !== JSON.stringify(saved));
    field('unsaved').hidden = !dirty;
    field('save').disabled = !dirty || busy || changingMaster || importing;
    field('discard').disabled = !dirty || busy || importing;
    field('group-controls').disabled = !draft || busy || importing;
    field('fields').disabled = !draft || busy || importing;
    updateActions();
  }

  function edited() {
    message('');
    updateDraftIndicator();
  }

  function updateApproval() {
    const hasSources = members().length + enrollments().length > 0;
    if (!hasSources) unapproved.delete(groupName);
    approval.disabled = !hasSources;
    approval.checked = hasSources && !unapproved.has(groupName);
  }

  function membershipEdited(trustChanged) {
    if (trustChanged) unapproved.add(groupName);
    updateApproval();
    edited();
  }

  function refreshOffers() {
    if (!draft) return;
    const existing = new Set(members().map(memberKey));
    const selected = tunnelPicker.value;
    const current = [];
    for (const [profileID, snapshot] of getProfiles()) {
      for (const tunnel of snapshot.connection?.tunnels || []) {
        const member = {profile_id: profileID, tunnel: tunnel.name, expected_server: snapshot.connection.server, priority: 100};
        if (tunnel.target_hint === 'socks' && !existing.has(memberKey(member))) current.push(member);
      }
    }
    const offerLabel = member => [memberKey(member), memberLabel(member)];
    const next = current.map(offerLabel);
    const present = [...tunnelPicker.options].filter(option => option.value).map(option => [option.value, option.textContent]);
    offers = current;
    if (JSON.stringify(next) !== JSON.stringify(present) || !tunnelPicker.options.length) {
      tunnelPicker.replaceChildren(...(offers.length ? next.map(([key, label]) => choice(key, label))
        : [choice('', 'No connected SOCKS tunnels to add')]));
      if (offers.some(member => memberKey(member) === selected)) tunnelPicker.value = selected;
    }
    tunnelPicker.disabled = !offers.length;
    field('add').disabled = !offers.length || members().length >= 64;
  }

  const matchFields = [
    ['Exact hostnames', 'hosts', 'app.example.net'],
    ['Domain suffixes', 'suffixes', 'example.net'],
    ['IP ranges (CIDR)', 'cidrs', '192.0.2.0/24'],
    ['Ports', 'ports', '80, 443'],
    ['ASNs', 'asns', 'AS13335, 15169']
  ];
  const ruleActions = {
    any: 'Through any ntwire tunnel',
    selected: 'Through selected ntwire tunnels',
    direct: 'Direct client connection',
    deny: 'Deny'
  };
  const tables = {
    members: {entries: members, name: 'tunnel', label: 'Tunnels', add: 'add-manual', limit: 64,
      columns: ['Profile / Tunnel', 'Expected server', 'Policy class', 'Priority']},
    enrollments: {entries: enrollments, name: 'enrollment', label: 'Automatic enrollment', add: 'add-enrollment', limit: 16,
      columns: ['Profile', 'Trusted HTTPS server', 'Policy class', 'Priority']},
    rules: {entries: rules, name: 'rule', label: 'Destination rules', add: 'add-rule', limit: 64,
      columns: ['Order', 'Matches', 'When matched']}
  };

  function profileLabel(id) {
    const profile = getProfiles().get(id)?.profile;
    return profile?.Name || profile?.name || id;
  }

  function tableValues(kind, entry, index) {
    if (kind !== 'rules') {
      return [kind === 'members' ? memberLabel(entry) : profileLabel(entry.profile_id),
        entry.expected_server, entry.egress_class || '—', String(entry.priority ?? '—')];
    }
    const conditions = make('div');
    for (const [label, key] of matchFields) {
      if (entry[key]?.length) conditions.append(make('div', label + ': ' + entry[key].join(', ')));
    }
    if (!conditions.childElementCount) conditions.textContent = 'Any destination';
    const match = make('div', ruleActions[ruleMode(entry)]);
    if (ruleMode(entry) === 'selected' && entry.members?.length) {
      match.append(make('div', entry.members.map(memberLabel).join(', '), 'help'));
    }
    const warning = validateRule(entry, members());
    if (warning) match.append(make('div', warning, 'smart-warning'));
    return [String(index + 1), conditions, match];
  }

  function renderTable(kind, focusIndex, focusAction = 'edit') {
    const spec = tables[kind];
    const entries = spec.entries();
    const target = field(kind);
    const add = field(spec.add);
    add.disabled = entries.length >= spec.limit;
    if (kind === 'members') { refreshOffers(); renderResolverMembers(); }
    target.replaceChildren();
    if (!entries.length) {
      target.append(make('p', 'No ' + (kind === 'rules' ? 'destination rules' : kind === 'members' ? 'tunnels' : 'enrollments') + ' yet.', 'help'));
      if (focusIndex !== undefined) add.focus();
      return;
    }

    const wrap = make('div', undefined, 'smart-table-wrap');
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'region');
    wrap.setAttribute('aria-label', spec.label);
    const table = make('table', undefined, 'smart-table');
    table.setAttribute('aria-label', spec.label);
    const headings = make('tr');
    for (const title of [...spec.columns, 'Actions']) {
      const header = make('th', title);
      header.scope = 'col';
      headings.append(header);
    }
    const head = make('thead');
    head.append(headings);
    const body = make('tbody');
    for (const [index, entry] of entries.entries()) {
      const row = make('tr');
      for (const [column, value] of tableValues(kind, entry, index).entries()) {
        const cell = make(column === 0 ? 'th' : 'td');
        if (column === 0) cell.scope = 'row';
        cell.append(value ?? '—');
        row.append(cell);
      }
      const actions = make('div', undefined, 'smart-table-actions');
      const title = spec.name + ' ' + (index + 1);
      function action(name, text, description, run, disabled = false) {
        const control = button(text, run, description + title);
        control.title = description + title;
        control.dataset.editorAction = name;
        control.disabled = disabled;
        actions.append(control);
      }
      function move(offset) {
        const next = index + offset;
        [entries[index], entries[next]] = [entries[next], entries[index]];
        edited();
        renderTable(kind, next, offset < 0 ? 'up' : 'down');
      }
      action('edit', 'Edit', 'Edit ', () => openEditor(kind, index, entry));
      action('remove', 'Remove', 'Remove ', () => {
        entries.splice(index, 1);
        if (kind === 'rules') edited();
        else membershipEdited(true);
        renderTable(kind, Math.min(index, entries.length - 1), 'remove');
        if (kind === 'members') renderTable('rules');
      });
      action('up', '↑', 'Move up ', () => move(-1), index === 0);
      action('down', '↓', 'Move down ', () => move(1), index === entries.length - 1);
      const cell = make('td');
      cell.append(actions);
      row.append(cell);
      body.append(row);
    }
    table.append(head, body);
    wrap.append(table);
    target.append(wrap);
    if (focusIndex !== undefined) {
      const row = body.rows[focusIndex];
      (row?.querySelector('[data-editor-action="' + focusAction + '"]:enabled') ||
        row?.querySelector('[data-editor-action="edit"]') || add).focus();
    }
  }

  function membershipFields(kind, entry) {
    const explicit = kind === 'members';
    const fields = make('div', undefined, 'smart-fields');
    function add(label, key, options) {
      fields.append(editField(label, entry[key], value => { entry[key] = value; }, options));
    }
    add('Profile ID', 'profile_id', {placeholder: 'office'});
    if (explicit) add('Tunnel name', 'tunnel', {placeholder: 'internet'});
    add(explicit ? 'Expected server' : 'Trusted HTTPS server', 'expected_server', {placeholder: 'https://office.example.net'});
    add(explicit ? 'Policy class (optional)' : 'Policy class', 'egress_class', {placeholder: 'office-v1'});
    add('Priority', 'priority', {numeric: true});
    return fields;
  }

  function ruleFields(rule, warning) {
    const fields = make('div', undefined, 'smart-fields');
    const destinations = make('fieldset', undefined, 'smart-card smart-targets');
    const mode = make('select');
    mode.append(...Object.entries(ruleActions).map(([value, label]) => choice(value, label)));
    mode.value = ruleMode(rule);
    mode.onchange = () => {
      rule.mode = mode.value;
      renderTargets();
    };
    const refreshWarning = () => updateText(warning, validateRule(rule, members()));
    function renderTargets() {
      destinations.replaceChildren(make('legend', 'Tunnels allowed by this rule'));
      destinations.disabled = mode.value !== 'selected';
      destinations.hidden = destinations.disabled;
      const selected = rule.members ?? [];
      const byKey = new Map(members().filter(member => member.profile_id && member.tunnel)
        .map(member => [memberKey(member), member]));
      const candidates = new Map([...selected.map(member => [memberKey(member), member]), ...byKey]);
      if (!candidates.size) destinations.append(make('p', 'Add tunnels to this group before restricting a rule.', 'help'));
      for (const [key, member] of candidates) {
        const toggle = make('input');
        toggle.type = 'checkbox';
        toggle.checked = selected.some(current => memberKey(current) === key);
        toggle.onchange = () => {
          rule.members = toggle.checked ? [...rule.members || [], {profile_id: member.profile_id, tunnel: member.tunnel}]
            : (rule.members || []).filter(current => memberKey(current) !== key);
          refreshWarning();
        };
        const label = labelFor(' ' + memberLabel(member) + (byKey.has(key) ? '' : ' (removed)'), toggle, 'toggle');
        label.prepend(toggle);
        destinations.append(label);
      }
      refreshWarning();
    }
    for (const [label, key, hint] of matchFields) {
      fields.append(editField(label, (rule[key] || []).join(', '), value => {
        rule[key] = key === 'asns' ? value.split(/[,\s]+/).filter(Boolean) : tokens(value);
        refreshWarning();
      }, {placeholder: hint}));
    }
    renderTargets();
    return [make('p', 'Leaving every match field empty matches all destinations.', 'help'),
      fields, labelFor('When matched', mode), destinations];
  }

  function editorError(kind, entry, index) {
    if (kind === 'rules') return validateRule(entry, members());
    const explicit = kind === 'members';
    if (!idPattern.test(entry.profile_id || '') || !entry.expected_server ||
        (explicit ? !entry.tunnel : !idPattern.test(entry.egress_class || '')) || !Number.isSafeInteger(entry.priority)) {
      return explicit ? 'Enter a valid profile ID, tunnel name, expected server, and integer priority.'
        : 'Enter a valid profile ID, trusted HTTPS server, policy class, and integer priority.';
    }
    const key = explicit ? memberKey : value => JSON.stringify([value.profile_id, value.egress_class]);
    if (tables[kind].entries().some((other, i) => i !== index && key(other) === key(entry))) {
      return 'This ' + tables[kind].name + ' already exists in the group.';
    }
    return '';
  }

  function openEditor(kind, index, initial) {
    const spec = tables[kind];
    const entries = spec.entries();
    const adding = index === undefined;
    if (adding && entries.length >= spec.limit) return;
    const entry = structuredClone(initial);
    const dialog = make('dialog', undefined, 'browser-profile-dialog smart-editor');
    const title = make('h2', (adding ? 'Add ' : 'Edit ') + spec.name);
    title.id = 'smart-proxy-editor-title';
    dialog.setAttribute('aria-labelledby', title.id);
    const editor = make('form');
    const warning = make('p', undefined, 'smart-warning');
    warning.setAttribute('role', 'status');
    const actions = make('div', undefined, 'row panel-actions');
    const submit = make('button', adding ? 'Add ' + spec.name : 'Apply edits');
    submit.type = 'submit';
    actions.append(submit, button('Cancel', () => dialog.close()));
    editor.append(...(kind === 'rules' ? ruleFields(entry, warning) : [membershipFields(kind, entry)]), warning, actions);
    dialog.append(title, editor);
    dialog.addEventListener('close', () => dialog.remove(), {once: true});
    editor.onsubmit = event => {
      event.preventDefault();
      const error = editorError(kind, entry, index);
      updateText(warning, error);
      if (error) return;
      const next = adding ? entries.length : index;
      entries[next] = entry;
      dialog.close();
      if (kind === 'rules') edited();
      else {
        const trustChanged = adding || ['profile_id', 'tunnel', 'expected_server', 'egress_class']
          .some(key => (initial[key] ?? '') !== (entry[key] ?? ''));
        membershipEdited(trustChanged);
      }
      renderTable(kind, next);
      if (kind === 'members') renderTable('rules');
    };
    document.body.append(dialog);
    dialog.showModal();
  }

  function openStrategyGuide() {
    const dialog = make('dialog', undefined, 'browser-profile-dialog smart-editor');
    const title = make('h2', 'Choosing a routing strategy');
    title.id = 'smart-proxy-strategy-guide-title';
    dialog.setAttribute('aria-labelledby', title.id);
    const wrap = make('div', undefined, 'smart-table-wrap');
    const table = make('table', undefined, 'smart-table');
    const head = make('tr');
    for (const name of ['Strategy', 'How it picks', 'Best for']) head.append(make('th', name));
    const thead = make('thead');
    thead.append(head);
    table.append(thead);
    const body = make('tbody');
    const current = group().egress.selection ?? 'sticky-fastest';
    for (const [value, name, how, best] of strategyGuide) {
      const row = make('tr');
      const cell = make('th', name + (value === current ? ' (selected)' : ''));
      cell.scope = 'row';
      row.append(cell, make('td', how), make('td', best));
      body.append(row);
    }
    table.append(body);
    wrap.append(table);
    const note = make('p', 'All strategies skip tunnels that are unhealthy, and failover can still retry another tunnel when a connection fails. Destination rules are applied before the strategy picks.', 'help');
    const actions = make('div', undefined, 'row panel-actions');
    actions.append(button('Close', () => dialog.close()));
    dialog.append(title, wrap, note, actions);
    dialog.addEventListener('close', () => dialog.remove(), {once: true});
    document.body.append(dialog);
    dialog.showModal();
  }

  function strategyDetails() {
    updateText(field('strategy-help'), strategyHelp[group().egress.selection ?? 'sticky-fastest'] || '');
  }

  function prepareConfig(config) {
    const next = structuredClone(config);
    for (const settings of [next, ...Object.values(next.groups || {})]) {
      settings.egress ??= {};
      settings.egress.members ??= [];
      settings.egress.enroll ??= [];
      settings.routing ??= {};
      settings.routing.rules ??= [];
    }
    return next;
  }

  function renderResolverMembers() {
    const picker = field('asn-resolver');
    const member = group().routing.asn?.resolver_member;
    const entries = members().map(entry => [memberKey(entry), memberLabel(entry)]);
    if (member && !entries.some(([key]) => key === memberKey(member))) entries.push([memberKey(member), memberLabel(member) + ' (removed)']);
    picker.replaceChildren(choice('', 'No resolver tunnel'), ...entries.map(([key, name]) => choice(key, name)));
    picker.value = member ? memberKey(member) : '';
    picker.disabled = !['local', 'remote'].includes(group().routing.asn?.hostname_resolution);
    field('asn-hosts').disabled = field('asn-suffixes').disabled = picker.disabled;
  }

  field('asn-resolver').onchange = event => {
    const policy = (group().routing.asn ??= {});
    const target = event.target.value;
    if (target) {
      const [profile_id, tunnel] = JSON.parse(target);
      policy.resolver_member = {profile_id, tunnel};
    } else delete policy.resolver_member;
    edited();
  };

  const rootSetting = path => path === 'pac_listen' || path.startsWith('asn_database.');

  function renderGroup() {
    selectGroup.replaceChildren(...['default', ...Object.keys(draft.groups || {}).sort()]
      .map(name => choice(name, displayGroup(name))));
    selectGroup.value = groupName;
    groupEnabled.checked = !!group().enabled;
    openLive.href = dashboardURL(groupName);
    field('remove-group').disabled = groupName === 'default';
    field('add-group').disabled = Object.keys(draft.groups || {}).length >= 16;
    for (const control of controls) {
      const path = control.dataset.smartField;
      let value = read(rootSetting(path) ? draft : group(), path);
      if (path === 'limits.concurrent_attempts' && value === undefined && group().limits?.auto) value = 128;
      setControl(control, value);
    }
    for (const input of protocolInputs) {
      input.checked = (group().protocols ?? defaultProtocols).includes(input.dataset.smartProtocol);
    }
    strategyDetails();
    renderResolverMembers();
    for (const kind of Object.keys(tables)) renderTable(kind);
    updateApproval();
    renderLive();
    updateDraftIndicator();
  }

  function updateActions() {
    const state = liveGroup();
    const config = groupAt(saved, groupName);
    const masterOn = live.master_enabled === true;
    const listening = masterOn && !changingMaster && !!state.listening && !!config;
    master.disabled = busy || changingMaster || importing || typeof live.master_enabled !== 'boolean';
    if (!changingMaster) master.checked = masterOn;
    openLive.hidden = !masterOn;
    const protocols = config?.protocols || defaultProtocols;
    for (const copy of copyButtons) {
      const kind = copy.dataset.copyProxy;
      copy.disabled = busy || !listening || (kind === 'pac' ? !live.pac_listen : !protocols.includes(kind));
    }
    field('browser').disabled = busy || !listening;
    const help = [];
    if (!masterOn) help.push('Enable Smart Proxy to use the proxy actions.');
    else if (!listening && !changingMaster) help.push('Activate and save this group to use the proxy actions.');
    else if (listening) {
      const unavailable = [];
      if (!protocols.includes('socks5')) unavailable.push('SOCKS5');
      if (!protocols.includes('http')) unavailable.push('HTTP');
      if (!live.pac_listen) unavailable.push('PAC');
      if (unavailable.length) help.push(unavailable.join(', ') + ' not enabled.');
      if (protocols.includes('socks5') && !protocols.includes('http') && !state.numeric_domain_ready) {
        help.push('Numeric IPv4 and IPv6 URLs in Chromium require a compatible SOCKS5 tunnel. Enable HTTP for compatibility.');
      }
    }
    if (dirty) help.push('Proxy actions and live status use saved settings.');
    updateText(field('action-help'), help.join(' '));
  }

  async function requestAction(callback, success = '') {
    try {
      await callback();
      updateText(field('action-status'), success);
    } catch (error) {
      updateText(field('action-status'), error.message);
    }
  }

  function renderLive() {
    const state = liveGroup();
    const config = groupAt(saved, groupName);
    const status = !saved ? loadError || 'Loading proxy settings…' : live.master_enabled === false ? 'Smart Proxy is off'
      : !config ? 'New group · Save to apply settings'
      : state.listening ? 'Listening on ' + state.listening : config.enabled ? 'Not listening' : 'Disabled';
    const detail = status + (state.error || live.error ? ' · ' + (state.error || live.error) : '');
    updateText(field('state'), [detail, liveError].filter(Boolean).join(' · '));
    const db = live.asn_database;
    updateText(field('asn-status'), !db ? 'Inactive until an enabled group uses ASN rules.'
      : db.loaded ? [db.stale ? 'Stale' : 'Loaded', db.ranges.toLocaleString() + ' ranges',
        db.ipv6 ? 'IPv4 and IPv6' : 'IPv4 only', db.last_update && 'Updated ' + stamp(db.last_update), db.last_error].filter(Boolean).join(' · ')
      : ['Unavailable', db.last_error].filter(Boolean).join(' · '));
    updateActions();
  }

  function updateStatus(status) {
    live = status || {};
    liveError = '';
    if (saved && syncGroupActivation(saved, draft, live)) {
      groupEnabled.checked = !!group().enabled;
      updateDraftIndicator();
    }
    renderLive();
  }

  master.onchange = async () => {
    changingMaster = true;
    updateText(field('master-status'), '');
    updateDraftIndicator();
    try {
      updateStatus(await api('PUT', proxyPath + '/master', {enabled: master.checked}));
    } catch (error) {
      updateText(field('master-status'), error.message);
    } finally {
      changingMaster = false;
      updateDraftIndicator();
    }
  };
  groupEnabled.onchange = () => {
    group().enabled = groupEnabled.checked;
    edited();
  };

  async function refreshStatus() {
    try {
      updateStatus(await api('GET', proxyPath + '/status'));
    } catch (error) {
      liveError = 'Could not refresh live status. ' + error.message;
      renderLive();
    }
  }

  function loadConfig(config) {
    saved = prepareConfig(config);
    draft = structuredClone(saved);
    if (!groupAt(draft, groupName)) groupName = 'default';
    unapproved.clear();
    renderGroup();
  }

  for (const control of controls) {
    const event = control.matches('select') ? 'change' : 'input';
    control.addEventListener(event, () => {
      const path = control.dataset.smartField;
      const value = controlValue(control);
      if (path.startsWith('asn_database.') && value === null) {
        if (draft.asn_database) delete draft.asn_database[path.split('.')[1]];
      } else write(rootSetting(path) ? draft : group(), path, value);
      if (path === 'routing.asn.hostname_resolution') {
        const policy = group().routing.asn;
        if (!['local', 'remote'].includes(value)) {
          delete policy.resolver_member;
          delete policy.hosts;
          delete policy.suffixes;
          setControl(field('asn-hosts'), undefined);
          setControl(field('asn-suffixes'), undefined);
        }
        renderResolverMembers();
      }
      if (path === 'limits.auto') renderGroup();
      if (path === 'egress.selection') strategyDetails();
      edited();
    });
  }
  for (const input of protocolInputs) {
    input.onchange = () => {
      const selected = new Set(protocolInputs.filter(input => input.checked).map(input => input.dataset.smartProtocol));
      group().protocols = [...new Set([...(group().protocols || defaultProtocols), ...selected])]
        .filter(protocol => selected.has(protocol));
      edited();
    };
  }
  selectGroup.onchange = () => {
    groupName = selectGroup.value;
    groupMessage('');
    updateText(field('action-status'), '');
    renderGroup();
  };
  field('strategy-compare').onclick = openStrategyGuide;
  field('add-group').onclick = () => {
    const input = field('group-name');
    const name = input.value.trim();
    if (!idPattern.test(name) || name === 'default' || Object.hasOwn(draft.groups || {}, name)) {
      groupMessage('Enter a unique group name starting with a lowercase letter or digit. Use lowercase letters, digits, hyphens, or underscores.', true);
      input.focus();
      return;
    }
    const addresses = new Set([draft.listen, draft.pac_listen, ...Object.values(draft.groups || {}).map(group => group.listen)]);
    let port = 1081;
    while (addresses.has('127.0.0.1:' + port)) port++;
    draft.groups ??= {};
    draft.groups[name] = {
      enabled: false, listen: '127.0.0.1:' + port, protocols: [...defaultProtocols],
      egress: {selection: 'sticky-fastest', members: [], enroll: []}, routing: {rules: []}
    };
    groupName = name;
    input.value = '';
    groupMessage('');
    renderGroup();
    edited();
  };
  field('remove-group').onclick = () => {
    if (groupName === 'default') return;
    delete draft.groups[groupName];
    unapproved.delete(groupName);
    if (!Object.keys(draft.groups).length) delete draft.groups;
    groupName = 'default';
    renderGroup();
    groupMessage('Group removal takes effect when you save.');
  };
  approval.onchange = () => {
    if (approval.checked) unapproved.delete(groupName);
    else unapproved.add(groupName);
    edited();
  };
  field('add').onclick = () => {
    const member = offers.find(offer => memberKey(offer) === tunnelPicker.value);
    if (member) openEditor('members', undefined, member);
  };
  field('add-manual').onclick = () => openEditor('members', undefined, {priority: 100});
  field('add-enrollment').onclick = () => openEditor('enrollments', undefined, {priority: 100});
  field('add-rule').onclick = () => openEditor('rules', undefined, {mode: 'deny'});
  field('discard').onclick = () => {
    loadConfig(saved);
    groupMessage('');
    message('Pending changes discarded.');
  };
  form.onsubmit = async event => {
    event.preventDefault();
    if (!draft || !dirty || busy || changingMaster || importing) return;
    try {
      const config = buildRequest(draft, controls, unapproved);
      busy = true;
      updateDraftIndicator();
      message('Saving…');
      loadConfig(await api('PUT', proxyPath, config));
      await refreshStatus();
      groupMessage('');
      message('Smart Proxy settings saved.');
    } catch (error) {
      message(error.message, true);
    } finally {
      busy = false;
      updateDraftIndicator();
    }
  };
  field('browser').onclick = () => requestAction(() => api('POST', proxyPath + '/open-browser?group=' + encodeURIComponent(groupName)));
  for (const copy of copyButtons) {
    copy.onclick = () => requestAction(async () => {
      const kind = copy.dataset.copyProxy;
      const address = kind === 'pac' ? 'http://' + live.pac_listen + '/' + groupName + '.pac'
        : (kind === 'socks5' ? 'socks5h' : 'http') + '://' + liveGroup().listening;
      if (!navigator.clipboard) throw new Error('Clipboard unavailable. Proxy URL: ' + address);
      await navigator.clipboard.writeText(address);
    }, 'Proxy URL copied.');
  }

  return {
    async load() {
      try {
        loadConfig(await api('GET', proxyPath));
        await refreshStatus();
      } catch (error) {
        loadError = 'Could not load proxy settings. ' + error.message;
        renderLive();
      }
    },
    updateStatus,
    refreshOffers
  };
}

export {strategyGuide, bindSettingsTabs, buildRequest, chartRows, choice, controlValue, displayGroup, groupAt, make,
  memberKey, milliseconds, readable, readSharedConfig, setControl, statusCard, statusMetrics, syncGroupActivation, updateText};
