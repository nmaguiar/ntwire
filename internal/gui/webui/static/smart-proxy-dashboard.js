const settingsModule = new URL('./smart-proxy.js', import.meta.url);
settingsModule.search = new URL(import.meta.url).search;
const {
  chartRows, choice, displayGroup, groupAt, make, memberKey, milliseconds, readable, statusCard, updateText
} = await import(settingsModule);

const windowMillis = 5 * 60_000;
const maxGapMillis = 10_000;
const apiPath = '/api/smart-proxy';
const svgNS = 'http://www.w3.org/2000/svg';
const count = value => value.toLocaleString();
const bytes = value => {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return value.toFixed(unit ? 1 : 0) + ' ' + units[unit];
};
const rate = value => bytes(value) + '/s';
const clock = new Intl.DateTimeFormat(undefined, {hour: 'numeric', minute: '2-digit', second: '2-digit'});

function trafficRates(before, member, seconds) {
  const rates = {};
  if (!before || seconds <= 0 || seconds * 1000 > maxGapMillis) return rates;
  for (const metric of ['sent', 'received']) {
    if (!Number.isFinite(before[metric]) || !Number.isFinite(member[metric])) continue;
    rates[metric] = Math.max(0, member[metric] - before[metric]) / seconds;
  }
  return rates;
}

function trafficEntriesFor(state) {
  const entries = state.members || [];
  const direct = state.direct;
  return direct ? [...entries, {...direct, direct: true, sent: direct.sent + (direct.udp_sent ?? 0),
    received: direct.received + (direct.udp_received ?? 0), routed: direct.successes}] : entries;
}

const trafficKey = member => member.direct ? 'direct' : memberKey(member);

function tunnelOutage(state) {
  switch (state) {
    case 'reconnecting': return 'Reconnecting';
    case 'failed': return 'Connection failed';
    case 'idle': return 'Profile disconnected';
    case 'transport': return 'Tunnel transport unavailable';
  }
}

function recordSample(history, state, time) {
  const entries = trafficEntriesFor(state);
  const previous = history.at(-1);
  const elapsed = previous ? (time - previous.time) / 1000 : 0;
  const totals = {};
  const members = new Map(entries.map(member => {
    const key = trafficKey(member);
    const outage = tunnelOutage(member.outage);
    const traffic = outage ? {} : trafficRates(previous?.members.get(key), member, elapsed);
    for (const [metric, value] of Object.entries(traffic)) {
      totals[metric] = (totals[metric] ?? 0) + value;
    }
    return [key, {
      member: {profile_id: member.profile_id, tunnel: member.tunnel, direct: member.direct},
      sent: outage ? undefined : member.sent, received: outage ? undefined : member.received, traffic,
      setup: member.connect_millis, rtt: member.carrier_rtt == null ? undefined : member.carrier_rtt / 1e6,
      latency: member.https_ttfb_millis, outage
    }];
  }));
  history.push({
    time,
    active: state.listening ? state.active ?? 0 : undefined,
    ...totals,
    members
  });
  while (history.length && history[0].time < time - windowMillis) history.shift();
}

function measuredLatency(sample, tunnel, metric) {
  const member = sample.members.get(tunnel);
  return member?.outage ? undefined : member?.[metric];
}

function latencySeries(choices, tunnel) {
  if (tunnel === 'direct') return [{name: 'Setup', color: 'primary', measure: sample => measuredLatency(sample, tunnel, 'setup')}];
  if (tunnel) {
    const measure = metric => sample => measuredLatency(sample, tunnel, metric);
    return [
      {name: 'Setup', color: 'primary', measure: measure('setup')},
      {name: 'Tunnel round trip', color: 'secondary-series', measure: measure('rtt')},
      {name: 'HTTPS probe', color: 'tertiary', measure: measure('latency')}
    ];
  }
  // Sort by identifier so status ordering changes don't swap line colors.
  return choices.toSorted(([a], [b]) => a.localeCompare(b)).map(([key, name], index) => ({
    name,
    hue: (222 + index * 137.508) % 360,
    measure: sample => measuredLatency(sample, key, 'setup')
  }));
}

function styleSeries(element, line) {
  if (line.color) element.classList.add(line.color);
  else element.style.color = `hsl(${line.hue} 70% var(--comparison-lightness))`;
  return element;
}

function svgElement(tag, attrs) {
  const node = document.createElementNS(svgNS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
  return node;
}

function seriesPath(samples, measure, x, y) {
  let path = '';
  let previousTime;
  for (const sample of samples) {
    const value = measure(sample);
    if (!Number.isFinite(value)) {
      previousTime = undefined;
      continue;
    }
    path += (previousTime !== undefined && sample.time - previousTime <= maxGapMillis ? ' L' : ' M') +
      x(sample.time).toFixed(2) + ',' + y(value).toFixed(2);
    previousTime = sample.time;
  }
  return path.trim();
}

function trendBands(samples, outages) {
  const bands = [];
  for (const [i, sample] of samples.entries()) {
    const next = samples[i + 1];
    const gap = next && next.time - sample.time > maxGapMillis;
    const affected = outages?.(sample);
    if (affected?.length) bands.push({type: 'down', from: sample.time, to: next && !gap ? next.time : sample.time, sample, affected});
    if (gap) bands.push({type: 'gap', from: sample.time, to: next.time});
  }
  return bands;
}

function nearestSample(samples, time) {
  return samples.reduce((nearest, sample) =>
    Math.abs(sample.time - time) < Math.abs(nearest.time - time) ? sample : nearest);
}

let tooltip;
let tooltipOwner;
const chartHover = new WeakMap();

function showTooltip(owner, lines, {clientX, clientY}) {
  if (!tooltip) {
    tooltip = make('div', undefined, 'chart-tooltip');
    tooltip.setAttribute('aria-hidden', 'true');
    document.body.append(tooltip);
  }
  tooltipOwner = owner;
  tooltip.replaceChildren(...lines.map(line => make('div', line)));
  tooltip.style.left = '0px';
  tooltip.style.top = '0px';
  tooltip.style.display = 'block';
  const {width, height} = tooltip.getBoundingClientRect();
  const pad = 12;
  const left = clientX + pad + width > innerWidth - 8 ? clientX - width - pad : clientX + pad;
  const top = clientY + pad + height > innerHeight - 8 ? clientY - height - pad : clientY + pad;
  tooltip.style.left = Math.max(8, left) + 'px';
  tooltip.style.top = Math.max(8, top) + 'px';
}

function bindChartHover(container, render) {
  let hover = chartHover.get(container);
  if (!hover) {
    hover = {};
    chartHover.set(container, hover);
    const move = event => {
      hover.pointer = {clientX: event.clientX, clientY: event.clientY};
      refresh();
    };
    const leave = () => {
      hover.pointer = undefined;
      refresh();
    };
    const refresh = () => {
      const lines = hover.render?.(hover.pointer);
      if (lines) showTooltip(container, lines, hover.pointer);
      else if (tooltipOwner === container) {
        tooltip.style.display = 'none';
        tooltipOwner = undefined;
      }
    };
    hover.refresh = refresh;
    container.addEventListener('pointermove', move);
    container.addEventListener('pointerleave', leave);
    container.addEventListener('pointercancel', leave);
  }
  hover.render = render;
  hover.refresh();
}

function pointsAt(pointer, rect) {
  if (!pointer) return false;
  return rect.width > 0 && pointer.clientX >= rect.left && pointer.clientX <= rect.right &&
    pointer.clientY >= rect.top && pointer.clientY <= rect.bottom;
}

function renderTrend(container, samples, series, format, emptyText, outages) {
  const values = samples.flatMap(sample => series.map(line => line.measure(sample))).filter(Number.isFinite);
  const bands = trendBands(samples, outages);
  if (!values.length && !bands.length) {
    container.replaceChildren(make('p', emptyText, 'help chart-empty'));
    bindChartHover(container, undefined);
    return;
  }

  const latest = samples.at(-1);
  const width = 600;
  const height = 128;
  const start = samples[0].time;
  const duration = Math.max(1, latest.time - start);
  const x = time => 4 + (width - 8) * (time - start) / duration;
  const max = Math.max(1, ...values);
  const y = value => height - 4 - (height - 8) * value / max;
  const legend = make('div', undefined, 'legend');
  const plot = svgElement('svg', {
    class: 'plot', viewBox: '0 0 ' + width + ' ' + height, preserveAspectRatio: 'none', 'aria-hidden': true
  });
  for (const band of bands) {
    const left = x(band.from);
    const span = x(band.to) - left;
    plot.append(svgElement('rect', {
      class: 'chart-' + band.type, x: span ? left : left - 2, y: 0, width: span || 4, height
    }));
  }
  for (const value of [0, max / 2, max]) {
    plot.append(svgElement('line', {x1: 0, x2: width, y1: y(value), y2: y(value), stroke: 'var(--border)'}));
  }

  const labels = [];
  for (const line of series) {
    const label = styleSeries(make('span'), line);
    const dot = make('i');
    dot.setAttribute('aria-hidden', 'true');
    const text = make('span');
    label.append(dot, text);
    legend.append(label);
    labels.push({line, text});
    const path = seriesPath(samples, line.measure, x, y);
    if (path) {
      plot.append(styleSeries(svgElement('path', {d: path, fill: 'none', stroke: 'currentColor',
        'stroke-width': 2, 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke'}), line));
      // The endpoint is visible even when there is only one measurement.
      const end = samples.findLast(sample => Number.isFinite(line.measure(sample)));
      plot.append(styleSeries(svgElement('circle', {cx: x(end.time), cy: y(line.measure(end)), r: 3,
        fill: 'currentColor'}), line));
    }
  }
  for (const [type, name] of [['down', 'Tunnel down'], ['gap', 'No samples recorded']]) {
    if (!bands.some(band => band.type === type)) continue;
    const key = make('span', undefined, 'chart-key-' + type);
    const swatch = make('i');
    swatch.setAttribute('aria-hidden', 'true');
    key.append(swatch, name);
    legend.append(key);
  }
  const axes = make('div', undefined, 'axis');
  const guide = svgElement('line', {class: 'chart-guide', y1: 0, y2: height});
  guide.style.display = 'none';
  plot.append(guide);
  const time = make('span');
  axes.append(time);
  if (values.length) axes.append(make('span', format(0) + ' to ' + format(max)));
  function showLegend(sample) {
    updateText(time, clock.format(sample.time));
    for (const {line, text} of labels) {
      const value = line.measure(sample);
      updateText(text, line.name + ' ' + (Number.isFinite(value) ? format(value) : '—'));
    }
  }
  container.replaceChildren(legend, plot, axes);
  bindChartHover(container, pointer => {
    const rect = pointer && plot.getBoundingClientRect();
    if (!pointsAt(pointer, rect)) {
      guide.style.display = 'none';
      showLegend(latest);
      return;
    }
    const plotX = (pointer.clientX - rect.left) / rect.width * width;
    const pointerTime = start + duration * (plotX - 4) / (width - 8);
    const band = bands.find(item => pointerTime >= item.from && pointerTime < item.to);
    if (band?.type === 'gap') {
      guide.style.display = 'none';
      showLegend({time: pointerTime, members: new Map()});
      return [clock.format(pointerTime), 'No samples recorded'];
    }
    const sample = band?.sample || nearestSample(samples, pointerTime);
    guide.setAttribute('x1', x(sample.time));
    guide.setAttribute('x2', x(sample.time));
    guide.style.display = 'block';
    showLegend(sample);
    const lines = [clock.format(sample.time), ...series.slice(0, 8).map(line => {
      const value = line.measure(sample);
      return line.name + ': ' + (Number.isFinite(value) ? format(value) : '—');
    })];
    if (series.length > 8) lines.push((series.length - 8) + ' more in the legend');
    const affected = band?.affected ?? outages?.(sample);
    if (affected?.length) lines.push(...affected);
    return lines;
  });
}

function renderUsage(container, rows, sampleTime) {
  if (!rows.length) {
    container.replaceChildren(make('p', 'No tunnels reporting for this group.', 'help chart-empty'));
    bindChartHover(container, undefined);
    return;
  }
  const list = make('ul', undefined, 'bars');
  const max = rows[0].value || 1;
  for (const {label, value} of rows) {
    const item = make('li');
    const legend = make('div', undefined, 'bar-label');
    legend.append(make('span', label), make('span', count(value) + ' routed'));
    const track = make('div', undefined, 'bar-track');
    track.setAttribute('aria-hidden', 'true');
    const bar = svgElement('svg', {viewBox: '0 0 100 8', preserveAspectRatio: 'none'});
    bar.append(svgElement('rect', {width: 100 * value / max, height: 8, fill: 'currentColor'}));
    track.append(bar);
    item.append(legend, track);
    list.append(item);
  }
  container.replaceChildren(list);
  bindChartHover(container, pointer => {
    if (!pointer || sampleTime == null) return;
    const index = Array.from(list.children).findIndex(item => pointsAt(pointer, item.getBoundingClientRect()));
    if (index < 0) return;
    const {label, value} = rows[index];
    return [clock.format(sampleTime), label, 'Routed: ' + count(value)];
  });
}

function fillSelect(select, entries, selected) {
  const changed = select.options.length !== entries.length ||
    entries.some(([key, label], i) => select.options[i].value !== key || select.options[i].text !== label);
  if (changed) select.replaceChildren(...entries.map(([key, label]) => choice(key, label)));
  select.value = selected;
}

function fillTunnelSelect(select, choices, selected) {
  const current = choices.some(([key]) => key === selected) ? selected : '';
  fillSelect(select, [['', 'All tunnels'], ...choices], current);
  select.disabled = !choices.length;
  return current;
}

export function startDashboard(url) {
  const el = id => document.getElementById(id);
  const groupPicker = el('group');
  const trafficPicker = el('traffic-tunnel');
  const latencyPicker = el('latency-tunnel');
  const target = el('health');
  const history = new Map();
  const cards = new Map();
  let group = new URLSearchParams(location.search).get('group') || 'default';
  let trafficTunnel = '';
  let latencyTunnel = '';
  let live;
  let profiles = new Map();
  let error = '';
  let historyError = '';

  async function request(path, body) {
    const options = {signal: AbortSignal.timeout(5000)};
    if (body) Object.assign(options, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const response = await fetch(url(path), options);
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(detail.error || 'HTTP ' + response.status);
    }
    if (response.status !== 204) return response.json();
  }

  const label = member => member.direct ? 'DIRECT (client)' : (profiles.get(member.profile_id) || member.profile_id) + ' / ' + member.tunnel;

  function render() {
    if (!live) {
      if (error) updateText(el('state'), error);
      return;
    }
    const names = ['default', ...Object.keys(live.groups || {}).sort()];
    if (!names.includes(group)) {
      group = 'default';
      trafficTunnel = latencyTunnel = '';
    }
    fillSelect(groupPicker, names.map(name => [name, displayGroup(name)]), group);
    groupPicker.disabled = names.length < 2;
    const state = groupAt(live, group) || {};
    const entries = state.members || [];
    const detail = live.master_enabled === false ? 'Smart Proxy is off'
      : state.listening ? 'Listening on ' + state.listening : state.enabled ? 'Not listening' : 'Disabled';
    updateText(el('state'), [detail, state.error || live.error, error, historyError].filter(Boolean).join(' · '));
    const summary = [count(state.active ?? 0) + ' active connections',
      count(state.recovered ?? 0) + ' of ' + count(state.failovers ?? 0) + ' failovers recovered'];
    if (state.limits?.auto) summary.push(`Auto limits · ${state.limits.connections} connections · ${state.limits.concurrent_attempts} simultaneous setups · ${state.limits.reason}`);
    if (state.last_selected) summary.push('Last selected ' + label(state.last_selected) +
      (state.selection_reason ? ' (' + readable(state.selection_reason) + ')' : ''));
    if (state.race_preparations) summary.push(count(state.race_backup_wins ?? 0) + ' backup wins in ' +
      count(state.race_preparations) + ' TCP preparations');
    if (state.direct) {
      const {active, udp_active, successes, failures, connect_millis} = state.direct;
      summary.push(`DIRECT (client) · ${active} TCP · ${udp_active ?? 0} UDP · ${successes} successful · ${failures} failed · Setup ${milliseconds(connect_millis)}`);
    }
    if (state.destination_denied || state.routing_indeterminate) summary.push(`${state.destination_denied ?? 0} denied · ${state.routing_indeterminate ?? 0} indeterminate`);
    if (live.asn_database) {
      const db = live.asn_database;
      summary.push(`ASN database ${db.stale ? 'stale' : db.loaded ? 'loaded' : 'unavailable'} · ${db.ranges} ranges · ${db.ipv6 ? 'IPv4/IPv6' : 'IPv4 only when loaded'} · ${state.asn_lookups_succeeded ?? 0} lookups succeeded · ${state.asn_lookups_failed ?? 0} failed`);
    }
    updateText(el('summary'), summary.join(' · '));

    const samples = history.get(group) || [];
    const trafficEntries = trafficEntriesFor(state);
    const chartLabels = new Map(trafficEntries.map(member => [trafficKey(member), label(member)]));
    for (const sample of samples) {
      for (const [key, {member}] of sample.members) {
        if (!chartLabels.has(key)) chartLabels.set(key, label(member));
      }
    }
    const choices = [...chartLabels];
    trafficTunnel = fillTunnelSelect(trafficPicker, choices, trafficTunnel);
    latencyTunnel = fillTunnelSelect(latencyPicker, choices, latencyTunnel);

    const visibleTraffic = trafficTunnel ? trafficEntries.filter(member => trafficKey(member) === trafficTunnel) : trafficEntries;
    const totals = visibleTraffic.reduce((sum, entry) => [sum[0] + (entry.sent ?? 0), sum[1] + (entry.received ?? 0)], [0, 0]);
    const trafficAt = sample => trafficTunnel ? sample.members.get(trafficTunnel)?.traffic : sample;
    updateText(el('traffic-total'), visibleTraffic.length ? bytes(totals[0]) + ' sent · ' + bytes(totals[1]) + ' received' : '');
    renderTrend(el('traffic'), samples, [
      {name: 'Sent', color: 'out', measure: sample => trafficAt(sample)?.sent},
      {name: 'Received', color: 'in', measure: sample => trafficAt(sample)?.received}
    ], rate, 'Waiting for traffic samples.');

    el('latency-comparison').hidden = !!latencyTunnel;
    const outages = sample => [...sample.members].flatMap(([key, {outage}]) =>
      outage && (!latencyTunnel || key === latencyTunnel) ? [chartLabels.get(key) + ' · ' + outage] : []);
    renderTrend(el('latency'), samples, latencySeries(choices, latencyTunnel), milliseconds,
      latencyTunnel ? 'No latency measurements for this tunnel yet.' : 'No setup latency measurements yet.', outages);
    renderTrend(el('activity'), samples, [{name: 'Active connections', color: 'primary', measure: sample => sample.active}],
      count, 'Waiting for an active proxy listener.');
    renderUsage(el('usage'), chartRows(trafficEntries, label, member => member.routed ?? 0), samples.at(-1)?.time);

    el('clear-preferred').disabled = !state.listening;
    const wanted = new Set();
    for (const member of entries) {
      const key = JSON.stringify([group, memberKey(member)]);
      wanted.add(key);
      let row = cards.get(key);
      if (!row) {
        row = statusCard(member => setPreference(member), setPreference);
        cards.set(key, row);
        target.append(row.card);
      }
      row.update(member, label(member), live.master_enabled !== false);
    }
    for (const [key, row] of cards) {
      if (wanted.has(key)) continue;
      if (row.card.contains(document.activeElement)) el('tunnel-status').focus();
      row.card.remove();
      cards.delete(key);
    }
  }

  async function setPreference(member, exclude) {
    const selectedGroup = group;
    const status = el('action-status');
    try {
      await request(apiPath + '/preference', {
        group, member: {profile_id: member.profile_id || '', tunnel: member.tunnel || ''}, exclude
      });
      if (group === selectedGroup) updateText(status, 'Tunnel preference updated.');
    } catch (error) {
      if (group === selectedGroup) updateText(status, error.message);
    }
  }

  async function poll() {
    const selected = group;
    const samples = history.get(selected) || [];
    const after = samples.at(-1)?.time ?? 0;
    const query = new URLSearchParams({group: selected, after});
    const [status, trend] = await Promise.allSettled([
      request(apiPath + '/status'),
      request(apiPath + '/history?' + query)
    ]);
    if (trend.status === 'fulfilled') {
      for (const sample of trend.value) recordSample(samples, sample, sample.time);
      history.set(selected, samples);
    }
    if (group === selected) {
      historyError = trend.status === 'rejected' ? 'Could not load chart history: ' + trend.reason.message : '';
    }
    if (status.status === 'fulfilled') {
      live = status.value;
      for (const name of history.keys()) {
        if (!groupAt(live, name)) history.delete(name);
      }
      error = '';
    } else {
      error = 'Could not refresh live status: ' + status.reason.message;
    }
    render();
    setTimeout(poll, 2000);
  }

  groupPicker.onchange = () => {
    group = groupPicker.value;
    trafficTunnel = latencyTunnel = '';
    historyError = '';
    updateText(el('action-status'), '');
    render();
  };
  trafficPicker.onchange = () => {
    trafficTunnel = trafficPicker.value;
    render();
  };
  latencyPicker.onchange = () => {
    latencyTunnel = latencyPicker.value;
    render();
  };
  el('clear-preferred').onclick = () => setPreference({});
  request('/api/profiles').then(snapshots => {
    profiles = new Map(snapshots.map(({profile}) => [profile.ID, profile.Name]));
    render();
  }).catch(() => {});
  poll();
}

export {latencySeries, nearestSample, recordSample, seriesPath, trendBands};
