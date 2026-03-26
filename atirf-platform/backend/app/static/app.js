async function api(path, options = {}) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  return res.json();
}

function badgeClass(severity) {
  return `badge ${severity || 'low'}`;
}

function renderMetrics(metrics) {
  const container = document.getElementById('metrics');
  container.innerHTML = [
    ['Events', metrics.events],
    ['Alerts', metrics.alerts],
    ['Incidents', metrics.incidents],
    ['Top ATT&CK Techniques', Object.keys(metrics.mitre_counts || {}).length]
  ].map(([label, value]) => `
    <div class="metric">
      <div class="label">${label}</div>
      <div class="value">${value}</div>
    </div>
  `).join('');

  const severity = document.getElementById('severity');
  severity.innerHTML = Object.entries(metrics.severity_breakdown || {}).map(([k,v]) => `
    <div class="kv"><span><span class="${badgeClass(k)}">${k}</span></span><strong>${v}</strong></div>
  `).join('');

  const mitre = document.getElementById('mitre');
  mitre.innerHTML = Object.entries(metrics.mitre_counts || {}).map(([k,v]) => `
    <div class="kv"><span>${k}</span><strong>${v}</strong></div>
  `).join('') || '<div class="small">No ATT&CK techniques mapped yet.</div>';
}

function renderAlerts(alerts) {
  const container = document.getElementById('alerts');
  container.innerHTML = alerts.map(a => `
    <div class="list-item">
      <h3>${a.title}</h3>
      <div class="meta"><span class="${badgeClass(a.severity)}">${a.severity}</span> Risk score: ${Math.round(a.risk_score)} · Technique: ${a.mitre_technique || 'n/a'}</div>
      <p>${a.rationale || ''}</p>
      <div class="small">Recommended actions: ${a.recommended_actions || 'n/a'}</div>
    </div>
  `).join('') || '<div class="small">No alerts loaded.</div>';
}

function renderEvents(events) {
  const container = document.getElementById('events');
  container.innerHTML = events.slice(0, 8).map(e => `
    <div class="list-item">
      <h3>${e.event_type} on ${e.hostname}</h3>
      <div class="meta">${e.timestamp} · ${e.event_source} · ${e.user || 'unknown user'}</div>
      <div class="small">Process: ${e.process_name || 'n/a'} · Parent: ${e.parent_process || 'n/a'} · Domain: ${e.domain || 'n/a'}</div>
    </div>
  `).join('') || '<div class="small">No events loaded.</div>';
}

function renderIncidents(incidents) {
  const container = document.getElementById('incidents');
  container.innerHTML = incidents.map(i => `
    <div class="list-item incident-item" data-id="${i.id}">
      <h3><a href="#" class="inline" onclick="loadIncident(${i.id}); return false;">${i.title}</a></h3>
      <div class="meta"><span class="${badgeClass(i.severity)}">${i.severity}</span> Risk score: ${Math.round(i.risk_score)} · Host: ${i.hostname || 'n/a'} · User: ${i.user || 'n/a'}</div>
      <div class="small">Status: ${i.status}</div>
    </div>
  `).join('') || '<div class="small">No incidents loaded.</div>';
}

async function loadIncident(id) {
  const data = await api(`/api/incidents/${id}`);
  const detail = document.getElementById('incidentDetail');
  const alertList = (data.alerts || []).map(a => `<li>${a.title} (${a.severity}, score ${Math.round(a.risk_score)})</li>`).join('');
  detail.innerHTML = `
    <div class="list-item">
      <h3>${data.incident.title}</h3>
      <div class="meta"><span class="${badgeClass(data.incident.severity)}">${data.incident.severity}</span> Risk score: ${Math.round(data.incident.risk_score)}</div>
      <p>${data.incident.summary || ''}</p>
      <strong>Linked alerts</strong>
      <ul>${alertList}</ul>
    </div>
  `;
}

async function refreshAll() {
  const [metrics, alerts, incidents, events] = await Promise.all([
    api('/api/metrics'),
    api('/api/alerts'),
    api('/api/incidents'),
    api('/api/events')
  ]);

  renderMetrics(metrics);
  renderAlerts(alerts);
  renderIncidents(incidents);
  renderEvents(events);

  if (incidents.length) {
    await loadIncident(incidents[0].id);
  }
}

async function resetDemo() {
  await api('/api/demo/reset', { method: 'POST' });
  await refreshAll();
}

async function loadDemo() {
  await api('/api/demo/load', { method: 'POST' });
  await refreshAll();
}

document.getElementById('refreshBtn').addEventListener('click', refreshAll);
document.getElementById('resetBtn').addEventListener('click', resetDemo);
document.getElementById('loadBtn').addEventListener('click', loadDemo);

refreshAll();
