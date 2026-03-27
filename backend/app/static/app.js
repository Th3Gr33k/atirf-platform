async function api(path, options = {}) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();

  if (!res.ok) {
    const message = typeof data === 'string' ? data : (data.detail || `Request failed with status ${res.status}`);
    throw new Error(message);
  }

  return data;
}

let selectedIncidentId = null;

function badgeClass(severity) {
  return `badge ${severity || 'low'}`;
}

function renderMetrics(metrics) {
  const container = document.getElementById('metrics');
  container.innerHTML = [
    ['Events', metrics.events],
    ['Alerts', metrics.alerts],
    ['Incidents', metrics.incidents],
    ['Top ATT&CK Techniques', Object.keys(metrics.mitre_counts || {}).length],
    ['Catalog Techniques', metrics.attack_techniques || 0],
    ['Connectors', metrics.connectors || 0]
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

function renderAttackTechniques(techniques) {
  const container = document.getElementById('attackTechniques');
  container.innerHTML = techniques.slice(0, 10).map(t => `
    <div class="list-item">
      <h3>${t.technique_id} · ${t.name}</h3>
      <div class="meta">Tactic: ${t.tactic} · Platform: ${t.platform || 'n/a'}</div>
      <div class="small">Data sources: ${t.data_sources || 'n/a'}</div>
    </div>
  `).join('') || '<div class="small">No ATT&CK techniques seeded yet.</div>';
}

function renderRansomwarePatterns(patterns) {
  const container = document.getElementById('ransomwarePatterns');
  container.innerHTML = patterns.map(p => `
    <div class="list-item">
      <h3>${p.family}</h3>
      <div class="meta">${p.pattern_type}</div>
      <div class="small">Likely ATT&CK: ${(p.likely_techniques || []).join(', ')}</div>
      <p>${p.operator_notes || ''}</p>
    </div>
  `).join('') || '<div class="small">No ransomware pattern data available.</div>';
}

function renderRansomwareLive(feed) {
  const status = document.getElementById('ransomwareLiveStatus');
  const groups = document.getElementById('ransomwareLiveGroups');
  const victims = document.getElementById('ransomwareLiveVictims');

  if (feed.status !== 'ok') {
    status.textContent = feed.message || 'Live ransomware feed unavailable.';
    status.className = feed.status === 'error' ? 'detail error' : 'detail';
    groups.innerHTML = '<div class="small">No live ransomware group activity available.</div>';
    victims.innerHTML = '<div class="small">No live victim feed available.</div>';
    return;
  }

  status.textContent = `Provider: ${feed.provider} · Groups tracked: ${feed.group_count}`;
  status.className = 'detail';

  groups.innerHTML = (feed.top_groups || []).map(item => `
    <div class="kv">
      <span>${item.group}</span>
      <strong>${item.count}</strong>
    </div>
  `).join('') || '<div class="small">No recent group activity returned.</div>';

  victims.innerHTML = (feed.recent_victims || []).map(item => `
    <div class="list-item">
      <h3>${item.post_title || item.name || item.website || 'Unnamed victim record'}</h3>
      <div class="meta">${item.group || 'unknown group'} · ${item.country || 'unknown country'} · ${item.discovered || item.date || 'unknown date'}</div>
      <div class="small">${item.activity || item.sector || item.description || 'No additional victim context returned.'}</div>
    </div>
  `).join('') || '<div class="small">No recent victims returned.</div>';
}

function renderSourceCatalog(sources) {
  const container = document.getElementById('sourceCatalog');
  container.innerHTML = sources.map(source => `
    <div class="list-item">
      <h3>${source.name}</h3>
      <div class="meta">${source.kind} · ${source.source_type} · Trust: ${source.trust_level}</div>
      <div class="small">Mode: ${source.ingestion_mode} · URL: ${source.base_url}</div>
      <p>${source.notes || ''}</p>
    </div>
  `).join('');
}

function renderConnectors(connectors) {
  const container = document.getElementById('connectors');
  container.innerHTML = connectors.map(connector => `
    <div class="list-item">
      <h3>${connector.name}</h3>
      <div class="meta">${connector.source_type} · ${connector.auth_type} · ${connector.enabled ? 'enabled' : 'disabled'}</div>
      <div class="small">${connector.base_url}</div>
      <div class="small">Credential hint: ${connector.credential_hint || 'n/a'}</div>
      <p>${connector.notes || ''}</p>
    </div>
  `).join('') || '<div class="small">No connectors added yet.</div>';
}

function renderHypotheses(incidents) {
  const container = document.getElementById('hypotheses');
  container.innerHTML = incidents.map(item => `
    <div class="list-item">
      <h3>${item.incident_title}</h3>
      <div class="small">Observed ATT&CK: ${(item.observed_techniques || []).join(', ') || 'none yet'}</div>
      ${(item.top_hypotheses || []).map(h => `
        <div class="kv">
          <span>${h.family} (${Math.round(h.confidence)}%)</span>
          <strong>${(h.matched_techniques || []).join(', ') || 'no match'}</strong>
        </div>
      `).join('')}
    </div>
  `).join('') || '<div class="small">No ranked attack-pattern hypotheses yet.</div>';
}

function renderCopilot(result) {
  const container = document.getElementById('copilotOutput');

  if (result.status === 'ok') {
    container.innerHTML = `
      <div class="list-item">
        <div class="meta">Provider: ${result.provider} · Model: ${result.model}</div>
        <pre class="copilot-text">${result.analysis}</pre>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="list-item">
      <div class="meta">Provider: ${result.provider || 'local'} · Model: ${result.model || 'n/a'} · Status: ${result.status}</div>
      <p>${result.message || 'Copilot is unavailable.'}</p>
      <div class="small">Observed ATT&CK: ${(result.context?.observed_techniques || []).join(', ') || 'none yet'}</div>
    </div>
  `;
}

async function loadIncident(id) {
  selectedIncidentId = id;
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

function setStatus(message, isError = false) {
  const status = document.getElementById('statusMessage');
  status.textContent = message;
  status.className = isError ? 'detail error' : 'detail';
}

async function refreshAll() {
  setStatus('Loading platform data...');

  try {
    const [metrics, alerts, incidents, events, techniques, catalog, patterns, connectors, hypotheses, liveFeed] = await Promise.all([
      api('/api/metrics'),
      api('/api/alerts'),
      api('/api/incidents'),
      api('/api/events'),
      api('/api/attack/techniques'),
      api('/api/intel/source-catalog'),
      api('/api/ransomware/patterns'),
      api('/api/connectors'),
      api('/api/hypotheses'),
      api('/api/ransomware/live')
    ]);

    renderMetrics(metrics);
    renderAlerts(alerts);
    renderIncidents(incidents);
    renderEvents(events);
    renderAttackTechniques(techniques);
    renderSourceCatalog(catalog.sources || []);
    renderRansomwarePatterns(patterns.patterns || []);
    renderRansomwareLive(liveFeed);
    renderConnectors(connectors);
    renderHypotheses(hypotheses.incidents || []);

    if (incidents.length) {
      await loadIncident(incidents[0].id);
    } else {
      selectedIncidentId = null;
      document.getElementById('incidentDetail').innerHTML = 'Select an incident after loading demo data.';
      document.getElementById('copilotOutput').innerHTML = 'Select or load an incident, then generate a grounded local-AI analysis.';
    }

    setStatus(`Platform ready. Events: ${metrics.events} · Alerts: ${metrics.alerts} · Incidents: ${metrics.incidents}`);
  } catch (error) {
    setStatus(`Platform failed to load: ${error.message}`, true);
    document.getElementById('metrics').innerHTML = '';
    document.getElementById('alerts').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('incidents').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('events').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('mitre').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('severity').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('incidentDetail').innerHTML = 'Check the status panel for the API error.';
    document.getElementById('hypotheses').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('copilotOutput').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('ransomwareLiveStatus').textContent = 'No live ransomware feed available.';
    document.getElementById('ransomwareLiveGroups').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('ransomwareLiveVictims').innerHTML = '<div class="small">No data available.</div>';
  }
}

async function resetDemo() {
  try {
    await api('/api/demo/reset', { method: 'POST' });
    await refreshAll();
  } catch (error) {
    setStatus(`Reset failed: ${error.message}`, true);
  }
}

async function loadDemo(dataset = 'demo_events.json') {
  try {
    await api(`/api/demo/load?dataset=${encodeURIComponent(dataset)}`, { method: 'POST' });
    await refreshAll();
  } catch (error) {
    setStatus(`Dataset load failed: ${error.message}`, true);
  }
}

async function seedAttackCatalog() {
  try {
    await api('/api/attack/seed', { method: 'POST' });
    await refreshAll();
  } catch (error) {
    setStatus(`Catalog seed failed: ${error.message}`, true);
  }
}

async function createConnector(event) {
  event.preventDefault();

  const payload = {
    name: document.getElementById('connectorName').value.trim(),
    source_type: document.getElementById('connectorType').value.trim(),
    base_url: document.getElementById('connectorUrl').value.trim(),
    auth_type: document.getElementById('connectorAuth').value.trim() || 'none',
    credential_hint: document.getElementById('connectorHint').value.trim() || null,
    notes: document.getElementById('connectorNotes').value.trim() || null
  };

  try {
    await api('/api/connectors', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    document.getElementById('connectorForm').reset();
    await refreshAll();
  } catch (error) {
    setStatus(`Connector creation failed: ${error.message}`, true);
  }
}

async function runCopilot() {
  if (!selectedIncidentId) {
    setStatus('No incident selected for copilot analysis.', true);
    return;
  }

  try {
    setStatus('Generating grounded local-AI incident analysis...');
    const result = await api(`/api/copilot/incident/${selectedIncidentId}`);
    renderCopilot(result);
    setStatus(`Copilot request completed with status: ${result.status}`);
  } catch (error) {
    setStatus(`Copilot request failed: ${error.message}`, true);
  }
}

async function refreshRansomwareLive() {
  try {
    setStatus('Refreshing live ransomware feed...');
    const liveFeed = await api('/api/ransomware/live');
    renderRansomwareLive(liveFeed);
    setStatus(`Ransomware feed refresh completed with status: ${liveFeed.status}`);
  } catch (error) {
    setStatus(`Ransomware feed refresh failed: ${error.message}`, true);
  }
}

document.getElementById('refreshBtn').addEventListener('click', refreshAll);
document.getElementById('resetBtn').addEventListener('click', resetDemo);
document.getElementById('loadBtn').addEventListener('click', () => loadDemo('demo_events.json'));
document.getElementById('loadShowcaseBtn').addEventListener('click', () => loadDemo('open_source_showcase.json'));
document.getElementById('seedAttackBtn').addEventListener('click', seedAttackCatalog);
document.getElementById('connectorForm').addEventListener('submit', createConnector);
document.getElementById('copilotBtn').addEventListener('click', runCopilot);
document.getElementById('refreshRansomwareBtn').addEventListener('click', refreshRansomwareLive);
document.getElementById('heroSeedBtn').addEventListener('click', seedAttackCatalog);
document.getElementById('heroShowcaseBtn').addEventListener('click', () => loadDemo('open_source_showcase.json'));
document.getElementById('heroCopilotBtn').addEventListener('click', runCopilot);

refreshAll();
