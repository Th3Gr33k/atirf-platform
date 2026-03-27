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
let currentNewsFeed = null;

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
    ['Connectors', metrics.connectors || 0],
    ['Synced Connectors', metrics.synced_connectors || 0]
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

function renderKev(feed) {
  const status = document.getElementById('kevStatus');
  const entries = document.getElementById('kevEntries');

  if (feed.status !== 'ok') {
    status.textContent = feed.message || 'CISA KEV unavailable.';
    status.className = feed.status === 'error' ? 'detail error' : 'detail';
    entries.innerHTML = '<div class="small">No KEV entries available.</div>';
    return;
  }

  status.textContent = `Provider: ${feed.provider} · Catalog version: ${feed.catalog_version || 'unknown'} · Entries: ${feed.count} · Ransomware-tagged: ${feed.known_ransomware_count}`;
  status.className = 'detail';
  entries.innerHTML = (feed.recent_entries || []).map(item => `
    <div class="list-item">
      <h3>${item.cveID || 'unknown CVE'}</h3>
      <div class="meta">${item.vendorProject || 'unknown vendor'} · ${item.product || 'unknown product'}</div>
      <div class="small">Ransomware campaign use: ${item.knownRansomwareCampaignUse || 'unknown'} · Due date: ${item.dueDate || 'n/a'}</div>
      <p>${item.shortDescription || ''}</p>
    </div>
  `).join('') || '<div class="small">No KEV entries returned.</div>';
}

function renderNews(feed) {
  currentNewsFeed = feed;
  const status = document.getElementById('newsStatus');
  const items = document.getElementById('newsItems');

  if (feed.status !== 'ok') {
    status.textContent = feed.message || 'Cybersecurity news unavailable.';
    status.className = 'detail error';
    items.innerHTML = '<div class="small">No cybersecurity news available.</div>';
    return;
  }

  const healthyFeeds = (feed.feeds || []).filter(source => source.status === 'ok').length;
  status.textContent = `Provider: ${feed.provider} · Healthy feeds: ${healthyFeeds}/${(feed.feeds || []).length}`;
  status.className = 'detail';
  const feedHealth = (feed.feeds || []).map(source => `
    <div class="kv">
      <span>${source.name}</span>
      <strong>${source.status}</strong>
    </div>
  `).join('') || '<div class="small">No source health available.</div>';

  const trustFilter = document.getElementById('newsTrustFilter')?.value || 'all';
  const filteredItems = (feed.top_items || []).filter(item => trustFilter === 'all' || item.trust_level === trustFilter);
  const topItems = filteredItems.map(item => `
    <div class="list-item">
      <h3><a class="inline" href="${item.link || '#'}" target="_blank" rel="noreferrer">${item.title || 'Untitled news item'}</a></h3>
      <div class="meta">${item.source || 'unknown source'} · ${item.published || 'unknown date'} · Trust: ${item.trust_level || 'community'}</div>
      <div class="inline-actions">
        <button type="button" onclick="pinNewsToIncident('note', '${escapeInline(item.title)}', '${escapeInline(item.link)}', '${escapeInline(item.source)}', '${escapeInline(item.published)}', '${escapeInline(item.trust_level)}')">Pin as Note</button>
        <button type="button" onclick="pinNewsToIncident('evidence', '${escapeInline(item.title)}', '${escapeInline(item.link)}', '${escapeInline(item.source)}', '${escapeInline(item.published)}', '${escapeInline(item.trust_level)}')">Pin as Evidence</button>
      </div>
    </div>
  `).join('') || '<div class="small">No news items returned.</div>';

  items.innerHTML = `
    <strong>Feed Health</strong>
    ${feedHealth}
    <strong>Latest Stories</strong>
    ${topItems}
  `;
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
      <div class="small">Last sync: ${connector.last_sync_status || 'never'}${connector.last_sync_at ? ` · ${connector.last_sync_at}` : ''}</div>
      <p>${connector.notes || ''}</p>
      <div class="small">${connector.last_sync_message || ''}</div>
    </div>
  `).join('') || '<div class="small">No connectors added yet.</div>';
}

function renderConnectorJobs(jobs) {
  const container = document.getElementById('connectorJobsPanel');
  container.innerHTML = (jobs || []).map(job => `
    <div class="list-item">
      <h3>Connector #${job.connector_id} · ${job.job_type}</h3>
      <div class="meta">${job.status} · created ${job.created_at || 'unknown time'}</div>
      <div class="small">Started: ${job.started_at || 'n/a'} · Finished: ${job.finished_at || 'n/a'}</div>
      <p>${job.message || ''}</p>
    </div>
  `).join('') || 'Run connector sync to create execution history.';
}

function renderNewsSources(sources) {
  const container = document.getElementById('newsSourcesPanel');
  container.innerHTML = (sources || []).map(source => `
    <div class="list-item">
      <h3>${source.name}</h3>
      <div class="meta">${source.trust_level} · ${source.enabled ? 'enabled' : 'disabled'}</div>
      <div class="small">${source.url}</div>
      <div class="inline-actions">
        <button type="button" onclick="toggleNewsSource(${source.id}, ${source.enabled ? 'false' : 'true'}, '${escapeInline(source.name)}', '${escapeInline(source.url)}', '${escapeInline(source.trust_level)}')">${source.enabled ? 'Disable' : 'Enable'}</button>
        <button type="button" onclick="removeNewsSource(${source.id})">Delete</button>
      </div>
    </div>
  `).join('') || 'Seed or add news feeds to customize cyber-news monitoring.';
}

function escapeInline(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
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

function renderPlaybook(result) {
  const container = document.getElementById('playbookPanel');

  if (!result || result.status !== 'ok' || !result.playbook) {
    container.innerHTML = 'No playbook available for the selected incident.';
    return;
  }

  const playbook = result.playbook;
  container.innerHTML = `
    <div class="list-item">
      <h3>${result.incident_type}</h3>
      <div class="meta">NIST alignment: ${playbook.nist_alignment || 'n/a'}</div>
      <strong>Priority questions</strong>
      <ul>${(playbook.priority_questions || []).map(item => `<li>${item}</li>`).join('')}</ul>
      <strong>Decision gates</strong>
      <ul>${(playbook.decision_gates || []).map(item => `<li>${item}</li>`).join('')}</ul>
      <strong>Immediate actions</strong>
      <ul>${(playbook.immediate_actions || []).map(item => `<li>${item}</li>`).join('')}</ul>
    </div>
  `;
}

function renderDecision(result) {
  const container = document.getElementById('decisionOutput');

  if (!result || result.status !== 'ok') {
    container.innerHTML = 'Decision helper is unavailable.';
    return;
  }

  container.innerHTML = `
    <div class="list-item">
      <h3>${result.recommended_decision}</h3>
      <div class="meta">Incident type: ${result.incident_type} · NIST phase: ${result.nistr_phase}</div>
      <strong>Decision rationale</strong>
      <ul>${(result.decision_rationale || []).map(item => `<li>${item}</li>`).join('')}</ul>
      <strong>Suggested actions</strong>
      <ul>${(result.suggested_actions || []).map(item => `<li>${item}</li>`).join('')}</ul>
    </div>
  `;
}

function renderNotes(notes) {
  const container = document.getElementById('notesPanel');
  container.innerHTML = (notes || []).map(note => `
    <div class="list-item">
      <h3>${note.author || 'unknown analyst'}</h3>
      <div class="meta">${note.created_at || 'unknown time'}</div>
      <p>${note.body || ''}</p>
    </div>
  `).join('') || 'Select an incident to review or add notes.';
}

function renderTasksAndEvidence(tasks, evidence) {
  const container = document.getElementById('tasksPanel');
  const taskHtml = (tasks || []).map(task => `
    <div class="list-item">
      <h3>${task.title}</h3>
      <div class="meta">${task.status} · ${task.owner || 'unassigned'}</div>
    </div>
  `).join('') || '<div class="small">No tasks yet.</div>';

  const evidenceHtml = (evidence || []).map(item => `
    <div class="list-item">
      <h3>${item.evidence_type}</h3>
      <div class="meta">${item.source || 'unknown source'}</div>
      <p>${item.description || ''}</p>
    </div>
  `).join('') || '<div class="small">No evidence records yet.</div>';

  container.innerHTML = `
    <strong>Tasks</strong>
    ${taskHtml}
    <strong>Evidence</strong>
    ${evidenceHtml}
  `;
}

async function loadIncident(id) {
  selectedIncidentId = id;
  const [data, playbook] = await Promise.all([
    api(`/api/incidents/${id}`),
    api(`/api/playbooks/incident/${id}`)
  ]);
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
  renderPlaybook(playbook);
  document.getElementById('decisionIncidentType').value = playbook.incident_type || '';
  document.getElementById('workflowStatus').value = data.incident.status || 'open';
  document.getElementById('workflowPhase').value = data.incident.nist_phase || 'Detection and Analysis';
  document.getElementById('workflowOwner').value = data.incident.owner || '';
  document.getElementById('workflowDisposition').value = data.incident.disposition || '';
  document.getElementById('workflowDecision').value = data.incident.last_decision || '';
  document.getElementById('workflowSummary').value = data.incident.response_summary || '';
  renderNotes(data.notes || []);
  renderTasksAndEvidence(data.tasks || [], data.evidence || []);
  document.getElementById('decisionOutput').innerHTML = 'Incident selected. Adjust the decision inputs if needed, then click Evaluate Decision.';
  document.getElementById('workflowOutput').innerHTML = 'Incident selected. Update workflow state and save changes.';
}

function setStatus(message, isError = false) {
  const status = document.getElementById('statusMessage');
  status.textContent = message;
  status.className = isError ? 'detail error' : 'detail';
}

async function refreshAll() {
  setStatus('Loading platform data...');

  try {
    const [metrics, alerts, incidents, events, techniques, catalog, patterns, connectors, jobs, newsSources, hypotheses, liveFeed, kevFeed, newsFeed] = await Promise.all([
      api('/api/metrics'),
      api('/api/alerts'),
      api('/api/incidents'),
      api('/api/events'),
      api('/api/attack/techniques'),
      api('/api/intel/source-catalog'),
      api('/api/ransomware/patterns'),
      api('/api/connectors'),
      api('/api/connectors/jobs'),
      api('/api/news/sources'),
      api('/api/hypotheses'),
      api('/api/ransomware/live'),
      api('/api/kev/live'),
      api('/api/news/live')
    ]);

    renderMetrics(metrics);
    renderAlerts(alerts);
    renderIncidents(incidents);
    renderEvents(events);
    renderAttackTechniques(techniques);
    renderSourceCatalog(catalog.sources || []);
    renderRansomwarePatterns(patterns.patterns || []);
    renderRansomwareLive(liveFeed);
    renderKev(kevFeed);
    renderNews(newsFeed);
    renderConnectors(connectors);
    renderConnectorJobs(jobs);
    renderNewsSources(newsSources);
    renderHypotheses(hypotheses.incidents || []);

    if (incidents.length) {
      await loadIncident(incidents[0].id);
    } else {
      selectedIncidentId = null;
      document.getElementById('incidentDetail').innerHTML = 'Select an incident after loading demo data.';
      document.getElementById('copilotOutput').innerHTML = 'Select or load an incident, then generate a grounded local-AI analysis.';
      document.getElementById('playbookPanel').innerHTML = 'Select an incident to view its inferred playbook.';
      document.getElementById('decisionOutput').innerHTML = 'Select an incident and evaluate decision support.';
      document.getElementById('workflowOutput').innerHTML = 'Select an incident and save workflow changes.';
      document.getElementById('notesPanel').innerHTML = 'Select an incident to review or add notes.';
      document.getElementById('tasksPanel').innerHTML = 'Select an incident to review tasks and evidence.';
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
    document.getElementById('kevStatus').textContent = 'No KEV feed available.';
    document.getElementById('kevEntries').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('newsStatus').textContent = 'No cyber news available.';
    document.getElementById('newsItems').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('playbookPanel').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('decisionOutput').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('workflowOutput').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('importOutput').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('notesPanel').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('tasksPanel').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('connectorJobsPanel').innerHTML = '<div class="small">No data available.</div>';
    document.getElementById('newsSourcesPanel').innerHTML = '<div class="small">No data available.</div>';
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

async function syncConnectors() {
  try {
    setStatus('Running local connector sync...');
    const result = await api('/api/connectors/sync', { method: 'POST' });
    await refreshAll();
    setStatus(`Connector sync completed. Synced ${result.synced}/${result.connectors} connectors.`);
  } catch (error) {
    setStatus(`Connector sync failed: ${error.message}`, true);
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

async function refreshKev() {
  try {
    setStatus('Refreshing CISA KEV feed...');
    const feed = await api('/api/kev/live');
    renderKev(feed);
    setStatus(`KEV refresh completed with status: ${feed.status}`);
  } catch (error) {
    setStatus(`KEV refresh failed: ${error.message}`, true);
  }
}

async function refreshNews() {
  try {
    setStatus('Refreshing cybersecurity news...');
    const feed = await api('/api/news/live');
    renderNews(feed);
    setStatus(`News refresh completed with status: ${feed.status}`);
  } catch (error) {
    setStatus(`News refresh failed: ${error.message}`, true);
  }
}

async function evaluateDecision(event) {
  if (event) {
    event.preventDefault();
  }

  if (!selectedIncidentId) {
    setStatus('No incident selected for decision support.', true);
    return;
  }

  const payload = {
    incident_type: document.getElementById('decisionIncidentType').value.trim() || null,
    confidence: document.getElementById('decisionConfidence').value,
    business_criticality: document.getElementById('decisionBusinessCriticality').value,
    privileged_identity_exposure: document.getElementById('decisionPrivileged').checked,
    lateral_movement_evidence: document.getElementById('decisionLateral').checked,
    exfiltration_evidence: document.getElementById('decisionExfil').checked,
    ransomware_impact_evidence: document.getElementById('decisionRansomware').checked,
    external_exposure: document.getElementById('decisionExternal').checked
  };

  try {
    setStatus('Evaluating incident decision support...');
    const result = await api(`/api/playbooks/incident/${selectedIncidentId}/decision`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    renderDecision(result);
    setStatus(`Decision helper completed with recommendation: ${result.recommended_decision}`);
  } catch (error) {
    setStatus(`Decision helper failed: ${error.message}`, true);
  }
}

async function saveWorkflow(event) {
  if (event) {
    event.preventDefault();
  }

  if (!selectedIncidentId) {
    setStatus('No incident selected for workflow update.', true);
    return;
  }

  const payload = {
    status: document.getElementById('workflowStatus').value,
    nist_phase: document.getElementById('workflowPhase').value,
    owner: document.getElementById('workflowOwner').value.trim() || null,
    disposition: document.getElementById('workflowDisposition').value.trim() || null,
    last_decision: document.getElementById('workflowDecision').value.trim() || null,
    response_summary: document.getElementById('workflowSummary').value.trim() || null
  };

  try {
    setStatus('Saving case workflow...');
    const result = await api(`/api/incidents/${selectedIncidentId}/workflow`, {
      method: 'PATCH',
      body: JSON.stringify(payload)
    });
    document.getElementById('workflowOutput').innerHTML = `
      <div class="list-item">
        <h3>Workflow saved</h3>
        <div class="meta">Status: ${result.status} · NIST phase: ${result.nist_phase}</div>
        <div class="small">Owner: ${result.owner || 'unassigned'} · Disposition: ${result.disposition || 'n/a'}</div>
        <p>${result.response_summary || 'No response summary provided.'}</p>
      </div>
    `;
    await refreshAll();
    setStatus('Case workflow saved.');
  } catch (error) {
    setStatus(`Workflow save failed: ${error.message}`, true);
  }
}

async function importLocalFile() {
  const fileInput = document.getElementById('importFile');
  const file = fileInput.files[0];

  if (!file) {
    setStatus('Choose a JSON file to import.', true);
    return;
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    setStatus(`Importing ${file.name}...`);
    const res = await fetch('/api/imports/events-file', { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || `Import failed with status ${res.status}`);
    }
    document.getElementById('importOutput').innerHTML = `
      <div class="list-item">
        <h3>Import completed</h3>
        <div class="meta">File: ${data.filename} · Records imported: ${data.count}</div>
      </div>
    `;
    fileInput.value = '';
    await refreshAll();
    setStatus(`Imported ${data.count} event records from ${data.filename}.`);
  } catch (error) {
    setStatus(`Local import failed: ${error.message}`, true);
  }
}

async function addNote(event) {
  event.preventDefault();
  if (!selectedIncidentId) {
    setStatus('No incident selected for adding a note.', true);
    return;
  }

  const payload = {
    author: document.getElementById('noteAuthor').value.trim() || null,
    body: document.getElementById('noteBody').value.trim()
  };
  if (!payload.body) {
    setStatus('Note body is required.', true);
    return;
  }

  try {
    await api(`/api/incidents/${selectedIncidentId}/notes`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    document.getElementById('noteForm').reset();
    await loadIncident(selectedIncidentId);
    setStatus('Analyst note added.');
  } catch (error) {
    setStatus(`Add note failed: ${error.message}`, true);
  }
}

async function addTask(event) {
  event.preventDefault();
  if (!selectedIncidentId) {
    setStatus('No incident selected for adding a task.', true);
    return;
  }

  const payload = {
    title: document.getElementById('taskTitle').value.trim(),
    owner: document.getElementById('taskOwner').value.trim() || null,
    status: document.getElementById('taskStatus').value
  };
  if (!payload.title) {
    setStatus('Task title is required.', true);
    return;
  }

  try {
    await api(`/api/incidents/${selectedIncidentId}/tasks`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    document.getElementById('taskForm').reset();
    await loadIncident(selectedIncidentId);
    setStatus('Incident task added.');
  } catch (error) {
    setStatus(`Add task failed: ${error.message}`, true);
  }
}

async function addEvidence(event) {
  event.preventDefault();
  if (!selectedIncidentId) {
    setStatus('No incident selected for adding evidence.', true);
    return;
  }

  const payload = {
    evidence_type: document.getElementById('evidenceType').value.trim(),
    source: document.getElementById('evidenceSource').value.trim() || null,
    description: document.getElementById('evidenceDescription').value.trim()
  };
  if (!payload.evidence_type || !payload.description) {
    setStatus('Evidence type and description are required.', true);
    return;
  }

  try {
    await api(`/api/incidents/${selectedIncidentId}/evidence`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    document.getElementById('evidenceForm').reset();
    await loadIncident(selectedIncidentId);
    setStatus('Incident evidence added.');
  } catch (error) {
    setStatus(`Add evidence failed: ${error.message}`, true);
  }
}

async function seedNewsSources() {
  try {
    setStatus('Seeding default news sources...');
    await api('/api/news/sources/seed', { method: 'POST' });
    await refreshAll();
    setStatus('Default news sources seeded.');
  } catch (error) {
    setStatus(`Seed news sources failed: ${error.message}`, true);
  }
}

async function addNewsSource(event) {
  event.preventDefault();
  const payload = {
    name: document.getElementById('newsSourceName').value.trim(),
    url: document.getElementById('newsSourceUrl').value.trim(),
    trust_level: document.getElementById('newsSourceTrust').value,
    enabled: true
  };

  if (!payload.name || !payload.url) {
    setStatus('News source name and URL are required.', true);
    return;
  }

  try {
    await api('/api/news/sources', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    document.getElementById('newsSourceForm').reset();
    await refreshAll();
    setStatus('News source added.');
  } catch (error) {
    setStatus(`Add news source failed: ${error.message}`, true);
  }
}

async function pinNewsToIncident(kind, title, link, source, published, trustLevel) {
  if (!selectedIncidentId) {
    setStatus('Select an incident before pinning a news item.', true);
    return;
  }

  try {
    if (kind === 'note') {
      await api(`/api/incidents/${selectedIncidentId}/notes`, {
        method: 'POST',
        body: JSON.stringify({
          author: 'ATIRF News Feed',
          body: `Pinned news item: ${title}\nSource: ${source}\nPublished: ${published}\nTrust: ${trustLevel}\nLink: ${link}`
        })
      });
    } else {
      await api(`/api/incidents/${selectedIncidentId}/evidence`, {
        method: 'POST',
        body: JSON.stringify({
          evidence_type: 'news',
          source,
          description: `Pinned news item: ${title}\nPublished: ${published}\nTrust: ${trustLevel}\nLink: ${link}`
        })
      });
    }

    await loadIncident(selectedIncidentId);
    setStatus(`News item pinned to incident as ${kind}.`);
  } catch (error) {
    setStatus(`Pin news item failed: ${error.message}`, true);
  }
}

function applyNewsFilter() {
  if (currentNewsFeed) {
    renderNews(currentNewsFeed);
  }
}

async function toggleNewsSource(id, enabled, name, url, trustLevel) {
  try {
    await api(`/api/news/sources/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name,
        url,
        trust_level: trustLevel,
        enabled
      })
    });
    await refreshAll();
    setStatus(`News source ${enabled ? 'enabled' : 'disabled'}.`);
  } catch (error) {
    setStatus(`Update news source failed: ${error.message}`, true);
  }
}

async function removeNewsSource(id) {
  try {
    await api(`/api/news/sources/${id}`, { method: 'DELETE' });
    await refreshAll();
    setStatus('News source deleted.');
  } catch (error) {
    setStatus(`Delete news source failed: ${error.message}`, true);
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
document.getElementById('refreshKevBtn').addEventListener('click', refreshKev);
document.getElementById('refreshNewsBtn').addEventListener('click', refreshNews);
document.getElementById('decisionBtn').addEventListener('click', evaluateDecision);
document.getElementById('decisionForm').addEventListener('submit', evaluateDecision);
document.getElementById('saveWorkflowBtn').addEventListener('click', saveWorkflow);
document.getElementById('workflowForm').addEventListener('submit', saveWorkflow);
document.getElementById('syncConnectorsBtn').addEventListener('click', syncConnectors);
document.getElementById('importFileBtn').addEventListener('click', importLocalFile);
document.getElementById('noteForm').addEventListener('submit', addNote);
document.getElementById('taskForm').addEventListener('submit', addTask);
document.getElementById('evidenceForm').addEventListener('submit', addEvidence);
document.getElementById('seedNewsBtn').addEventListener('click', seedNewsSources);
document.getElementById('newsSourceForm').addEventListener('submit', addNewsSource);
document.getElementById('newsTrustFilter').addEventListener('change', applyNewsFilter);

refreshAll();
