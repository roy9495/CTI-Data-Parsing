// App Initialization & State
let activeView = 'dashboard';
let charts = {};
let visNetwork = null;
let visNodes = null;
let visEdges = null;
let currentDetailObject = null;
let activeConnectorsPollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    // Nav Click Handling
    const navItems = document.querySelectorAll('.nav-menu a');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.getAttribute('data-view');
            switchView(view);
        });
    });

    // Handle initial hash routing
    if (window.location.hash) {
        const view = window.location.hash.substring(1);
        if (['dashboard', 'indicators', 'threats', 'graph', 'connectors'].includes(view)) {
            switchView(view);
        }
    } else {
        switchView('dashboard');
    }

    // Modal Ingest handlers
    document.getElementById('btn-quick-ingest').addEventListener('click', showIngestModal);
    document.getElementById('btn-close-modal').addEventListener('click', hideIngestModal);
    document.getElementById('btn-cancel-ingest').addEventListener('click', hideIngestModal);
    document.getElementById('btn-submit-ingest').addEventListener('click', handleStixIngest);

    // Drawer handlers
    document.getElementById('btn-close-drawer').addEventListener('click', closeStixDrawer);
    document.getElementById('stix-drawer-overlay').addEventListener('click', closeStixDrawer);
    document.getElementById('btn-view-raw-stix').addEventListener('click', () => {
        if (currentDetailObject) {
            openStixDrawer(currentDetailObject);
        }
    });

    // Drawer Tabs
    const drawerTabBtns = document.querySelectorAll('.drawer-tab-btn');
    drawerTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            drawerTabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.drawer-tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            const contentId = btn.getAttribute('data-drawer-tab');
            document.getElementById(contentId).classList.add('active');
        });
    });

    // Threats view sub-tabs
    const threatTabBtns = document.querySelectorAll('.tab-btn');
    threatTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            threatTabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            fetchThreats(btn.getAttribute('data-tab'));
        });
    });

    // Graph action buttons
    document.getElementById('btn-graph-reset').addEventListener('click', () => fetchGraphData());
    const physicsBtn = document.getElementById('btn-graph-physics');
    physicsBtn.addEventListener('click', () => {
        if (visNetwork) {
            const isPhysicsEnabled = visNetwork.physics.options.enabled;
            visNetwork.setOptions({ physics: { enabled: !isPhysicsEnabled } });
            physicsBtn.innerHTML = isPhysicsEnabled ? 
                '<i data-lucide="play-circle"></i> Enable Physics' : 
                '<i data-lucide="pause-circle"></i> Freeze Physics';
            lucide.createIcons();
        }
    });

    // Refresh Dashboard Feed
    document.getElementById('refresh-dashboard-feed').addEventListener('click', () => {
        fetchStats();
        fetchDashboardFeed();
    });

    // Global Search & Filters
    document.getElementById('global-search').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const q = e.target.value.trim();
            if (q) {
                switchView('indicators');
                document.getElementById('indicator-search').value = q;
                fetchIndicators();
            }
        }
    });

    document.getElementById('indicator-search').addEventListener('input', debounce(fetchIndicators, 300));
    document.getElementById('indicator-filter-type').addEventListener('change', fetchIndicators);
    document.getElementById('indicator-filter-source').addEventListener('change', fetchIndicators);

    // Initial load
    initCharts();
    lucide.createIcons();
    startConnectorPolling();
});

// View Switching Logic
function switchView(viewName) {
    activeView = viewName;
    window.location.hash = viewName;

    // Update Nav Sidebar State
    document.querySelectorAll('.nav-menu a').forEach(item => {
        if (item.getAttribute('data-view') === viewName) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Update View Panels visibility
    document.querySelectorAll('.content-view').forEach(panel => {
        panel.classList.remove('active');
    });
    
    const activePanel = document.getElementById(`${viewName}-view`);
    if (activePanel) {
        activePanel.classList.add('active');
    }

    // Trigger loads for specific views
    if (viewName === 'dashboard') {
        fetchStats();
        fetchDashboardFeed();
    } else if (viewName === 'indicators') {
        fetchIndicators();
        fetchIndicatorSources();
    } else if (viewName === 'threats') {
        const activeTab = document.querySelector('.tab-btn.active').getAttribute('data-tab');
        fetchThreats(activeTab);
    } else if (viewName === 'graph') {
        fetchGraphData();
    } else if (viewName === 'connectors') {
        fetchConnectors();
    }
}

// Chart Initializations
function initCharts() {
    // Entities Breakdown Chart
    const ctxEntities = document.getElementById('chart-entities').getContext('2d');
    charts.entities = new Chart(ctxEntities, {
        type: 'bar',
        data: {
            labels: ['Indicators', 'Malware', 'Threat Actors', 'Campaigns', 'Vulnerabilities', 'Tools', 'Techniques', 'Targets'],
            datasets: [{
                label: 'Ingested Count',
                data: [0, 0, 0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 240, 255, 0.65)',
                    'rgba(255, 59, 92, 0.65)',
                    'rgba(196, 77, 255, 0.65)',
                    'rgba(255, 159, 26, 0.65)',
                    'rgba(255, 208, 0, 0.65)',
                    'rgba(59, 130, 246, 0.65)',
                    'rgba(168, 85, 247, 0.65)',
                    'rgba(0, 230, 118, 0.65)'
                ],
                borderColor: [
                    '#00f0ff',
                    '#ff3b5c',
                    '#c44dff',
                    '#ff9f1a',
                    '#ffd000',
                    '#3b82f6',
                    '#a855f7',
                    '#00e676'
                ],
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#64748b' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b' }
                }
            }
        }
    });

    // Confidence Level Doughnut
    const ctxConfidence = document.getElementById('chart-confidence').getContext('2d');
    charts.confidence = new Chart(ctxConfidence, {
        type: 'doughnut',
        data: {
            labels: ['High (>80)', 'Medium (50-80)', 'Low (<50)'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(0, 230, 118, 0.7)',
                    'rgba(255, 208, 0, 0.7)',
                    'rgba(255, 59, 92, 0.7)'
                ],
                borderColor: '#0f131a',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { size: 11 } }
                }
            },
            cutout: '65%'
        }
    });
}

// REST API helper functions
async function apiGet(endpoint) {
    try {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return await response.json();
    } catch (e) {
        console.error(`API GET error: ${endpoint}`, e);
        return null;
    }
}

async function apiPost(endpoint, data = {}) {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    } catch (e) {
        console.error(`API POST error: ${endpoint}`, e);
        return null;
    }
}

// Fetch stats and refresh charts
async function fetchStats() {
    const data = await apiGet('/api/stats');
    if (!data) return;

    // Fill counts
    document.getElementById('stat-indicators').innerText = data.summary.indicators;
    document.getElementById('stat-malware').innerText = data.summary.malware;
    document.getElementById('stat-actors').innerText = data.summary.threat_actors;
    document.getElementById('stat-relationships').innerText = data.summary.relationships;

    // Update active connectors badge in sidebar
    const badge = document.getElementById('active-connectors-count');
    if (data.summary.active_connectors > 0) {
        badge.innerText = data.summary.active_connectors;
        badge.style.display = 'inline-block';
    } else {
        badge.style.display = 'none';
    }

    // Update charts
    charts.entities.data.datasets[0].data = [
        data.summary.indicators || 0,
        data.summary.malware || 0,
        data.summary.threat_actors || 0,
        data.summary.campaigns || 0,
        data.summary.vulnerabilities || 0,
        data.summary.tools || 0,
        data.summary.techniques || 0,
        data.summary.identities || 0
    ];
    charts.entities.update();

    charts.confidence.data.datasets[0].data = [
        data.breakdown.confidence.high,
        data.breakdown.confidence.medium,
        data.breakdown.confidence.low
    ];
    charts.confidence.update();
}

// Fetch recent activity and populate Dashboard Feed Table
async function fetchDashboardFeed() {
    const data = await apiGet('/api/indicators');
    if (!data) return;

    const tbody = document.querySelector('#dashboard-feed-table tbody');
    tbody.innerHTML = '';

    if (data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-muted">No indicators ingested. Ingest baseline or run connectors.</td></tr>`;
        return;
    }

    // Limit to 6 items on dashboard
    data.slice(0, 6).forEach(row => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', () => fetchAndShowObject(row.id));

        const badgeClass = getBadgeClassForIoc(row.ioc_type);
        const relativeTime = getRelativeTimeString(new Date(row.created_at));

        tr.innerHTML = `
            <td><span class="badge ${badgeClass}">${row.ioc_type}</span></td>
            <td class="text-mono">${escapeHtml(row.name)}</td>
            <td><span class="text-primary">${escapeHtml(row.source || 'Direct API')}</span></td>
            <td>
                <div class="confidence-bar">
                    <div class="confidence-fill ${getConfidenceFillColor(row.confidence)}" style="width: ${row.confidence}%"></div>
                </div>
                <span>${row.confidence}%</span>
            </td>
            <td><span class="text-muted">${relativeTime}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Fetch indicators for Registry table
async function fetchIndicators() {
    const q = document.getElementById('indicator-search').value.trim();
    const type = document.getElementById('indicator-filter-type').value;
    const source = document.getElementById('indicator-filter-source').value;

    let url = `/api/indicators?`;
    if (q) url += `q=${encodeURIComponent(q)}&`;
    if (type) url += `type=${type}&`;
    if (source) url += `source=${encodeURIComponent(source)}&`;

    const data = await apiGet(url);
    const tbody = document.querySelector('#indicators-table tbody');
    tbody.innerHTML = '';

    if (!data || data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No indicators found matching filters.</td></tr>`;
        return;
    }

    data.forEach(row => {
        const tr = document.createElement('tr');
        const badgeClass = getBadgeClassForIoc(row.ioc_type);
        
        tr.innerHTML = `
            <td><span class="badge ${badgeClass}">${row.ioc_type}</span></td>
            <td class="text-mono font-bold">${escapeHtml(row.name)}</td>
            <td class="text-muted text-xs text-mono">${escapeHtml(row.pattern)}</td>
            <td><span class="text-primary">${escapeHtml(row.source || 'Direct API')}</span></td>
            <td>
                <div class="confidence-bar">
                    <div class="confidence-fill ${getConfidenceFillColor(row.confidence)}" style="width: ${row.confidence}%"></div>
                </div>
                <span>${row.confidence}%</span>
            </td>
            <td>
                <button class="btn-icon view-stix-btn" data-id="${row.id}"><i data-lucide="eye"></i></button>
            </td>
        `;
        
        // Add row clicks
        tr.style.cursor = 'pointer';
        tr.querySelector('.view-stix-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            fetchAndShowObject(row.id);
        });
        tr.addEventListener('click', () => fetchAndShowObject(row.id));

        tbody.appendChild(tr);
    });
    lucide.createIcons();
}

// Fetch source filter options for Registry page
async function fetchIndicatorSources() {
    const data = await apiGet('/api/connectors');
    const select = document.getElementById('indicator-filter-source');
    
    // Save current selection
    const prevSelection = select.value;
    select.innerHTML = '<option value="">All Sources</option><option value="Direct API Ingest">Direct API Ingest</option>';

    if (data) {
        data.forEach(conn => {
            const opt = document.createElement('option');
            opt.value = conn.name.split(" ")[0]; // Take first word like AbuseIPDB, ThreatFox, MITRE
            opt.innerText = conn.name;
            select.appendChild(opt);
        });
    }
    select.value = prevSelection;
}

// Fetch Threat objects based on active tab
async function fetchThreats(typeTab) {
    let typeFilter = 'threat-actor';
    if (typeTab === 'malware') typeFilter = 'malware';
    else if (typeTab === 'campaigns') typeFilter = 'campaign';
    else if (typeTab === 'vulnerabilities') typeFilter = 'vulnerability';
    else if (typeTab === 'tools') typeFilter = 'tool';
    else if (typeTab === 'techniques') typeFilter = 'attack-pattern';
    else if (typeTab === 'targets') typeFilter = 'identity';

    const data = await apiGet(`/api/objects?type=${typeFilter}`);
    const container = document.getElementById('threats-content');
    container.innerHTML = '';

    if (!data || data.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5 text-muted">
                <i data-lucide="folder-open" style="width: 48px; height: 48px; margin-bottom: 12px;"></i>
                <p>No threat items in this class. Go to the Connectors page and run 'MITRE ATT&CK Baseline Data' to ingest default library.</p>
            </div>`;
        lucide.createIcons();
        return;
    }

    const grid = document.createElement('div');
    grid.className = 'threats-list-grid';

    data.forEach(item => {
        const card = document.createElement('div');
        card.className = 'threat-card';
        card.addEventListener('click', () => fetchAndShowObject(item.id));

        const badgeClass = getBadgeClassForIoc(item.type);
        
        card.innerHTML = `
            <div class="threat-card-header">
                <span class="badge ${badgeClass}">${item.type}</span>
                <span class="text-muted font-bold text-xs">${item.confidence}% Conf</span>
            </div>
            <h3>${escapeHtml(item.name)}</h3>
            <p class="threat-card-desc">${escapeHtml(item.description || 'No description available.')}</p>
        `;
        grid.appendChild(card);
    });

    container.appendChild(grid);
    lucide.createIcons();
}

// Fetch Connectors and render
async function fetchConnectors() {
    const data = await apiGet('/api/connectors');
    const container = document.getElementById('connectors-container');
    container.innerHTML = '';

    if (!data) return;

    data.forEach(conn => {
        const card = document.createElement('div');
        card.className = 'connector-card';
        
        const isRunning = conn.status === 'RUNNING';
        const formattedDate = conn.last_run ? new Date(conn.last_run).toLocaleString() : 'Never';
        const textStatusClass = conn.status === 'RUNNING' ? 'status-running' : (conn.status === 'ERROR' ? 'status-error' : 'status-idle');

        card.innerHTML = `
            <div class="connector-header">
                <div class="connector-info">
                    <h3>${escapeHtml(conn.name)}</h3>
                    <span class="connector-type">${escapeHtml(conn.type)}</span>
                </div>
                <span class="status-indicator ${conn.status === 'RUNNING' ? 'online' : (conn.status === 'ERROR' ? 'status-red' : '')}"></span>
            </div>
            
            <p class="connector-desc">${escapeHtml(conn.description)}</p>
            
            <div class="connector-stats">
                <div class="connector-stat-item">
                    <span class="c-stat-label">Ingested STIX</span>
                    <span class="c-stat-value">${conn.record_count}</span>
                </div>
                <div class="connector-stat-item">
                    <span class="c-stat-label">Connector Status</span>
                    <span class="c-stat-value ${textStatusClass}">
                        ${isRunning ? '<span class="spinner-mini"></span> RUNNING' : conn.status}
                    </span>
                </div>
            </div>

            <div class="connector-logs-wrapper" id="logs-${conn.id}">
                <pre><code>${conn.logs ? escapeHtml(conn.logs) : 'No logs available.'}</code></pre>
            </div>
            
            <div class="connector-footer">
                <button class="log-toggle btn-text" data-target="logs-${conn.id}">
                    <i data-lucide="chevron-down"></i> Show Logs
                </button>
                <button class="btn btn-primary btn-run-connector" data-id="${conn.id}" ${isRunning ? 'disabled' : ''}>
                    <i data-lucide="play"></i> Run Connector
                </button>
            </div>
        `;

        // Log toggle click
        card.querySelector('.log-toggle').addEventListener('click', (e) => {
            const wrapper = card.querySelector('.connector-logs-wrapper');
            const isVisible = wrapper.classList.toggle('show');
            e.currentTarget.innerHTML = isVisible ? 
                '<i data-lucide="chevron-up"></i> Hide Logs' : 
                '<i data-lucide="chevron-down"></i> Show Logs';
            lucide.createIcons();
        });

        // Run click
        const runBtn = card.querySelector('.btn-run-connector');
        runBtn.addEventListener('click', () => triggerConnector(conn.id, runBtn));

        container.appendChild(card);
    });

    lucide.createIcons();
}

// Trigger connector ingestion
async function triggerConnector(connId, button) {
    button.disabled = true;
    button.innerHTML = '<span class="spinner-mini"></span> Launching...';

    const res = await apiPost(`/api/connectors/${connId}/trigger`);
    if (res && res.status === 'triggered') {
        // Refresh connector view immediately
        fetchConnectors();
        fetchStats();
    } else {
        alert("Failed to trigger connector run!");
        button.disabled = false;
        button.innerHTML = '<i data-lucide="play"></i> Run Connector';
        lucide.createIcons();
    }
}

// Polling active connectors
function startConnectorPolling() {
    activeConnectorsPollInterval = setInterval(async () => {
        // Poll database if any connector is active or on connectors page
        const connectors = await apiGet('/api/connectors');
        if (connectors) {
            let activeCount = 0;
            let changes = false;
            connectors.forEach(conn => {
                if (conn.status === 'RUNNING') activeCount++;
            });

            // Update badge
            const badge = document.getElementById('active-connectors-count');
            if (activeCount > 0) {
                badge.innerText = activeCount;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }

            // If active view is connectors or dashboard, refresh
            if (activeView === 'connectors') {
                fetchConnectors();
            }
            if (activeView === 'dashboard') {
                fetchStats();
                fetchDashboardFeed();
            }
        }
    }, 3000);
}

// Graph Vis.js Network rendering
async function fetchGraphData() {
    const data = await apiGet('/api/relationships');
    if (!data) return;

    const container = document.getElementById('relationship-graph');
    
    // Clear Detail Panel
    document.querySelector('#graph-node-details .empty-state').style.display = 'flex';
    document.querySelector('#graph-node-details .entity-details').style.display = 'none';

    // Format Vis.js Nodes
    const visNodesArr = data.nodes.map(n => {
        const styles = getGraphNodeStyle(n.type);
        return {
            id: n.id,
            label: n.name,
            color: styles.color,
            shadow: { enabled: true, color: styles.shadow, size: 8 },
            size: styles.size,
            shape: 'dot',
            font: { face: 'Plus Jakarta Sans', color: '#f1f5f9', size: 12, strokeWidth: 2, strokeColor: '#080a10' },
            borderWidth: 2,
            borderColor: '#ffffff1a'
        };
    });

    // Format Vis.js Edges
    const visEdgesArr = data.edges.map(e => {
        return {
            id: e.id,
            from: e.source,
            to: e.target,
            label: e.label,
            arrows: 'to',
            font: { face: 'Space Grotesk', color: '#94a3b8', size: 10, strokeWidth: 1, strokeColor: '#080a10', align: 'middle' },
            color: { color: 'rgba(255, 255, 255, 0.12)', highlight: '#3b82f6', hover: '#3b82f6' },
            width: 1.5,
            smooth: { type: 'curvedCW', roundness: 0.1 }
        };
    });

    visNodes = new vis.DataSet(visNodesArr);
    visEdges = new vis.DataSet(visEdgesArr);

    const graphData = { nodes: visNodes, edges: visEdges };
    
    const options = {
        interaction: { hover: true, selectConnectedEdges: true },
        physics: {
            stabilization: { iterations: 100 },
            barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 95 }
        }
    };

    visNetwork = new vis.Network(container, graphData, options);

    // Node / Edge click handler
    visNetwork.on("click", (params) => {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            fetchAndShowGraphDetails(nodeId);
        } else if (params.edges.length > 0) {
            const edgeId = params.edges[0];
            fetchAndShowGraphDetails(edgeId);
        } else {
            // Clicked empty background
            document.querySelector('#graph-node-details .empty-state').style.display = 'flex';
            document.querySelector('#graph-node-details .entity-details').style.display = 'none';
            currentDetailObject = null;
        }
    });
}

// Get Detail node/edge properties and display in Graph panel
async function fetchAndShowGraphDetails(id) {
    const data = await apiGet(`/api/objects/${id}`);
    if (!data) return;

    currentDetailObject = data;

    // Hide empty state, show entity details
    document.querySelector('#graph-node-details .empty-state').style.display = 'none';
    const detailPanel = document.querySelector('#graph-node-details .entity-details');
    detailPanel.style.display = 'flex';

    // Populate panel
    const badge = document.getElementById('detail-entity-type');
    const nameEl = document.getElementById('detail-entity-name');
    const descEl = document.getElementById('detail-entity-desc');
    const idEl = document.getElementById('detail-entity-id');
    const confidenceEl = document.getElementById('detail-entity-confidence');
    const sourceEl = document.getElementById('detail-entity-source');

    badge.innerText = data.type || 'Relationship';
    badge.className = `entity-badge ${getBadgeClassForIoc(data.type)}`;
    nameEl.innerText = data.name || data.relationship_type || 'STIX Relation';
    descEl.innerText = data.description || 'No description available for this cyber threat element.';
    idEl.innerText = data.id;
    confidenceEl.innerText = `${data.confidence || 70}%`;
    sourceEl.innerText = data.source || 'MITRE ATT&CK Baseline';
}

// Fetch single STIX object and open Slideout Drawer
async function fetchAndShowObject(id) {
    const data = await apiGet(`/api/objects/${id}`);
    if (data) {
        openStixDrawer(data);
    }
}

// Open slideout STIX details drawer
function openStixDrawer(obj) {
    currentDetailObject = obj;
    
    // Set Header
    document.querySelector('#stix-drawer h2').innerText = obj.name || obj.relationship_type || obj.type;

    // Reset drawer tabs
    document.querySelectorAll('.drawer-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('.drawer-tab-btn[data-drawer-tab="stix-properties"]').classList.add('active');
    
    document.querySelectorAll('.drawer-tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('stix-properties').classList.add('active');

    // Build Properties
    const propDiv = document.getElementById('stix-properties');
    propDiv.innerHTML = '';
    
    const propList = document.createElement('div');
    propList.className = 'drawer-property-list';

    const props = [
        { label: 'Type', value: `<span class="badge ${getBadgeClassForIoc(obj.type)}">${obj.type}</span>` },
        { label: 'STIX ID', value: `<span class="text-mono text-xs">${obj.id}</span>` },
        { label: 'Confidence Score', value: `${obj.confidence || 70}%` },
        { label: 'Ingested Source', value: obj.source || 'Direct API' },
        { label: 'Description', value: obj.description || 'No description provided.' }
    ];

    // For indicators, include pattern
    if (obj.raw && obj.raw.pattern) {
        props.push({ label: 'STIX 2.1 Pattern', value: `<pre style="font-family: var(--font-mono); font-size:11px; color: var(--color-cyan); background:#06080d; padding:10px; border-radius:6px; overflow-x:auto;">${escapeHtml(obj.raw.pattern)}</pre>` });
        props.push({ label: 'Indicator Type', value: obj.raw.x_ioc_type || 'Unknown' });
        props.push({ label: 'Indicator Value', value: obj.raw.x_ioc_value || 'Unknown' });
    }

    // For relationships, show source/target as clickable links
    if (obj.type === 'relationship') {
        props.push({ label: 'Relationship Type', value: `<span class="badge badge-campaign">${obj.relationship_type}</span>` });
        props.push({ label: 'Source STIX Ref', value: `<a href="#" class="drawer-nav-link text-mono text-xs" data-id="${obj.source_ref}" style="text-decoration: underline; color: var(--color-cyan); font-weight:600;">${obj.source_ref}</a>` });
        props.push({ label: 'Target STIX Ref', value: `<a href="#" class="drawer-nav-link text-mono text-xs" data-id="${obj.target_ref}" style="text-decoration: underline; color: var(--color-cyan); font-weight:600;">${obj.target_ref}</a>` });
    }

    props.forEach(p => {
        const item = document.createElement('div');
        item.className = 'drawer-prop-item';
        item.innerHTML = `
            <div class="drawer-prop-label">${p.label}</div>
            <div class="drawer-prop-value">${p.value}</div>
        `;
        propList.appendChild(item);
    });

    propDiv.appendChild(propList);

    // Bind event listeners to drawer properties navigation links
    propDiv.querySelectorAll('.drawer-nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('data-id');
            fetchAndShowObject(targetId);
        });
    });

    // Load related threat assets asynchronously
    loadDrawerRelationships(obj.id);

    // Code view
    const jsonStr = JSON.stringify(obj.raw || obj, null, 2);
    document.getElementById('stix-json-code').innerText = jsonStr;

    // Show drawer
    document.getElementById('stix-drawer-overlay').classList.add('active');
    document.getElementById('stix-drawer').classList.add('active');
}

async function loadDrawerRelationships(objId) {
    const listContainer = document.getElementById('stix-relationships-list');
    listContainer.innerHTML = '<div class="text-center text-muted text-xs py-3">Loading relationships...</div>';

    const relations = await apiGet(`/api/objects/${objId}/relationships`);
    listContainer.innerHTML = '';

    if (!relations || relations.length === 0) {
        listContainer.innerHTML = '<div class="text-center text-muted text-xs py-3">No direct relationships found for this object.</div>';
        return;
    }

    relations.forEach(r => {
        const item = document.createElement('div');
        item.className = 'drawer-prop-item';
        
        const badgeClass = getBadgeClassForIoc(r.other_type);
        const directionText = r.direction === 'out' ? 'Outgoing' : 'Incoming';

        item.innerHTML = `
            <div class="drawer-prop-label" style="display: flex; align-items: center; gap: 6px; margin-bottom: 6px;">
                <span class="badge badge-campaign">${escapeHtml(r.relationship_type)}</span>
                <span style="font-size: 10px; color: var(--text-muted); font-weight:600; text-transform: uppercase;">${directionText}</span>
            </div>
            <div class="drawer-prop-value" style="display: flex; align-items: center; justify-content: space-between; gap: 10px;">
                <a href="#" class="drawer-nav-link" data-id="${r.other_id}" style="display: inline-flex; align-items: center; gap: 8px;">
                    <span class="badge ${badgeClass}">${escapeHtml(r.other_type)}</span>
                    <span style="font-weight: 600; text-decoration: underline; color: var(--color-cyan);">${escapeHtml(r.other_name)}</span>
                </a>
                <span class="text-xs text-muted" style="font-family: var(--font-mono);">${r.confidence}% Conf</span>
            </div>
            ${r.description ? `<p style="font-size:11px; color: var(--text-muted); margin-top:6px; font-style: italic; border-left: 2px solid rgba(255,255,255,0.05); padding-left: 6px;">${escapeHtml(r.description)}</p>` : ''}
        `;
        
        // Add click navigation handler
        item.querySelector('.drawer-nav-link').addEventListener('click', (e) => {
            e.preventDefault();
            fetchAndShowObject(r.other_id);
        });

        listContainer.appendChild(item);
    });
}

function closeStixDrawer() {
    document.getElementById('stix-drawer-overlay').classList.remove('active');
    document.getElementById('stix-drawer').classList.remove('active');
}

// Modal handling
function showIngestModal() {
    document.getElementById('stix-bundle-paste').value = '';
    document.getElementById('ingest-modal-overlay').classList.add('active');
    document.getElementById('ingest-modal').classList.add('active');
}

function hideIngestModal() {
    document.getElementById('ingest-modal-overlay').classList.remove('active');
    document.getElementById('ingest-modal').classList.remove('active');
}

// Ingest custom STIX bundle POST request
async function handleStixIngest() {
    const rawVal = document.getElementById('stix-bundle-paste').value.trim();
    if (!rawVal) {
        alert("Please paste a STIX 2.1 Bundle JSON string.");
        return;
    }

    let bundleJson;
    try {
        bundleJson = JSON.parse(rawVal);
    } catch (e) {
        alert("Invalid JSON format! Please check the structure.");
        return;
    }

    if (bundleJson.type !== 'bundle') {
        alert("Ingested JSON is not a STIX 'bundle' type!");
        return;
    }

    const btn = document.getElementById('btn-submit-ingest');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-mini"></span> Ingesting...';

    const res = await apiPost('/api/ingest', bundleJson);
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="upload"></i> Process Ingestion';
    lucide.createIcons();

    if (res && res.status === 'success') {
        alert(`STIX bundle processed successfully! Ingested ${res.ingested_objects} objects.`);
        hideIngestModal();
        switchView('dashboard');
    } else {
        alert("Ingestion failed: " + (res?.detail || "Unknown validation error."));
    }
}

function getBadgeClassForIoc(type) {
    switch (type) {
        case 'ipv4-addr':
        case 'ipv6-addr':
        case 'ip':
            return 'badge-ip';
        case 'domain-name':
        case 'domain':
            return 'badge-domain';
        case 'url':
            return 'badge-url';
        case 'file':
        case 'hash':
            return 'badge-hash';
        case 'vulnerability':
            return 'badge-vuln';
        case 'threat-actor':
            return 'badge-actor';
        case 'malware':
            return 'badge-malware';
        case 'campaign':
            return 'badge-campaign';
        case 'tool':
            return 'badge-domain';
        case 'attack-pattern':
            return 'badge-actor';
        case 'identity':
            return 'badge-hash';
        case 'incident':
            return 'badge-malware';
        case 'location':
            return 'badge-url';
        default:
            return 'badge-secondary';
    }
}

function getConfidenceFillColor(conf) {
    if (conf > 80) return 'high';
    if (conf > 50) return 'med';
    return 'low';
}

function getGraphNodeStyle(type) {
    switch (type) {
        case 'threat-actor':
            return { color: '#c44dff', shadow: 'rgba(196, 77, 255, 0.4)', size: 24 };
        case 'malware':
            return { color: '#ff3b5c', shadow: 'rgba(255, 59, 92, 0.4)', size: 22 };
        case 'campaign':
            return { color: '#ff9f1a', shadow: 'rgba(255, 159, 26, 0.4)', size: 22 };
        case 'vulnerability':
            return { color: '#ffd000', shadow: 'rgba(255, 208, 0, 0.4)', size: 20 };
        case 'indicator':
            return { color: '#00f0ff', shadow: 'rgba(0, 240, 255, 0.4)', size: 18 };
        case 'identity':
            return { color: '#00e676', shadow: 'rgba(0, 230, 118, 0.4)', size: 20 };
        case 'attack-pattern':
            return { color: '#3b82f6', shadow: 'rgba(59, 130, 246, 0.4)', size: 18 };
        case 'tool':
            return { color: '#3b82f6', shadow: 'rgba(59, 130, 246, 0.4)', size: 18 };
        case 'incident':
            return { color: '#ef4444', shadow: 'rgba(239, 68, 68, 0.4)', size: 22 };
        case 'location':
            return { color: '#e5c158', shadow: 'rgba(229, 193, 88, 0.4)', size: 20 };
        default:
            return { color: '#94a3b8', shadow: 'rgba(148, 163, 184, 0.2)', size: 16 };
    }
}

function getRelativeTimeString(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);

    if (diffSecs < 60) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
