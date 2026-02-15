/**
 * C2Trap SOC Dashboard - Premium JS
 * Enhanced with smooth animations and robust data handling
 */

const API_BASE = '';
let currentView = 'overview';
let refreshInterval = null;
let lastUpdate = Date.now();

// =============================================
// Initialization & Navigation
// =============================================

document.addEventListener('DOMContentLoaded', () => {
    // Initial Load
    loadOverview();

    // Setup Navigation
    setupNavigation();

    // Start Auto-Refresh
    console.log("Starting Auto-Refresh interval (5s)");
    refreshInterval = setInterval(() => {
        console.log("Auto-Refresh triggered at", new Date().toISOString());
        refreshData(true);
    }, 5000); // Fast 5s refresh for "live" feel

    // Initial icon render
    lucide.createIcons();
});

function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            switchView(view);
        });
    });

    document.querySelectorAll('.panel-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = link.dataset.view;
            switchView(view);
        });
    });
}

function switchView(view) {
    if (currentView === view) return;

    currentView = view;

    // Update Nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });

    // Animate View Transition
    document.querySelectorAll('.view').forEach(v => {
        if (v.id === `view-${view}`) {
            v.style.display = 'block';
            setTimeout(() => v.classList.add('active'), 10);
        } else {
            v.classList.remove('active');
            setTimeout(() => v.style.display = 'none', 300);
        }
    });

    // Update Title
    const titles = {
        overview: 'Command Center',
        events: 'Live Event Stream',
        alerts: 'Threat Intelligence',
        mitre: 'ATT&CK Matrix',
        killchain: 'Kill Chain Analysis',
        iocs: 'IOC Database',

        falco: 'Runtime Security'
    };

    const titleEl = document.getElementById('view-title');
    titleEl.style.opacity = 0;
    setTimeout(() => {
        titleEl.textContent = titles[view] || 'Dashboard';
        titleEl.style.opacity = 1;
    }, 200);

    // Refresh data for new view
    loadViewData(view);
}

async function refreshData(silent = false) {
    if (!silent) {
        const btn = document.querySelector('.btn i');
        if (btn) btn.classList.add('spin-anim');
    }

    await loadViewData(currentView);

    if (!silent) {
        const btn = document.querySelector('.btn i');
        if (btn) setTimeout(() => btn.classList.remove('spin-anim'), 1000);
    }

    updateLastUpdate();
}

// =============================================
// Data Loading
// =============================================

async function fetchAPI(endpoint) {
    try {
        // Add timestamp to prevent caching
        const sep = endpoint.includes('?') ? '&' : '?';
        const url = `${API_BASE}/api/${endpoint}${sep}_t=${Date.now()}`;

        const response = await fetch(url, {
            cache: 'no-store',
            headers: {
                'Pragma': 'no-cache',
                'Cache-Control': 'no-cache'
            }
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        return null;
    }
}

async function loadViewData(view) {
    switch (view) {
        case 'overview':
            await loadOverview();
            break;
        case 'events':
            await loadEvents();
            break;
        case 'alerts':
            await loadAlerts();
            break;
        case 'mitre':
            await loadMitre();
            break;
        case 'killchain':
            await loadKillchain();
            break;
        case 'iocs':
            await loadIOCs();
            break;

        case 'falco':
            await loadFalco();
            break;
    }
    lucide.createIcons();
}

async function loadOverview() {
    const [stats, alerts, events, killchain] = await Promise.all([
        fetchAPI('stats'),
        fetchAPI('alerts?limit=5'),
        fetchAPI('events?limit=8'),
        fetchAPI('killchain')
    ]);

    if (stats) {
        animateValue('stat-events', stats.total_events || 0);
        animateValue('stat-alerts', stats.total_alerts || 0);
        animateValue('stat-critical', stats.critical_alerts || 0);
        animateValue('stat-techniques', stats.mitre_techniques || 0);

    }

    renderRecentAlerts(alerts);
    renderRecentEvents(events);
    renderKillchainMini(killchain);
}

// =============================================
// Rendering Functions
// =============================================

function renderRecentAlerts(alerts) {
    const container = document.getElementById('recent-alerts');
    if (!alerts || alerts.length === 0) {
        container.innerHTML = getEmptyState('check-circle', 'No active threats');
        return;
    }

    const html = alerts.map((alert, index) => `
        <div class="list-item severity-${alert.severity.toLowerCase()}" style="animation-delay: ${index * 50}ms">
            <div class="alert-icon">
                <i data-lucide="${getSeverityIcon(alert.severity)}"></i>
            </div>
            <div class="alert-content">
                <div class="alert-header">
                    <span class="alert-title">${escapeHtml(alert.title)}</span>
                    <span class="alert-badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
                </div>
                <div class="alert-desc">${escapeHtml(alert.description)}</div>
                <div class="meta-tags">
                    <span class="meta-tag"><i data-lucide="clock" size="12"></i> ${formatTime(alert.timestamp)}</span>
                    ${alert.source_ip ? `<span class="meta-tag"><i data-lucide="network" size="12"></i> ${alert.source_ip}</span>` : ''}
                </div>
            </div>
        </div>
    `).join('');

    if (container.innerHTML !== html) container.innerHTML = html;
}

function renderRecentEvents(events) {
    const container = document.getElementById('recent-events');
    if (!events || events.length === 0) {
        container.innerHTML = getEmptyState('activity', 'No recent activity');
        return;
    }

    const html = events.map((event, index) => `
        <div class="feed-item" style="animation: slideIn 0.3s ease forwards ${index * 50}ms; opacity: 0">
            <div class="feed-time">${formatTimeShort(event.timestamp)}</div>
            <div class="feed-marker feed-type-${getEventTypeClass(event)}"></div>
            <div class="feed-content">
                <div class="feed-title">${formatEventType(event.event_type)}</div>
                <div class="feed-details">${formatEventDetails(event)}</div>
            </div>
        </div>
    `).join('');

    container.innerHTML = html;
}


function formatSource(source) {
    const map = {
        'http_decoy': '<span style="color:#e74c3c; font-weight:bold">⛔ Rerouted to HTTP Decoy</span>',
        'dns_decoy': '<span style="color:#e67e22; font-weight:bold">🌀 Rerouted to DNS Sinkhole</span>',
        'ftp_decoy': '<span style="color:#9b59b6; font-weight:bold">🔒 Rerouted to HoneyFTP</span>',
        'smtp_decoy': '<span style="color:#2ecc71; font-weight:bold">📧 Mail Trap</span>',
        'packet_capture': '<span style="color:#3498db">📡 Deep Packet Insp.</span>',
        'beacon_detector': '<span style="color:#e74c3c; font-weight:bold">🚨 C2 Beacon</span>',
        'dga_detector': '<span style="color:#ff6b6b; font-weight:bold">🧬 DGA Detector</span>',
        'dns_tunnel_detector': '<span style="color:#ffa502; font-weight:bold">🕳️ DNS Tunnel Detector</span>',
        'tls_anomaly_detector': '<span style="color:#a29bfe; font-weight:bold">🔐 TLS Anomaly Detector</span>',
        'zeek': '<span style="color:#f1c40f">Zeek IDS</span>'
    };
    return map[source] || source;
}

function renderEventsList(events) {
    const container = document.getElementById('events-list');
    if (!events || events.length === 0) {
        container.innerHTML = getEmptyState('list', 'No events found matching criteria');
        return;
    }

    container.innerHTML = events.map((event, index) => `
        <div class="list-item" style="animation-delay: ${index * 30}ms">
            <div class="feed-time" style="min-width: 140px;">${new Date(event.timestamp).toLocaleString()}</div>
            <div class="feed-marker feed-type-${getEventTypeClass(event)}"></div>
            <div class="feed-content">
                <div class="feed-title">
                    ${formatEventType(event.event_type)}
                    <span style="float: right; font-size: 11px; opacity: 0.8;">${formatSource(event.source)}</span>
                </div>
                <div class="feed-details" style="color: var(--text-primary); margin-top: 6px;">
                    ${formatEventDetails(event)}
                </div>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
}

function renderAlertsList(alerts) {
    const container = document.getElementById('alerts-list');
    if (!alerts || alerts.length === 0) {
        container.innerHTML = getEmptyState('shield-check', 'System Secure: No Alerts');
        return;
    }

    container.innerHTML = alerts.map((alert, index) => `
        <div class="list-item severity-${alert.severity.toLowerCase()}" style="animation-delay: ${index * 50}ms">
            <div class="alert-icon">
                <i data-lucide="${getSeverityIcon(alert.severity)}"></i>
            </div>
            <div class="alert-content">
                <div class="alert-header">
                    <span class="alert-title">${escapeHtml(alert.title)}</span>
                    <span class="alert-badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
                </div>
                <div class="alert-desc">${escapeHtml(alert.description)}</div>
                <div class="meta-tags">
                    <span class="meta-tag"><i data-lucide="clock" size="12"></i> ${new Date(alert.timestamp).toLocaleString()}</span>
                    ${alert.source_ip ? `<span class="meta-tag"><i data-lucide="network" size="12"></i> ${alert.source_ip}</span>` : ''}
                    ${alert.mitre_technique ? `<span class="meta-tag"><i data-lucide="crosshair" size="12"></i> ${alert.mitre_technique}</span>` : ''}
                </div>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
}

function renderKillchainMini(data) {
    const container = document.getElementById('killchain-mini');
    if (!data || !data.phases) return;

    container.innerHTML = data.phases.map(phase => `
        <div class="phase-card ${phase.active ? 'active' : ''}">
            <i data-lucide="${getPhaseIcon(phase.name)}" class="phase-icon"></i>
            <div class="phase-title">${phase.name}</div>
            <div class="phase-count">${phase.events}</div>
        </div>
    `).join('');
    lucide.createIcons();
}

function renderMitreMatrix(mitre) {
    const container = document.getElementById('mitre-matrix');
    if (!mitre || !mitre.matrix) {
        container.innerHTML = getEmptyState('grid', 'No MITRE Data');
        return;
    }

    container.innerHTML = `<div class="matrix-grid">` +
        Object.entries(mitre.matrix).map(([tactic, techniques]) => `
            <div class="tactic-column">
                <div class="tactic-header">${tactic.replace(/-/g, ' ')}</div>
                <div class="tech-list">
                    ${techniques.length ? techniques.map(t => `
                        <div class="tech-item ${t.detected ? 'detected' : ''}">
                            <span style="opacity: 0.7">${t.id}</span>
                            <span>${t.name}</span>
                        </div>
                    `).join('') : '<div class="tech-item" style="opacity:0.3">No detections</div>'}
                </div>
            </div>
        `).join('') +
        `</div>`;
}

// =============================================
// Helper Functions
// =============================================

function animateValue(id, end, duration = 1000) {
    const obj = document.getElementById(id);
    if (!obj) return;

    // If value hasn't changed, don't animate
    const current = parseInt(obj.innerText.replace(/,/g, '')) || 0;
    if (current === end) return;

    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 4); // Ease out quart

        obj.innerHTML = Math.floor(progress * (end - current) + current).toLocaleString();

        if (progress < 1) {
            window.requestAnimationFrame(step);
        } else {
            obj.innerHTML = end.toLocaleString();
        }
    };
    window.requestAnimationFrame(step);
}

function formatTime(ts) {
    if (!ts) return '--';
    const date = new Date(ts);
    const now = new Date();
    const diff = (now - date) / 1000; // seconds

    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
}

function formatTimeShort(ts) {
    const d = new Date(ts);
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
}

function getSeverityIcon(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'zap';
        case 'high': return 'alert-triangle';
        case 'medium': return 'alert-circle';
        case 'low': return 'info';
        default: return 'help-circle';
    }
}

function getEventTypeClass(event) {
    const t = event.event_type || '';
    if (t.includes('http')) return 'http';
    if (t.includes('dns')) return 'dns';
    if (t.includes('malware') || t.includes('beacon')) return 'malware';
    if (event.source.includes('zeek')) return 'zeek';
    return 'default';
}

function getPhaseIcon(name) {
    const map = {
        'Reconnaissance': 'search',
        'Delivery': 'package',
        'Exploitation': 'zap',
        'Installation': 'download',
        'Command & Control': 'wifi',
        'Actions': 'activity'
    };
    return map[name] || 'circle';
}

function formatEventType(type) {
    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function getEmptyState(icon, text) {
    return `
        <div class="empty-state">
            <div class="empty-icon"><i data-lucide="${icon}"></i></div>
            <p>${text}</p>
        </div>
    `;
}

function formatEventDetails(event) {
    const data = event.data || {};
    const parts = [];

    if (data.remote_ip || data.src_ip || data.client_ip) {
        parts.push(`<span style="color: var(--text-accent)">${data.remote_ip || data.src_ip || data.client_ip}</span>`);
    }
    if (data.path) parts.push(`Path: ${data.path}`);
    if (data.domain || data.query_name) parts.push(`Domain: <span style="color: var(--purple-haze)">${data.domain || data.query_name}</span>`);
    if (data.method) parts.push(`${data.method}`);

    // DGA Detection specifics
    if (event.event_type === 'dga_domain_detected') {
        parts.push(`<span style="color:#ff6b6b;font-weight:bold">DGA Score: ${(data.dga_score || 0).toFixed(2)}</span>`);
        if (data.entropy) parts.push(`Entropy: ${data.entropy}`);
        if (data.mitre_technique) parts.push(`MITRE: ${data.mitre_technique}`);
    }

    // DNS Tunnel specifics
    if (event.event_type === 'dns_tunneling_detected') {
        parts.push(`<span style="color:#ffa502;font-weight:bold">Tunnel Score: ${(data.tunnel_score || 0).toFixed(2)}</span>`);
        if (data.encoding) parts.push(`Encoding: ${data.encoding}`);
        if (data.mitre_technique) parts.push(`MITRE: ${data.mitre_technique}`);
    }

    // TLS Anomaly specifics
    if (event.event_type === 'tls_anomaly_detected') {
        parts.push(`<span style="color:#a29bfe;font-weight:bold">TLS Score: ${(data.tls_score || 0).toFixed(2)}</span>`);
        if (data.ja3_hash) parts.push(`JA3: ${data.ja3_hash.substring(0, 12)}...`);
        if (data.anomalies) parts.push(`${data.anomalies.join(', ').substring(0, 60)}`);
    }

    // Zeek specifics
    if (event.source && event.source.includes('zeek')) {
        if (data.service) parts.push(`Service: ${data.service}`);
        if (data.ja3_hash) parts.push(`JA3: ${data.ja3_hash.substring(0, 8)}...`);
    }

    // MITRE technique for c2 events
    if (data.mitre_technique && !['dga_domain_detected', 'dns_tunneling_detected', 'tls_anomaly_detected'].includes(event.event_type)) {
        parts.push(`<span style="color:#e94560">MITRE: ${data.mitre_technique}</span>`);
    }

    return parts.length > 0 ? parts.join(' &bull; ') : 'Raw Event Data';
}

function updateLastUpdate() {
    const el = document.getElementById('last-update');
    if (el) {
        el.textContent = new Date().toLocaleTimeString();
        // Add visual pulse to confirm update
        el.style.color = '#4CAF50';
        setTimeout(() => { el.style.color = ''; }, 500);
    }
}

// Load other views (placeholders for brevity, follow same pattern)
async function loadEvents() {
    const filter = document.getElementById('event-filter')?.value || '';
    const events = await fetchAPI(filter ? `events?limit=100&event_type=${filter}` : 'events?limit=100');
    renderEventsList(events);
}

async function loadAlerts() {
    const alerts = await fetchAPI('alerts?limit=100');
    renderAlertsList(alerts);
}



async function loadMitre() {
    const mitre = await fetchAPI('mitre');
    renderMitreMatrix(mitre);
}

async function loadKillchain() {
    const data = await fetchAPI('killchain');
    const container = document.getElementById('killchain-full');
    if (!data || !data.phases) {
        container.innerHTML = getEmptyState('link', 'No Kill Chain data available');
        return;
    }

    container.innerHTML = `
        <div class="killchain-timeline">
            ${data.phases.map((phase, index) => `
                <div class="killchain-phase ${phase.active ? 'active' : ''}">
                    <div class="phase-number">${index + 1}</div>
                    <div class="phase-icon-large"><i data-lucide="${getPhaseIcon(phase.name)}"></i></div>
                    <div class="phase-name">${phase.name}</div>
                    <div class="phase-events-count">${phase.events} events</div>
                    ${phase.active ? '<div class="phase-active-badge">DETECTED</div>' : ''}
                </div>
                ${index < data.phases.length - 1 ? '<div class="phase-connector"></div>' : ''}
            `).join('')}
        </div>
    `;
    lucide.createIcons();
}

async function loadIOCs() {
    const typeFilter = document.querySelector('.ioc-filter.active')?.dataset.type || '';
    const maliciousOnly = document.getElementById('malicious-only')?.checked || false;

    let endpoint = 'iocs';
    const params = [];
    if (typeFilter) params.push(`ioc_type=${typeFilter}`);
    if (maliciousOnly) params.push('malicious_only=true');
    if (params.length) endpoint += '?' + params.join('&');

    const iocs = await fetchAPI(endpoint);
    const container = document.getElementById('iocs-list');

    if (!iocs || iocs.length === 0) {
        container.innerHTML = getEmptyState('database', 'No IOCs found matching criteria');
        return;
    }

    container.innerHTML = iocs.map((ioc, index) => {
        const threatScore = ioc.threat_score || 0;
        const vt = ioc.virus_total || {};
        const scoreClass = threatScore >= 80 ? 'critical' : threatScore >= 50 ? 'high' : threatScore > 0 ? 'medium' : '';

        return `
        <div class="list-item ${ioc.is_malicious ? 'severity-high' : ''}" style="animation-delay: ${index * 30}ms">
            <div class="ioc-type-badge">${ioc.type.toUpperCase()}</div>
            <div class="ioc-content" style="flex: 1;">
                <div class="ioc-value" style="display: flex; align-items: center; gap: 10px;">
                    ${escapeHtml(ioc.value)}
                    ${threatScore > 0 ? `<span class="threat-score-badge ${scoreClass}" style="background: ${threatScore >= 80 ? '#e74c3c' : threatScore >= 50 ? '#e67e22' : '#f39c12'}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">${threatScore}/100</span>` : ''}
                </div>
                <div class="meta-tags">
                    <span class="meta-tag"><i data-lucide="activity" size="12"></i> ${ioc.hit_count} hits</span>
                    <span class="meta-tag"><i data-lucide="clock" size="12"></i> Last: ${formatTime(ioc.last_seen)}</span>
                    ${ioc.is_malicious ? '<span class="meta-tag" style="color: var(--red-alert)"><i data-lucide="alert-triangle" size="12"></i> Malicious</span>' : ''}
                    ${vt.malicious ? `<span class="meta-tag" style="color: #e74c3c;"><i data-lucide="shield-alert" size="12"></i> VT: ${vt.malicious}/${vt.malicious + vt.harmless} detections</span>` : ''}
                </div>
            </div>
        </div>
    `;
    }).join('');
    lucide.createIcons();
}


async function loadFalco() {
    const priorityFilter = document.getElementById('falco-priority-filter')?.value || '';
    const endpoint = priorityFilter ? `falco?limit=100&priority=${priorityFilter}` : 'falco?limit=100';
    const events = await fetchAPI(endpoint);
    const container = document.getElementById('falco-list');

    if (!events || events.length === 0) {
        container.innerHTML = getEmptyState('server', 'No Falco alerts. System calls appear normal.');
        return;
    }

    container.innerHTML = events.map((event, index) => `
        <div class="list-item severity-${event.priority?.toLowerCase() || 'low'}" style="animation-delay: ${index * 30}ms">
            <div class="alert-icon">
                <i data-lucide="${getSeverityIcon(event.priority || 'info')}"></i>
            </div>
            <div class="alert-content">
                <div class="alert-header">
                    <span class="alert-title">${escapeHtml(event.rule || 'Unknown Rule')}</span>
                    <span class="alert-badge badge-${(event.priority || 'low').toLowerCase()}">${event.priority || 'INFO'}</span>
                </div>
                <div class="alert-desc">${escapeHtml(event.output || '')}</div>
                <div class="meta-tags">
                    <span class="meta-tag"><i data-lucide="clock" size="12"></i> ${new Date(event.time).toLocaleString()}</span>
                    <span class="meta-tag"><i data-lucide="box" size="12"></i> ${event.hostname || 'unknown'}</span>
                    ${event.output_fields?.['container.id'] ? `<span class="meta-tag"><i data-lucide="container" size="12"></i> ${event.output_fields['container.id']}</span>` : ''}
                </div>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
}

// Setup IOC filter buttons
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.ioc-filter').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.ioc-filter').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            loadIOCs();
        });
    });

    document.getElementById('malicious-only')?.addEventListener('change', loadIOCs);

    document.getElementById('falco-priority-filter')?.addEventListener('change', loadFalco);
    document.getElementById('event-filter')?.addEventListener('change', loadEvents);
});


async function downloadReport() {
    const btn = document.querySelector('.btn i[data-lucide="file-text"]');
    if (btn) btn.classList.add('spin-anim');

    try {
        const response = await fetch(`${API_BASE}/api/report/download`);
        if (!response.ok) throw new Error('Download failed');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `C2Trap_Report_${new Date().toISOString().slice(0, 10)}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Report download error:', error);
        alert('Failed to download report. Check console for details.');
    } finally {
        if (btn) btn.classList.remove('spin-anim');
    }
}

// Expose functions globally
window.refreshData = () => refreshData(false);
window.switchView = switchView;
window.downloadReport = downloadReport;

