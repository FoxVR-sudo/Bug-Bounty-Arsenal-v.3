/**
 * Scan Form Handler for BugBounty Arsenal
 * Handles scan form submissions and real-time status updates
 */

// Initialize API client
const api = new BugBountyAPI();

// Store active scans
let activeScans = new Map();
let statusPollInterval = null;

/**
 * Start scan from form submission
 */
async function startScan(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    
    try {
        // Disable button
        submitBtn.disabled = true;
        submitBtn.textContent = '🔄 Starting scan...';
        
        // Get form data
        const target = form.querySelector('#target').value.trim();
        const scanType = getScanType();
        
        if (!target) {
            throw new Error('Please enter a target URL');
        }
        
        // Get scan options based on page
        const options = getScanOptions(form);
        
        // Start scan via API
        const result = await api.startScan(target, scanType, options);
        
        // Show success message
        showNotification('✅ Scan started successfully!', 'success');
        
        // Show scan results section
        const resultsSection = document.getElementById('scanResults');
        if (resultsSection) {
            resultsSection.classList.add('active');
        }
        
        // Add to active scans
        activeScans.set(result.id, {
            id: result.id,
            target: result.target,
            scan_type: result.scan_type,
            status: result.status,
            started_at: result.started_at,
            progress: 0
        });
        
        // Store current scan ID for progress tracking
        window.currentScanId = result.id;
        
        // Clear form
        form.reset();
        
        // Start polling for status updates and progress
        startStatusPolling();
        startProgressPolling(result.id);
        
        // Update scan list
        await updateScanList();
        
    } catch (error) {
        console.error('Scan start error:', error);
        showNotification('❌ ' + error.message, 'error');
    } finally {
        // Re-enable button
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

/**
 * Get scan type based on current page
 */
function getScanType() {
    const path = window.location.pathname;
    
    // New 5 main scanner URLs
    if (path.includes('/scan/reconnaissance')) return 'reconnaissance';
    if (path.includes('/scan/web')) return 'web_security';
    if (path.includes('/scan/api')) return 'api_security';
    if (path.includes('/scan/mobile')) return 'mobile_security';
    if (path.includes('/scan/comprehensive')) return 'comprehensive';
    
    // Old dashboard URLs (backward compatibility)
    if (path.includes('/api-scan/')) return 'api_security';
    if (path.includes('/vulnerability-scan/')) return 'vulnerability';
    if (path.includes('/mobile-scan/')) return 'mobile';
    if (path.includes('/custom-scan/')) return 'custom';
    if (path.includes('/passive-scan/')) return 'passive';
    
    return 'web_security'; // Default
}

/**
 * Get scan options from form
 */
function getScanOptions(form) {
    const options = {};
    
    // Get scan mode
    const scanModeEl = form.querySelector('#scanMode');
    if (scanModeEl) {
        options.scan_mode = scanModeEl.value;
    }
    
    // Get authentication if present
    const authTypeEl = form.querySelector('#authType');
    if (authTypeEl && authTypeEl.value !== 'none') {
        options.auth_type = authTypeEl.value;
        
        const authValueEl = form.querySelector('#authValue');
        if (authValueEl) {
            options.auth_value = authValueEl.value;
        }
    }
    
    // Get custom headers if present
    const customHeadersEl = form.querySelector('#customHeaders');
    if (customHeadersEl && customHeadersEl.value) {
        try {
            options.custom_headers = JSON.parse(customHeadersEl.value);
        } catch (e) {
            console.warn('Invalid JSON in custom headers');
        }
    }
    
    // Get detectors
    const detectors = [];
    form.querySelectorAll('input[type="checkbox"][data-detector]').forEach(checkbox => {
        if (checkbox.checked) {
            detectors.push(checkbox.dataset.detector);
        }
    });
    if (detectors.length > 0) {
        options.detectors = detectors;
    }
    
    // Get concurrency
    const concurrencyEl = form.querySelector('#concurrency');
    if (concurrencyEl) {
        options.concurrency = parseInt(concurrencyEl.value, 10);
    }
    
    // Get timeout
    const timeoutEl = form.querySelector('#timeout');
    if (timeoutEl) {
        options.timeout = parseInt(timeoutEl.value, 10);
    }
    
    return options;
}

/**
 * Update scan list table
 */
async function updateScanList() {
    try {
        const scans = await api.getScanStatus();
        
        const tbody = document.querySelector('table tbody');
        if (!tbody) return;
        
        if (scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; padding: 2rem; color: #6c757d;">
                        No scans yet. Start your first scan above.
                    </td>
                </tr>
            `;
            return;
        }
        
        // Show only recent 10 scans
        const recentScans = scans.slice(0, 10);
        
        tbody.innerHTML = recentScans.map(scan => {
            const statusEmoji = getStatusEmoji(scan.status);
            const statusClass = getStatusClass(scan.status);
            const timeAgo = getTimeAgo(scan.started_at);
            
            return `
                <tr>
                    <td>
                        <a href="/dashboard/results/?scan=${scan.id}" style="color: var(--primary); text-decoration: none;">
                            ${escapeHtml(scan.target)}
                        </a>
                    </td>
                    <td>
                        <span class="status-badge ${statusClass}">
                            ${statusEmoji} ${capitalize(scan.status)}
                        </span>
                    </td>
                    <td>
                        ${scan.vulnerabilities_found !== null ? 
                            `<strong>${scan.vulnerabilities_found}</strong> found` : 
                            '<span style="color: #6c757d;">Pending</span>'}
                    </td>
                    <td style="color: #6c757d; font-size: 0.875rem;">
                        ${timeAgo}
                    </td>
                </tr>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Failed to update scan list:', error);
    }
}

/**
 * Start polling for scan status
 */
function startStatusPolling() {
    if (statusPollInterval) return;
    
    // Poll every 5 seconds
    statusPollInterval = setInterval(async () => {
        await updateScanList();
    }, 5000);
}

/**
 * Stop polling for scan status
 */
function stopStatusPolling() {
    if (statusPollInterval) {
        clearInterval(statusPollInterval);
        statusPollInterval = null;
    }
}

/**
 * Get status emoji
 */
function getStatusEmoji(status) {
    const emojis = {
        'pending': '⏳',
        'running': '🔄',
        'completed': '✅',
        'failed': '❌',
        'cancelled': '⛔'
    };
    return emojis[status] || '❓';
}

/**
 * Get status CSS class
 */
function getStatusClass(status) {
    const classes = {
        'pending': 'status-pending',
        'running': 'status-running',
        'completed': 'status-completed',
        'failed': 'status-failed',
        'cancelled': 'status-cancelled'
    };
    return classes[status] || '';
}

/**
 * Get time ago string
 */
function getTimeAgo(timestamp) {
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Check if notification container exists
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; max-width: 400px;';
        document.body.appendChild(container);
    }
    
    // Create notification
    const notification = document.createElement('div');
    notification.style.cssText = `
        background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#007bff'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin-bottom: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        animation: slideInRight 0.3s ease-out;
    `;
    notification.textContent = message;
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

/**
 * Capitalize first letter
 */
function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Attach form handler
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', startScan);
    }
    
    // Load initial scan list
    updateScanList();
    
    // Start polling
    startStatusPolling();
    
    // Stop polling when page is hidden
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopStatusPolling();
        } else {
            startStatusPolling();
        }
    });
});

// Add CSS animation styles
const style = document.createElement('style');
style.textContent = `
@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes slideOutRight {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
}

.status-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.875rem;
    font-weight: 500;
}

.status-pending {
    background: #fff3cd;
    color: #856404;
}

.status-running {
    background: #d1ecf1;
    color: #0c5460;
}

.status-completed {
    background: #d4edda;
    color: #155724;
}

.status-failed {
    background: #f8d7da;
    color: #721c24;
}

.status-cancelled {
    background: #e2e3e5;
    color: #383d41;
}
`;
document.head.appendChild(style);

// Progress polling variables
let progressPollInterval = null;

/**
 * Start polling for scan progress
 */
function startProgressPolling(scanId) {
    if (progressPollInterval) return;
    
    // Poll every 2 seconds for real-time updates
    progressPollInterval = setInterval(async () => {
        await updateScanProgress(scanId);
    }, 2000);
    
    // Initial update
    updateScanProgress(scanId);
}

/**
 * Stop progress polling
 */
function stopProgressPolling() {
    if (progressPollInterval) {
        clearInterval(progressPollInterval);
        progressPollInterval = null;
    }
}

/**
 * Update scan progress UI
 */
async function updateScanProgress(scanId) {
    try {
        // Get scan status from API
        const response = await api.getScanDetails(scanId);
        
        if (!response) return;
        
        // Update progress bar
        const progress = response.progress || 0;
        const progressBar = document.getElementById('progressBar');
        const progressPercentage = document.getElementById('progressPercentage');
        
        if (progressBar && progressPercentage) {
            progressBar.style.width = progress + '%';
            progressPercentage.textContent = Math.round(progress) + '%';
            
            if (progress > 5) {
                progressBar.textContent = Math.round(progress) + '%';
            }
        }
        
        // Update current detector
        const currentDetector = document.getElementById('currentDetector');
        if (currentDetector && response.current_detector) {
            currentDetector.innerHTML = `<span style="color: var(--primary-blue);">🔍</span> Running: <strong>${formatDetectorName(response.current_detector)}</strong>`;
        }
        
        // Update active processes
        const processList = document.getElementById('processList');
        if (processList && response.active_detectors && response.active_detectors.length > 0) {
            processList.innerHTML = response.active_detectors.map(detector => `
                <div style="background: var(--card-bg); padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.85rem;">
                    <span style="color: var(--primary-blue);">⚡</span> ${formatDetectorName(detector)}
                </div>
            `).join('');
        } else if (processList && progress > 0 && progress < 100) {
            processList.innerHTML = '<div style="color: var(--text-secondary);">Initializing...</div>';
        }
        
        // Update status indicator
        const statusIndicator = document.getElementById('statusIndicator');
        const statusText = document.getElementById('statusText');
        
        if (response.status === 'completed') {
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator completed';
            }
            if (statusText) {
                statusText.textContent = '✅ Scan Completed';
            }
            stopProgressPolling();
            
            // Load final results
            await loadScanResults(scanId);
            
        } else if (response.status === 'failed') {
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator failed';
            }
            if (statusText) {
                statusText.textContent = '❌ Scan Failed';
            }
            stopProgressPolling();
            
        } else if (response.status === 'running') {
            if (statusText) {
                statusText.textContent = '🔄 Scanning... (' + Math.round(progress) + '%)';
            }
        }
        
        // Update vulnerability counts if available
        if (response.vulnerabilities_found !== undefined) {
            updateVulnerabilityCounts(response.vulnerabilities);
        }
        
    } catch (error) {
        console.error('Failed to update progress:', error);
    }
}

/**
 * Format detector name for display
 */
function formatDetectorName(detector) {
    return detector
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Update vulnerability counts in info boxes
 */
function updateVulnerabilityCounts(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) return;

    const infoBoxes = document.getElementById('infoBoxes');
    if (infoBoxes) infoBoxes.style.display = 'flex';

    const counts = {
        total:    vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high:     vulnerabilities.filter(v => v.severity === 'high').length,
        medium:   vulnerabilities.filter(v => v.severity === 'medium').length,
        low:      vulnerabilities.filter(v => v.severity === 'low').length,
        info:     vulnerabilities.filter(v => v.severity === 'info').length,
    };

    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('totalVulns',    counts.total);
    set('criticalSeverity', counts.critical);
    set('highSeverity',  counts.high);
    set('mediumSeverity',counts.medium);
    set('lowSeverity',   counts.low);
    set('infoSeverity',  counts.info);
}

/**
 * Render a single detailed vulnerability card
 */
function renderVulnCard(vuln) {
    const sev = (vuln.severity || 'info').toLowerCase();
    const sevColors = {
        critical: '#ff2d55', high: '#ff4757', medium: '#ffa502',
        low: '#00b4d8', info: '#6c757d'
    };
    const sevColor = sevColors[sev] || sevColors.info;

    const uid = 'vuln_' + (vuln.id || Math.random().toString(36).slice(2));

    // Meta row: detector + confidence + status + response time
    const metaParts = [];
    if (vuln.detector)       metaParts.push(`<span class="vuln-tag tag-detector">🔍 ${escapeHtml(formatDetectorName(vuln.detector))}</span>`);
    if (vuln.confidence)     metaParts.push(`<span class="vuln-tag tag-confidence">⚡ ${escapeHtml(vuln.confidence)} confidence</span>`);
    if (vuln.status_code)    metaParts.push(`<span class="vuln-tag tag-status">HTTP ${vuln.status_code}</span>`);
    if (vuln.response_time)  metaParts.push(`<span class="vuln-tag tag-time">⏱ ${vuln.response_time}ms</span>`);
    if (vuln.cvss_score > 0) metaParts.push(`<span class="vuln-tag tag-cvss">CVSS ${vuln.cvss_score}</span>`);
    if (vuln.is_verified)    metaParts.push(`<span class="vuln-tag tag-verified">✅ Verified</span>`);
    if (vuln.needs_verification) metaParts.push(`<span class="vuln-tag tag-unverified">⚠️ Needs verification</span>`);

    // Evidence block
    const evidenceHtml = vuln.evidence ? `
        <div style="margin-top:0.75rem;">
            <button class="collapsible-btn" onclick="toggleCollapsible('${uid}_evidence')">
                📄 Evidence <span style="opacity:0.6;font-size:0.8rem;">(click to expand)</span>
            </button>
            <div id="${uid}_evidence" class="collapsible-content" style="display:none;">
                <pre class="detail-pre">${escapeHtml(vuln.evidence)}</pre>
            </div>
        </div>` : '';

    // Payload block
    const payloadHtml = vuln.payload ? `
        <div style="margin-top:0.5rem;">
            <strong style="font-size:0.85rem;color:var(--text-secondary);">Payload:</strong>
            <code class="inline-code">${escapeHtml(vuln.payload)}</code>
        </div>` : '';

    // Request headers block
    const reqHeaders = vuln.request_headers && Object.keys(vuln.request_headers).length > 0;
    const reqHtml = reqHeaders ? `
        <div style="margin-top:0.75rem;">
            <button class="collapsible-btn" onclick="toggleCollapsible('${uid}_req')">
                📤 Request Headers
            </button>
            <div id="${uid}_req" class="collapsible-content" style="display:none;">
                <pre class="detail-pre">${escapeHtml(headersToString(vuln.request_headers))}</pre>
            </div>
        </div>` : '';

    // Response headers block
    const resHeaders = vuln.response_headers && Object.keys(vuln.response_headers).length > 0;
    const resHtml = resHeaders ? `
        <div style="margin-top:0.75rem;">
            <button class="collapsible-btn" onclick="toggleCollapsible('${uid}_res')">
                📥 Response Headers
            </button>
            <div id="${uid}_res" class="collapsible-content" style="display:none;">
                <pre class="detail-pre">${escapeHtml(headersToString(vuln.response_headers))}</pre>
            </div>
        </div>` : '';

    // Notes
    const notesHtml = vuln.notes ? `
        <div style="margin-top:0.75rem;padding:0.75rem;background:rgba(255,165,0,0.08);border-radius:6px;border-left:3px solid #ffa502;">
            <strong style="font-size:0.85rem;">📝 Notes:</strong>
            <p style="margin:0.25rem 0 0;font-size:0.875rem;">${escapeHtml(vuln.notes)}</p>
        </div>` : '';

    return `
    <div class="vulnerability-item ${sev}" style="border-left:4px solid ${sevColor};">
        <div class="vulnerability-header">
            <h4 class="vulnerability-title">${escapeHtml(vuln.title || vuln.type || 'Finding')}</h4>
            <span class="severity-badge ${sev}" style="background:${sevColor}22;color:${sevColor};">${sev.toUpperCase()}</span>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem;margin-bottom:0.75rem;">${metaParts.join('')}</div>
        <p class="vulnerability-description">${escapeHtml(vuln.description || 'No description provided.')}</p>
        ${vuln.url ? `<p style="font-size:0.85rem;color:var(--text-secondary);word-break:break-all;"><strong>URL:</strong> <a href="${escapeHtml(vuln.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--primary-blue);">${escapeHtml(vuln.url)}</a></p>` : ''}
        ${payloadHtml}
        ${evidenceHtml}
        ${reqHtml}
        ${resHtml}
        ${notesHtml}
    </div>`;
}

/**
 * Render pre_scan results (subfinder / amass subdomains)
 */
function renderPreScanSection(rawResults) {
    if (!rawResults || !rawResults.pre_scan) return '';
    const ps = rawResults.pre_scan;
    if (!ps.subdomains || ps.subdomains.length === 0) return '';

    const tools = ps.tools || {};
    const toolSummary = Object.entries(tools).map(([name, info]) => {
        const ok = info.ok ? '✅' : '❌';
        return `<span class="vuln-tag tag-detector">${ok} ${name}: ${info.count || 0} found</span>`;
    }).join(' ');

    const subList = ps.subdomains.slice(0, 100).map(s =>
        `<div style="font-family:monospace;font-size:0.85rem;padding:0.2rem 0;border-bottom:1px solid var(--border-color);">${escapeHtml(s)}</div>`
    ).join('');
    const more = ps.subdomains.length > 100 ? `<p style="color:var(--text-secondary);font-size:0.85rem;">...and ${ps.subdomains.length - 100} more</p>` : '';

    return `
    <div style="background:var(--darker-bg);border:1px solid var(--border-color);border-radius:8px;padding:1.25rem;margin-bottom:1.5rem;">
        <h4 style="margin-bottom:0.75rem;">🗺️ Pre-Scan: Subdomain Enumeration</h4>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem;margin-bottom:0.75rem;">${toolSummary}</div>
        <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:0.75rem;">
            ${ps.subdomains.length} unique subdomains discovered for <strong>${escapeHtml(ps.domain || '')}</strong>
        </p>
        <button class="collapsible-btn" onclick="toggleCollapsible('prescan_subs')">
            📋 Show all subdomains (${ps.subdomains.length})
        </button>
        <div id="prescan_subs" class="collapsible-content" style="display:none;margin-top:0.75rem;max-height:300px;overflow-y:auto;">
            ${subList}${more}
        </div>
    </div>`;
}

/**
 * Toggle a collapsible section
 */
function toggleCollapsible(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

/**
 * Convert headers object to readable string
 */
function headersToString(headers) {
    if (!headers || typeof headers !== 'object') return '';
    return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
}

/**
 * Load and display final scan results — full detailed view
 */
async function loadScanResults(scanId) {
    try {
        const response = await api.getScanDetails(scanId);
        if (!response) return;

        const resultsContent = document.getElementById('resultsContent');
        if (!resultsContent) return;

        // Inject collapsible styles once
        if (!document.getElementById('collapsible-styles')) {
            const s = document.createElement('style');
            s.id = 'collapsible-styles';
            s.textContent = `
                .collapsible-btn {
                    background: var(--darker-bg);
                    border: 1px solid var(--border-color);
                    color: var(--text-secondary);
                    padding: 0.3rem 0.75rem;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 0.85rem;
                    transition: background 0.15s;
                }
                .collapsible-btn:hover { background: var(--card-bg); color: var(--text-primary); }
                .detail-pre {
                    background: var(--dark-bg);
                    border: 1px solid var(--border-color);
                    border-radius: 6px;
                    padding: 0.75rem;
                    font-size: 0.8rem;
                    overflow-x: auto;
                    white-space: pre-wrap;
                    word-break: break-all;
                    margin-top: 0.4rem;
                    max-height: 300px;
                    overflow-y: auto;
                }
                .inline-code {
                    background: var(--dark-bg);
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    padding: 0.15rem 0.4rem;
                    font-size: 0.82rem;
                    font-family: monospace;
                    word-break: break-all;
                }
                .vuln-tag {
                    display: inline-block;
                    padding: 0.15rem 0.55rem;
                    border-radius: 12px;
                    font-size: 0.78rem;
                    font-weight: 500;
                }
                .tag-detector  { background: rgba(0,180,216,0.12); color: var(--primary-blue); }
                .tag-confidence{ background: rgba(0,208,132,0.12); color: #00d084; }
                .tag-status    { background: rgba(255,165,0,0.12);  color: #ffa502; }
                .tag-time      { background: rgba(108,117,125,0.15);color: var(--text-secondary); }
                .tag-cvss      { background: rgba(255,45,85,0.12);  color: #ff2d55; }
                .tag-verified  { background: rgba(0,208,132,0.15);  color: #00d084; }
                .tag-unverified{ background: rgba(255,165,0,0.15);  color: #ffa502; }
                .results-filter-bar { display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:1.5rem; }
                .filter-btn { padding:0.35rem 0.9rem; border-radius:20px; border:1px solid var(--border-color);
                    background:transparent; color:var(--text-secondary); cursor:pointer; font-size:0.85rem;
                    transition:all 0.15s; }
                .filter-btn.active, .filter-btn:hover { background:var(--primary-blue); color:#fff; border-color:var(--primary-blue); }
            `;
            document.head.appendChild(s);
        }

        const vulns = response.vulnerabilities || [];
        updateVulnerabilityCounts(vulns);

        // Build severity filter bar
        const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'];
        const filterBar = `
            <div class="results-filter-bar" id="severityFilterBar">
                ${severities.map((s, i) => `
                    <button class="filter-btn ${i === 0 ? 'active' : ''}" onclick="filterResults('${s}', this)">
                        ${s === 'all' ? 'All (' + vulns.length + ')' : s.charAt(0).toUpperCase() + s.slice(1) + ' (' + vulns.filter(v => v.severity === s).length + ')'}
                    </button>`).join('')}
            </div>`;

        // Pre-scan section (subfinder/amass)
        const preScanHtml = renderPreScanSection(response.raw_results);

        if (vulns.length === 0) {
            resultsContent.innerHTML = preScanHtml + `
                <div style="text-align:center;padding:3rem;color:var(--text-secondary);">
                    <div style="font-size:3rem;margin-bottom:1rem;">✅</div>
                    <h3>No Vulnerabilities Found</h3>
                    <p>The target appears to be secure based on the selected detectors.</p>
                </div>`;
        } else {
            const cardsHtml = vulns.map(renderVulnCard).join('');
            resultsContent.innerHTML = preScanHtml + filterBar + `
                <div id="vulnCardContainer">
                    <h3 style="margin-bottom:1.25rem;">Findings (${vulns.length})</h3>
                    ${cardsHtml}
                </div>`;
        }

    } catch (error) {
        console.error('Failed to load results:', error);
    }
}

/**
 * Filter vulnerability cards by severity
 */
function filterResults(severity, btn) {
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    // Show/hide cards
    document.querySelectorAll('.vulnerability-item').forEach(card => {
        if (severity === 'all') {
            card.style.display = '';
        } else {
            const cardSev = [...card.classList].find(c =>
                ['critical','high','medium','low','info'].includes(c)
            );
            card.style.display = cardSev === severity ? '' : 'none';
        }
    });
}

