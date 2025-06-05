/* InfoGather Web Dashboard JavaScript */

// Global variables
let dashboardCharts = {};
let refreshInterval = null;

// Utility functions
function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

function formatDuration(startTime, endTime) {
    if (!startTime || !endTime) return 'N/A';
    
    const start = new Date(startTime);
    const end = new Date(endTime);
    const duration = Math.floor((end - start) / 1000);
    
    if (duration < 60) return duration + 's';
    if (duration < 3600) return Math.floor(duration / 60) + 'm ' + (duration % 60) + 's';
    
    const hours = Math.floor(duration / 3600);
    const minutes = Math.floor((duration % 3600) / 60);
    return hours + 'h ' + minutes + 'm';
}

function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container-fluid');
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Dashboard specific functions
function initializeDashboard() {
    loadDashboardStats();
    
    // Set up auto-refresh
    refreshInterval = setInterval(loadDashboardStats, 30000);
}

function loadDashboardStats() {
    fetch('/api/dashboard_stats')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to load dashboard data');
            }
            return response.json();
        })
        .then(data => {
            updateDashboardStats(data);
        })
        .catch(error => {
            console.error('Error loading dashboard stats:', error);
        });
}

function updateDashboardStats(data) {
    // Update stat cards if they exist
    const totalScans = document.getElementById('total-scans');
    const completedScans = document.getElementById('completed-scans');
    const runningScans = document.getElementById('running-scans');
    const criticalFindings = document.getElementById('critical-findings');
    
    if (totalScans) totalScans.textContent = data.total_scans || 0;
    if (completedScans) completedScans.textContent = data.completed_scans || 0;
    if (runningScans) runningScans.textContent = data.running_scans || 0;
    if (criticalFindings) criticalFindings.textContent = data.critical_findings || 0;
    
    // Update recent scans if container exists
    const recentScansContainer = document.getElementById('recent-scans');
    if (recentScansContainer && data.recent_scans) {
        updateRecentScans(data.recent_scans);
    }
    
    // Update activity chart if container exists
    const chartContainer = document.getElementById('activity-chart');
    if (chartContainer && data.activity_data) {
        updateActivityChart(data.activity_data);
    }
    
    // Update findings overview if container exists
    const findingsContainer = document.getElementById('findings-overview');
    if (findingsContainer && data.findings_summary) {
        updateFindingsOverview(data.findings_summary);
    }
}

function updateRecentScans(scans) {
    const container = document.getElementById('recent-scans');
    
    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="fas fa-search fa-3x mb-3"></i>
                <p>No recent scans</p>
                <a href="/scan" class="btn btn-outline-primary">
                    Start Your First Scan
                </a>
            </div>
        `;
        return;
    }
    
    let html = '';
    scans.slice(0, 5).forEach(scan => {
        const statusClass = getStatusClass(scan.status);
        const timeAgo = getTimeAgo(scan.started_at);
        
        html += `
            <div class="d-flex justify-content-between align-items-center mb-3 p-3 border rounded hover-card">
                <div>
                    <strong>${scan.target}</strong>
                    <br>
                    <small class="text-muted">${timeAgo}</small>
                </div>
                <div class="text-end">
                    <span class="badge bg-${statusClass}">${scan.status}</span>
                    ${scan.status === 'completed' ? 
                        `<br><a href="/results/${scan.id}" class="btn btn-sm btn-outline-primary mt-1">View</a>` : 
                        ''}
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function updateActivityChart(data) {
    const canvas = document.getElementById('activity-chart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart if it exists
    if (dashboardCharts.activity) {
        dashboardCharts.activity.destroy();
    }
    
    dashboardCharts.activity = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'Scans per Day',
                data: data.values || [],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#e9ecef'
                    }
                },
                x: {
                    grid: {
                        color: '#e9ecef'
                    }
                }
            }
        }
    });
}

function updateFindingsOverview(findings) {
    const container = document.getElementById('findings-overview');
    
    if (!findings || Object.keys(findings).length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted py-4">
                <i class="fas fa-shield-alt fa-3x mb-3"></i>
                <p>No security findings yet</p>
                <small>Run scans to discover security issues</small>
            </div>
        `;
        return;
    }
    
    let html = '<div class="row">';
    
    const severityConfig = {
        critical: { color: 'danger', icon: 'exclamation-triangle' },
        high: { color: 'warning', icon: 'exclamation' },
        medium: { color: 'info', icon: 'info-circle' },
        low: { color: 'secondary', icon: 'minus-circle' }
    };
    
    Object.entries(findings).forEach(([severity, count]) => {
        if (count > 0) {
            const config = severityConfig[severity];
            html += `
                <div class="col-md-3 mb-3">
                    <div class="card border-${config.color}">
                        <div class="card-body text-center">
                            <i class="fas fa-${config.icon} fa-2x text-${config.color} mb-2"></i>
                            <h3 class="text-${config.color}">${count}</h3>
                            <p class="mb-0">${severity.charAt(0).toUpperCase() + severity.slice(1)}</p>
                        </div>
                    </div>
                </div>
            `;
        }
    });
    
    html += '</div>';
    container.innerHTML = html;
}

// Utility functions for status and time
function getStatusClass(status) {
    const statusMap = {
        'completed': 'success',
        'running': 'warning',
        'failed': 'danger',
        'pending': 'secondary'
    };
    return statusMap[status] || 'secondary';
}

function getTimeAgo(dateString) {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    
    return date.toLocaleDateString();
}

// Scan management functions
function startNewScan(targetId, portsId, modulesName) {
    const target = document.getElementById(targetId).value.trim();
    const ports = document.getElementById(portsId).value.trim();
    const modules = Array.from(document.querySelectorAll(`input[name="${modulesName}"]:checked`))
                         .map(cb => cb.value);
    
    if (!target) {
        showNotification('Please enter a target', 'warning');
        return false;
    }
    
    if (modules.length === 0) {
        showNotification('Please select at least one module', 'warning');
        return false;
    }
    
    const scanData = {
        target: target,
        ports: ports || '1-1000',
        modules: modules
    };
    
    return fetch('/api/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(scanData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showNotification('Error: ' + data.error, 'danger');
            return null;
        } else {
            showNotification('Scan started successfully', 'success');
            return data.scan_id;
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showNotification('Failed to start scan', 'danger');
        return null;
    });
}

function checkScanStatus(scanId) {
    return fetch(`/api/scan_status/${scanId}`)
        .then(response => response.json())
        .catch(error => {
            console.error('Error checking scan status:', error);
            return null;
        });
}

function getScanResults(scanId) {
    return fetch(`/api/scan_results/${scanId}`)
        .then(response => response.json())
        .catch(error => {
            console.error('Error getting scan results:', error);
            return null;
        });
}

function deleteScan(scanId) {
    return fetch(`/api/delete_scan/${scanId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .catch(error => {
        console.error('Error deleting scan:', error);
        return null;
    });
}

// Results page functions
function initializeResultsPage(scanId) {
    loadScanResults(scanId);
}

function loadScanResults(scanId) {
    getScanResults(scanId)
        .then(data => {
            if (data && !data.error) {
                displayScanResults(data);
            } else {
                showNotification('Failed to load scan results', 'danger');
            }
        });
}

function displayScanResults(results) {
    // This function would populate the results page
    // Implementation depends on the specific results template structure
    console.log('Displaying results:', results);
}

// Export functions
function exportReport(scanId, format) {
    const url = `/api/export_report/${scanId}?format=${format}`;
    window.open(url, '_blank');
}

// Search and filter functions
function initializeSearch(inputId, tableId) {
    const searchInput = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    
    if (!searchInput || !table) return;
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
        
        for (let row of rows) {
            const cells = row.getElementsByTagName('td');
            let matchFound = false;
            
            for (let cell of cells) {
                if (cell.textContent.toLowerCase().includes(searchTerm)) {
                    matchFound = true;
                    break;
                }
            }
            
            row.style.display = matchFound ? '' : 'none';
        }
    });
}

// Form validation
function validateScanForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    const target = form.querySelector('input[name="target"]').value.trim();
    const modules = form.querySelectorAll('input[name="modules"]:checked');
    
    if (!target) {
        showNotification('Please enter a target', 'warning');
        return false;
    }
    
    if (modules.length === 0) {
        showNotification('Please select at least one module', 'warning');
        return false;
    }
    
    return true;
}

// Module selection helpers
function selectAllModules() {
    document.querySelectorAll('input[name="modules"]').forEach(cb => {
        cb.checked = true;
    });
    updateEstimatedTime();
}

function selectCoreModules() {
    clearAllModules();
    ['network_scan', 'dns_enum', 'whois', 'ssl_analysis', 'vuln_scan'].forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox) checkbox.checked = true;
    });
    updateEstimatedTime();
}

function selectAdvancedModules() {
    clearAllModules();
    ['social_intel', 'advanced_dns', 'cloud_assets'].forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox) checkbox.checked = true;
    });
    updateEstimatedTime();
}

function clearAllModules() {
    document.querySelectorAll('input[name="modules"]').forEach(cb => {
        cb.checked = false;
    });
    updateEstimatedTime();
}

function updateEstimatedTime() {
    const estimatedTimeElement = document.getElementById('estimated-time');
    if (!estimatedTimeElement) return;
    
    const checkedModules = document.querySelectorAll('input[name="modules"]:checked');
    const moduleCount = checkedModules.length;
    
    if (moduleCount === 0) {
        estimatedTimeElement.textContent = 'Select modules to see estimate';
        return;
    }
    
    const timeEstimates = {
        network_scan: 5,
        dns_enum: 3,
        whois: 1,
        ssl_analysis: 2,
        vuln_scan: 8,
        social_intel: 10,
        advanced_dns: 7,
        cloud_assets: 12
    };
    
    let totalTime = 0;
    checkedModules.forEach(cb => {
        totalTime += timeEstimates[cb.value] || 5;
    });
    
    estimatedTimeElement.textContent = `Approximately ${totalTime} minutes`;
}

// Real-time updates for running scans
function startScanPolling(scanId, progressCallback) {
    const pollInterval = setInterval(() => {
        checkScanStatus(scanId)
            .then(data => {
                if (!data) {
                    clearInterval(pollInterval);
                    return;
                }
                
                if (progressCallback) {
                    progressCallback(data);
                }
                
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(pollInterval);
                }
            });
    }, 2000);
    
    return pollInterval;
}

// Cleanup function
function cleanup() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    // Destroy charts
    Object.values(dashboardCharts).forEach(chart => {
        if (chart && typeof chart.destroy === 'function') {
            chart.destroy();
        }
    });
}

// Initialize based on page
document.addEventListener('DOMContentLoaded', function() {
    // Check which page we're on and initialize accordingly
    const pathname = window.location.pathname;
    
    if (pathname === '/' || pathname === '/dashboard') {
        initializeDashboard();
    } else if (pathname.startsWith('/results/')) {
        const scanId = pathname.split('/')[2];
        if (scanId) {
            initializeResultsPage(scanId);
        }
    } else if (pathname === '/history') {
        initializeSearch('search-input', 'scans-table');
    }
    
    // Add module checkbox listeners if they exist
    const moduleCheckboxes = document.querySelectorAll('input[name="modules"]');
    if (moduleCheckboxes.length > 0) {
        moduleCheckboxes.forEach(cb => {
            cb.addEventListener('change', updateEstimatedTime);
        });
        updateEstimatedTime();
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', cleanup);