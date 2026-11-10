// SafeFS Dashboard Visualizations & Live Telemetry

let eventChart = null;
let threatChart = null;

async function fetchDashboardStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();

    // Update Numerical Stat Counters
    const updateEl = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : 0;
    };

    updateEl('stat-total-files', data.total_files);
    updateEl('stat-active-folders', data.active_folders);
    updateEl('stat-modified-files', data.modified_files);
    updateEl('stat-deleted-files', data.deleted_files);
    updateEl('stat-active-threats', data.active_threats);
    updateEl('stat-total-versions', data.total_versions);

    // Update Charts
    updateCharts(data.event_distribution, data.threat_distribution);

    // Update Recent Activities Table
    updateRecentActivities(data.recent_activities);

  } catch (err) {
    console.error('Error fetching dashboard stats:', err);
  }
}

function initCharts() {
  // 1. Event Distribution Doughnut Chart
  const eventCtx = document.getElementById('eventDistributionChart');
  if (eventCtx) {
    eventChart = new Chart(eventCtx, {
      type: 'doughnut',
      data: {
        labels: ['CREATED', 'MODIFIED', 'DELETED', 'MOVED', 'RESTORED'],
        datasets: [{
          data: [0, 0, 0, 0, 0],
          backgroundColor: ['#05d69e', '#00d2ff', '#ff477e', '#ffbe0b', '#7952ff'],
          borderWidth: 1,
          borderColor: '#101522'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
          }
        },
        cutout: '70%'
      }
    });
  }

  // 2. Threat Severity Bar Chart
  const threatCtx = document.getElementById('threatSeverityChart');
  if (threatCtx) {
    threatChart = new Chart(threatCtx, {
      type: 'bar',
      data: {
        labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        datasets: [{
          label: 'Alerts',
          data: [0, 0, 0, 0],
          backgroundColor: ['#3a86ff', '#ffbe0b', '#ff7a00', '#ff477e'],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#64748b' }, grid: { display: false } },
          y: { ticks: { color: '#64748b', precision: 0 }, grid: { color: '#232d45' } }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

function updateCharts(eventDist = {}, threatDist = {}) {
  if (eventChart) {
    const labels = ['CREATED', 'MODIFIED', 'DELETED', 'MOVED', 'RESTORED'];
    const values = labels.map(l => eventDist[l] || 0);
    eventChart.data.datasets[0].data = values;
    eventChart.update();
  }

  if (threatChart) {
    const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const values = severities.map(s => threatDist[s] || 0);
    threatChart.data.datasets[0].data = values;
    threatChart.update();
  }
}

function updateRecentActivities(activities) {
  const tbody = document.getElementById('recent-activities-body');
  if (!tbody || !activities) return;

  if (activities.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">No file events recorded yet. Add a folder to begin monitoring.</td></tr>`;
    return;
  }

  tbody.innerHTML = activities.map(act => {
    let badgeClass = 'badge-secondary';
    if (act.event_type === 'CREATED') badgeClass = 'badge-success';
    if (act.event_type === 'MODIFIED') badgeClass = 'badge-info';
    if (act.event_type === 'DELETED') badgeClass = 'badge-danger';
    if (act.event_type === 'MOVED') badgeClass = 'badge-warning';
    if (act.event_type === 'RESTORED') badgeClass = 'badge-success';

    const hashDisplay = act.new_hash ? `<span class="font-mono">${act.new_hash.substring(0, 8)}...</span>` : '-';
    
    return `
      <tr>
        <td><span class="badge ${badgeClass}">${act.event_type}</span></td>
        <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(act.filename || '-')}</td>
        <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(truncateString(act.file_path, 40))}</td>
        <td>${hashDisplay}</td>
        <td style="color: var(--text-muted); font-size: 12px;">${act.timestamp}</td>
      </tr>
    `;
  }).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  fetchDashboardStats();
  // Poll stats every 4 seconds for live dashboard view
  setInterval(fetchDashboardStats, 4000);
});
