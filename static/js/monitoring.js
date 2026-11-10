// SafeFS Real-time Monitoring Stream Controller

let isLiveStreaming = true;
let eventFilter = 'ALL';

async function fetchLiveEvents() {
  if (!isLiveStreaming) return;

  try {
    const res = await fetch('/api/events/live?limit=50');
    if (!res.ok) return;
    const data = await res.json();
    renderLiveEvents(data.events || []);
  } catch (err) {
    console.error('Error fetching live events:', err);
  }
}

function renderLiveEvents(events) {
  const tbody = document.getElementById('live-events-tbody');
  if (!tbody) return;

  const filtered = events.filter(e => {
    if (eventFilter === 'ALL') return true;
    return e.event_type === eventFilter;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 32px; color: var(--text-muted);">No matching real-time events in buffer.</td></tr>`;
    return;
  }

  // Display newest first
  filtered.reverse();

  tbody.innerHTML = filtered.map(evt => {
    let badgeClass = 'badge-secondary';
    if (evt.event_type === 'CREATED') badgeClass = 'badge-success';
    if (evt.event_type === 'MODIFIED') badgeClass = 'badge-info';
    if (evt.event_type === 'DELETED') badgeClass = 'badge-danger';
    if (evt.event_type === 'MOVED') badgeClass = 'badge-warning';

    const hashStr = evt.hash ? `<span class="font-mono">${evt.hash.substring(0, 10)}...</span>` : 'N/A';

    return `
      <tr>
        <td><span class="badge ${badgeClass}">${evt.event_type}</span></td>
        <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(evt.filename)}</td>
        <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(evt.file_path)}</td>
        <td>${hashStr}</td>
        <td style="font-size: 12px; color: var(--text-secondary);">${evt.timestamp}</td>
      </tr>
    `;
  }).join('');
}

function toggleStream() {
  isLiveStreaming = !isLiveStreaming;
  const btn = document.getElementById('toggle-stream-btn');
  if (btn) {
    if (isLiveStreaming) {
      btn.innerHTML = '<span>⏸</span> Pause Stream';
      btn.className = 'btn btn-outline btn-sm';
      showToast('Live stream resumed', 'info');
      fetchLiveEvents();
    } else {
      btn.innerHTML = '<span>▶</span> Resume Stream';
      btn.className = 'btn btn-primary btn-sm';
      showToast('Live stream paused', 'info');
    }
  }
}

async function toggleMonitorEngine() {
  try {
    const statusRes = await fetch('/api/stats');
    const stats = await statusRes.json();
    const currentlyRunning = stats.monitor_status && stats.monitor_status.is_running;

    const res = await fetch('/api/monitor/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enable: !currentlyRunning })
    });

    const data = await res.json();
    showToast(data.message, data.is_running ? 'success' : 'info');
    
    const engineBtn = document.getElementById('engine-toggle-btn');
    if (engineBtn) {
      engineBtn.textContent = data.is_running ? 'Pause Engine' : 'Resume Engine';
    }
    updateMonitoringStatusIndicator();
  } catch (err) {
    showToast('Failed to toggle monitor engine', 'error');
  }
}

function filterEvents(type) {
  eventFilter = type;
  document.querySelectorAll('.filter-chip').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-type') === type);
  });
  fetchLiveEvents();
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

document.addEventListener('DOMContentLoaded', () => {
  fetchLiveEvents();
  setInterval(fetchLiveEvents, 2000);
});
