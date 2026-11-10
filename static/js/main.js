// SafeFS Global Application JavaScript

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  let icon = 'ℹ️';
  if (type === 'success') icon = '✓';
  if (type === 'error') icon = '⚠️';

  toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(50px)';
    setTimeout(() => toast.remove(), 400);
  }, 4500);
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
  }
}

// Close modal when clicking on dark backdrop
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.remove('active');
  }
});

// Update topbar pulse indicator
async function updateMonitoringStatusIndicator() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    
    const dot = document.getElementById('global-pulse-dot');
    const label = document.getElementById('global-monitor-status-text');
    
    if (dot && label) {
      if (data.monitor_status && data.monitor_status.is_running) {
        dot.className = 'pulse-dot';
        label.textContent = `Monitoring Active (${data.active_folders} Folders)`;
      } else {
        dot.className = 'pulse-dot danger';
        label.textContent = 'Monitoring Paused';
      }
    }
  } catch (err) {
    // Silent catch on network blip
  }
}

// Global Folder Addition Handler
async function handleAddMonitoredFolder(event) {
  event.preventDefault();
  const pathInput = document.getElementById('modal-folder-path');
  const labelInput = document.getElementById('modal-folder-label');

  if (!pathInput || !pathInput.value.trim()) {
    showToast('Please enter a valid directory path', 'error');
    return;
  }

  const payload = {
    path: pathInput.value.trim(),
    label: labelInput ? labelInput.value.trim() : ''
  };

  try {
    const res = await fetch('/api/folders/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (data.success) {
      showToast(data.message || 'Folder added successfully!', 'success');
      closeModal('add-folder-modal');
      pathInput.value = '';
      if (labelInput) labelInput.value = '';
      setTimeout(() => location.reload(), 1000);
    } else {
      showToast(data.error || 'Failed to add folder', 'error');
    }
  } catch (err) {
    showToast('Network error while adding folder', 'error');
  }
}

// Format utilities
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function truncateString(str, len = 12) {
  if (!str) return 'N/A';
  return str.length > len ? str.substring(0, len) + '...' : str;
}

// Init global periodic checks
document.addEventListener('DOMContentLoaded', () => {
  updateMonitoringStatusIndicator();
  setInterval(updateMonitoringStatusIndicator, 6000);
});
