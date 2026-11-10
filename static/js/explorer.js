// SafeFS File Explorer & Integrity Management

let currentFiles = [];

async function loadFiles() {
  const folderSelect = document.getElementById('explorer-folder-filter');
  const searchInput = document.getElementById('explorer-search-input');
  const statusSelect = document.getElementById('explorer-status-filter');

  const folderId = folderSelect ? folderSelect.value : '';
  const search = searchInput ? searchInput.value.trim() : '';
  const status = statusSelect ? statusSelect.value : '';

  let url = `/api/files?`;
  if (folderId) url += `folder_id=${encodeURIComponent(folderId)}&`;
  if (search) url += `search=${encodeURIComponent(search)}&`;
  if (status) url += `status=${encodeURIComponent(status)}&`;

  try {
    const res = await fetch(url);
    if (!res.ok) return;
    currentFiles = await res.json();
    renderFileList(currentFiles);
  } catch (err) {
    console.error('Error loading files:', err);
  }
}

function renderFileList(files) {
  const tbody = document.getElementById('explorer-file-tbody');
  if (!tbody) return;

  if (files.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">No tracked files found. Add or scan a folder.</td></tr>`;
    return;
  }

  tbody.innerHTML = files.map(f => {
    let statusBadge = 'badge-success';
    if (f.status === 'MODIFIED') statusBadge = 'badge-info';
    if (f.status === 'DELETED') statusBadge = 'badge-danger';
    if (f.status === 'MISSING') statusBadge = 'badge-danger';

    const hashStr = f.sha256 ? `<span class="font-mono">${f.sha256.substring(0, 10)}...</span>` : 'Pending';

    return `
      <tr>
        <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(f.filename)}</td>
        <td><span class="badge badge-secondary">${escapeHtml(f.folder_label || 'Default')}</span></td>
        <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(truncateString(f.relative_path, 35))}</td>
        <td style="font-size:12px;">${formatBytes(f.size_bytes)}</td>
        <td>${hashStr}</td>
        <td><span class="badge ${statusBadge}">${f.status}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-outline btn-sm" onclick="verifyFileIntegrity(${f.id})" title="Verify SHA-256 Checksum">🛡️ Verify</button>
            <button class="btn btn-outline btn-sm" onclick="viewFileVersions(${f.id}, '${escapeHtml(f.filename)}')" title="View Versions">🕒 (${f.version_count || 0})</button>
            <button class="btn btn-outline btn-sm" onclick="previewFile(${f.id}, '${escapeHtml(f.filename)}')" title="Preview Content">👁️</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function verifyFileIntegrity(fileId) {
  try {
    showToast('Calculating live SHA-256 checksum...', 'info');
    const res = await fetch('/api/files/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_id: fileId })
    });
    const data = await res.json();
    if (data.status === 'VALID') {
      showToast(`Integrity Verified: ${data.message}`, 'success');
    } else {
      showToast(`Integrity Warning [${data.status}]: ${data.message}`, 'error');
    }
    loadFiles();
  } catch (err) {
    showToast('Integrity check request failed', 'error');
  }
}

async function verifyAllInFolder() {
  const folderSelect = document.getElementById('explorer-folder-filter');
  const folderId = folderSelect ? folderSelect.value : null;

  try {
    showToast('Verifying cryptographic integrity across all monitored files...', 'info');
    const res = await fetch('/api/files/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ folder_id: folderId ? parseInt(folderId) : null })
    });
    const data = await res.json();
    const c = data.counts || {};
    showToast(`Integrity Check Finished: ${c.VALID || 0} Valid, ${c.MODIFIED || 0} Modified, ${c.MISSING || 0} Missing`, 'info');
    loadFiles();
  } catch (err) {
    showToast('Folder verification failed', 'error');
  }
}

async function viewFileVersions(fileId, filename) {
  try {
    const res = await fetch(`/api/files/${fileId}/versions`);
    if (!res.ok) return;
    const versions = await res.json();

    const titleEl = document.getElementById('versions-modal-title');
    if (titleEl) titleEl.textContent = `Version Snapshots: ${filename}`;

    const tbody = document.getElementById('versions-modal-tbody');
    if (tbody) {
      if (versions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No snapshots captured for this file yet.</td></tr>`;
      } else {
        tbody.innerHTML = versions.map(v => `
          <tr>
            <td style="font-weight:700;">#${v.version_number}</td>
            <td><span class="badge badge-secondary">${v.change_type}</span></td>
            <td>${formatBytes(v.size_bytes)}</td>
            <td class="font-mono" style="font-size:11px;">${v.sha256.substring(0, 12)}...</td>
            <td style="font-size:12px; color:var(--text-muted);">${v.created_at}</td>
            <td>
              <div style="display:flex; gap:4px;">
                <button class="btn btn-outline btn-sm" onclick="showDiff(${v.id}, true)" title="Compare with Live File">Diff</button>
                <a href="/api/versions/download/${v.id}" class="btn btn-outline btn-sm" title="Download">⬇</a>
                <button class="btn btn-primary btn-sm" onclick="restoreVersion(${v.id}, ${v.version_number})" title="Restore with Safety Backup">Restore</button>
              </div>
            </td>
          </tr>
        `).join('');
      }
    }

    openModal('file-versions-modal');
  } catch (err) {
    showToast('Failed to load version history', 'error');
  }
}

async function restoreVersion(versionId, versionNumber) {
  if (!confirm(`Are you sure you want to restore Version #${versionNumber}?\n\nSafeFS OS Invariant: An automatic snapshot of the target file's current state will be safely preserved before overwriting.`)) {
    return;
  }

  try {
    showToast('Executing safe restoration with pre-restore snapshot...', 'info');
    const res = await fetch('/api/files/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version_id: versionId, reason: 'Restored from File Explorer UI' })
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message, 'success');
      closeModal('file-versions-modal');
      loadFiles();
    } else {
      showToast(data.error || 'Restoration failed', 'error');
    }
  } catch (err) {
    showToast('Restoration request failed', 'error');
  }
}

async function previewFile(fileId, filename) {
  try {
    const res = await fetch(`/api/files/preview?file_id=${fileId}`);
    const data = await res.json();

    const titleEl = document.getElementById('preview-modal-title');
    if (titleEl) titleEl.textContent = `File Preview: ${filename}`;

    const contentEl = document.getElementById('preview-modal-content');
    if (contentEl) contentEl.textContent = data.content || '[Empty File]';

    openModal('file-preview-modal');
  } catch (err) {
    showToast('Failed to load file preview', 'error');
  }
}

async function showDiff(versionId, vsCurrent = true) {
  try {
    const res = await fetch(`/api/versions/diff?v1_id=${versionId}&current_file=${vsCurrent}`);
    const data = await res.json();

    const titleEl = document.getElementById('diff-modal-title');
    if (titleEl) titleEl.textContent = `File Difference (${data.v1_label} vs ${data.v2_label})`;

    const container = document.getElementById('diff-modal-content');
    if (container) {
      const lines = (data.diff || '').split('\n');
      container.innerHTML = lines.map(line => {
        let cls = '';
        if (line.startsWith('+') && !line.startsWith('+++')) cls = 'diff-add';
        else if (line.startsWith('-') && !line.startsWith('---')) cls = 'diff-del';
        else if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) cls = 'diff-hdr';
        return `<span class="${cls}">${escapeHtml(line)}</span>`;
      }).join('\n');
    }

    openModal('diff-viewer-modal');
  } catch (err) {
    showToast('Failed to calculate diff', 'error');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

document.addEventListener('DOMContentLoaded', () => {
  loadFiles();
});
