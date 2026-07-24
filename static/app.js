const connectBtn = document.getElementById('connectBtn');
const statusEl = document.getElementById('status');
const outputEl = document.getElementById('output');
const tokenInput = document.getElementById('token');
const fileListEl = document.getElementById('fileList');
const currentPathText = document.getElementById('currentPathText');
const commandForm = document.getElementById('commandForm');
const commandInput = document.getElementById('commandInput');
const commandBtn = document.getElementById('commandBtn');
const upBtn = document.getElementById('upBtn');
const refreshBtn = document.getElementById('refreshBtn');
const contextMenu = document.getElementById('contextMenu');
const editorPanel = document.getElementById('editorPanel');
const editorTitle = document.getElementById('editorTitle');
const editorPath = document.getElementById('editorPath');
const fileEditor = document.getElementById('fileEditor');
const saveFileBtn = document.getElementById('saveFileBtn');
const closeEditorBtn = document.getElementById('closeEditorBtn');

let ws;
let serverPublicKey;
let rootDir = '';
let pathSeparator = '/';
let currentPath = '';
let selectedEntry = null;
let contextEntry = null;
let pendingResponse = null;
let currentEntries = [];
let sortState = {
	key: 'name',
	direction: 'asc',
};
let openEditorPath = '';
let socketReady = false;

connectBtn.addEventListener('click', connectSocket);
upBtn.addEventListener('click', goUp);
refreshBtn.addEventListener('click', () => loadDirectory(currentPath));
commandForm.addEventListener('submit', runTypedCommand);
saveFileBtn.addEventListener('click', saveOpenFile);
closeEditorBtn.addEventListener('click', closeEditor);

fileListEl.addEventListener('click', (event) => {
	const sortButton = event.target.closest('[data-sort-key]');
	if (sortButton) {
		setSort(sortButton.dataset.sortKey);
		return;
	}

  const row = event.target.closest('.file-row');
  hideContextMenu();
  if (!row) {
    selectEntry(null);
    return;
  }
  selectEntry(entryFromRow(row));
});

fileListEl.addEventListener('dblclick', (event) => {
  const row = event.target.closest('.file-row');
  if (!row) {
    return;
  }
  const entry = entryFromRow(row);
  if (entry.isDir) {
    loadDirectory(joinPath(currentPath, entry.name));
  }
});

fileListEl.addEventListener('contextmenu', (event) => {
  event.preventDefault();
  const row = event.target.closest('.file-row');
  contextEntry = row ? entryFromRow(row) : null;
  selectEntry(contextEntry);
  showContextMenu(event.clientX, event.clientY, contextEntry);
});

contextMenu.addEventListener('click', (event) => {
  const action = event.target.dataset.menuAction;
  if (!action) {
    return;
  }
  hideContextMenu();
  runMenuAction(action);
});

document.addEventListener('click', (event) => {
  if (!contextMenu.contains(event.target)) {
    hideContextMenu();
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    hideContextMenu();
  }
  if (event.key === 'F2' && selectedEntry) {
    event.preventDefault();
    renameEntry(selectedEntry);
  }
  if (event.key === 'Delete' && selectedEntry) {
    event.preventDefault();
    deleteEntry(selectedEntry);
  }
});

async function connectSocket() {
  const token = tokenInput.value.trim();
  if (!token) {
    showOutput('Enter a JWT token before connecting.');
    return;
  }
  if (!window.isSecureContext || !window.crypto?.subtle) {
    statusEl.textContent = 'Secure connection required';
    showOutput(
      'Encrypted commands require HTTPS. Open this UI with https:// (or use localhost during local development).',
    );
    return;
  }

  try {
    [serverPublicKey] = await Promise.all([fetchPublicKey(), fetchSystemInfo()]);
  } catch (error) {
    showOutput('Unable to load startup data: ' + error);
    return;
  }

  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${protocol}://${window.location.host}/ws?token=${encodeURIComponent(token)}`;
  ws = new WebSocket(url);

  ws.addEventListener('open', () => {
    statusEl.textContent = 'Authenticating...';
    socketReady = false;
    setControlsEnabled(false);
  });

  ws.addEventListener('message', async (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch (err) {
      showOutput('Received: ' + event.data);
      return;
    }

    if (!socketReady) {
      if (!data.success) {
        statusEl.textContent = 'Authentication failed';
        showOutput(data.message || 'Authentication failed.');
        ws.close();
        return;
      }
      socketReady = true;
      statusEl.textContent = 'Connected';
      setControlsEnabled(true);
      showOutput('Connected. Loading workspace...');
      const loaded = await loadDirectory(currentPath, { quiet: true });
      showOutput(loaded ? data.message : 'Connected, but the workspace could not be loaded.');
      return;
    }

    if (pendingResponse) {
      const resolve = pendingResponse;
      pendingResponse = null;
      resolve(data);
      return;
    }

    if (data.success) {
      loadDirectory(currentPath, { quiet: true });
    }
    showOutput(JSON.stringify(data, null, 2));
  });

  ws.addEventListener('close', () => {
    socketReady = false;
    statusEl.textContent = 'Disconnected';
    setControlsEnabled(false);
    renderEmpty('Connect to load workspace.');
    showOutput('WebSocket closed.');
  });

  ws.addEventListener('error', () => {
    socketReady = false;
    statusEl.textContent = 'Error';
    showOutput('WebSocket error.');
  });
}

async function loadDirectory(path, options = {}) {
	if (!isSocketOpen()) {
		return false;
	}

	const targetPath = normalizePath(path || currentPath || rootDir);
	const response = await sendEncryptedCommand({ action: 'list', path: targetPath });
	if (!response.success) {
		showCommandOutput(options.command, response.message || 'List folder failed.');
		return false;
	}

	currentPath = targetPath;
  selectedEntry = null;
  contextEntry = null;
  renderBreadcrumb();
  currentEntries = response.entries || [];
  renderEntries(currentEntries);
  if (!options.quiet) {
    showCommandOutput(options.command, formatDirectoryListing(response.entries || []));
  }
  return true;
}

async function createFolder(parentPath) {
  if (!isSocketOpen()) {
    showOutput('Socket is not open. Connect first.');
    return;
  }

  const name = prompt('New folder name');
  if (!name) {
    return;
  }

  const folderName = cleanName(name);
  if (!folderName) {
    showOutput('Folder name cannot be empty.');
    return;
  }

  const response = await sendEncryptedCommand({
    action: 'mkdir',
    path: joinPath(parentPath, folderName),
  });
  showOutput(JSON.stringify(response, null, 2));
  if (response.success) {
    loadDirectory(currentPath);
  }
}

async function renameEntry(entry) {
  if (!entry) {
    return;
  }

  const newName = prompt('Rename to', entry.name);
  if (!newName || newName === entry.name) {
    return;
  }

  const safeName = cleanName(newName);
  if (!safeName) {
    showOutput('New name cannot be empty.');
    return;
  }

  const response = await sendEncryptedCommand({
    action: 'rename',
    path: joinPath(currentPath, entry.name),
    target: joinPath(currentPath, safeName),
  });
  showOutput(JSON.stringify(response, null, 2));
  if (response.success) {
    loadDirectory(currentPath);
  }
}

async function deleteEntry(entry) {
  if (!entry) {
    return;
  }

  const ok = confirm(`Delete "${entry.name}"?`);
  if (!ok) {
    return;
  }

  const response = await sendEncryptedCommand({
    action: 'remove',
    path: joinPath(currentPath, entry.name),
  });
  showOutput(JSON.stringify(response, null, 2));
  if (response.success) {
    loadDirectory(currentPath);
  }
}

function runMenuAction(action) {
  const entry = contextEntry || selectedEntry;
  if (action === 'open' && entry?.isDir) {
    loadDirectory(joinPath(currentPath, entry.name));
  }
  if (action === 'read-file') {
    openFileForRead(entry);
  }
  if (action === 'edit-file') {
    openFileForEdit(entry);
  }
  if (action === 'new-folder') {
    createFolder(currentPath);
  }
  if (action === 'rename') {
    renameEntry(entry);
  }
  if (action === 'delete') {
    deleteEntry(entry);
  }
  if (action === 'refresh') {
    loadDirectory(currentPath);
  }
}

function renderBreadcrumb() {
	currentPathText.textContent = displayCurrentPath();
	upBtn.disabled = !isSocketOpen() || parentPath(currentPath) === currentPath;
}

function renderEntries(entries) {
  if (!entries.length) {
    renderEmpty('This folder is empty. Right-click to create a folder.');
    return;
  }

  const sorted = sortEntries(entries);

  fileListEl.innerHTML = `
    <div class="file-row file-row-head">
      ${renderSortHeader('name', 'Name')}
      ${renderSortHeader('type', 'Type')}
      ${renderSortHeader('size', 'Size')}
      ${renderSortHeader('modified', 'Modified')}
    </div>
  `;

  for (const entry of sorted) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'file-row';
    row.dataset.name = entry.name;
    row.dataset.isDir = String(entry.isDir);
    row.dataset.size = String(entry.size);
    row.dataset.modTime = entry.modTime;
    row.innerHTML = `
      <span class="file-name"><span class="file-icon">${entry.isDir ? '[]' : '--'}</span>${escapeHtml(entry.name)}</span>
      <span>${entry.isDir ? 'Folder' : 'File'}</span>
      <span>${entry.isDir ? '-' : formatSize(entry.size)}</span>
      <span>${formatDate(entry.modTime)}</span>
    `;
    fileListEl.appendChild(row);
  }
}

function setSort(key) {
	if (sortState.key === key) {
		sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
	} else {
		sortState = { key, direction: 'asc' };
	}
	renderEntries(currentEntries);
}

function renderSortHeader(key, label) {
	const marker = sortState.key === key ? (sortState.direction === 'asc' ? '^' : 'v') : '';
	return `<button type="button" class="sort-button" data-sort-key="${key}">${label}<span>${marker}</span></button>`;
}

function sortEntries(entries) {
	const direction = sortState.direction === 'asc' ? 1 : -1;
	return [...entries].sort((a, b) => {
		const primary = compareEntryValue(a, b, sortState.key);
		if (primary !== 0) {
			return primary * direction;
		}
		return a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });
	});
}

function compareEntryValue(a, b, key) {
	if (key === 'type') {
		return Number(b.isDir) - Number(a.isDir) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });
	}
	if (key === 'size') {
		return a.size - b.size;
	}
	if (key === 'modified') {
		return new Date(a.modTime).getTime() - new Date(b.modTime).getTime();
	}
	return a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });
}

function renderEmpty(message) {
  fileListEl.innerHTML = `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function selectEntry(entry) {
  selectedEntry = entry;
  document.querySelectorAll('.file-row.is-selected').forEach((row) => {
    row.classList.remove('is-selected');
  });
  if (!entry) {
    return;
  }
  const row = fileListEl.querySelector(`[data-name="${cssEscape(entry.name)}"]`);
  row?.classList.add('is-selected');
}

function showContextMenu(x, y, entry) {
  const hasEntry = Boolean(entry);
  contextMenu.querySelector('[data-menu-action="open"]').disabled = !entry?.isDir;
  contextMenu.querySelector('[data-menu-action="read-file"]').disabled = !hasEntry || entry.isDir;
  contextMenu.querySelector('[data-menu-action="edit-file"]').disabled = !hasEntry || entry.isDir;
  contextMenu.querySelector('[data-menu-action="rename"]').disabled = !hasEntry;
  contextMenu.querySelector('[data-menu-action="delete"]').disabled = !hasEntry;
  contextMenu.style.left = `${Math.min(x, window.innerWidth - 190)}px`;
  contextMenu.style.top = `${Math.min(y, window.innerHeight - 220)}px`;
  contextMenu.classList.add('is-open');
  contextMenu.setAttribute('aria-hidden', 'false');
}

async function openFileForRead(entry) {
	if (!entry || entry.isDir) {
		return;
	}
	await openFile(entry, true);
}

async function openFileForEdit(entry) {
	if (!entry || entry.isDir) {
		return;
	}
	await openFile(entry, false);
}

async function openFile(entry, readOnly) {
	const path = joinPath(currentPath, entry.name);
	const response = await sendEncryptedCommand({ action: 'readFile', path });
	if (!response.success) {
		showOutput(response.message || 'Read file failed.');
		return;
	}

	const data = response.data || {};
	openEditorPath = data.path || path;
	editorPanel.hidden = false;
	editorTitle.textContent = readOnly ? 'Read File' : 'Edit File';
	editorPath.textContent = toSystemPath(openEditorPath);
	fileEditor.value = data.content || '';
	fileEditor.readOnly = readOnly;
	saveFileBtn.disabled = readOnly;
	showOutput(`${readOnly ? 'Read' : 'Opened'}: ${toSystemPath(openEditorPath)}`);
}

async function saveOpenFile() {
	if (!openEditorPath) {
		showOutput('No file is open.');
		return;
	}

	saveFileBtn.disabled = true;
	const response = await writeFileInChunks(openEditorPath, fileEditor.value);
	saveFileBtn.disabled = fileEditor.readOnly;
	if (!response.success) {
		showOutput(response.message || 'Save failed.');
		return;
	}

	await loadDirectory(currentPath, { quiet: true });
	showOutput(`Saved: ${toSystemPath(openEditorPath)}`);
}

function closeEditor() {
	openEditorPath = '';
	editorPanel.hidden = true;
	fileEditor.value = '';
	fileEditor.readOnly = false;
	saveFileBtn.disabled = false;
	editorPath.textContent = '-';
}

function hideContextMenu() {
  contextMenu.classList.remove('is-open');
  contextMenu.setAttribute('aria-hidden', 'true');
}

function goUp() {
	loadDirectory(parentPath(currentPath));
}

function entryFromRow(row) {
  return {
    name: row.dataset.name,
    isDir: row.dataset.isDir === 'true',
    size: Number(row.dataset.size || 0),
    modTime: row.dataset.modTime || '',
  };
}

async function fetchPublicKey() {
  const response = await fetch('/publicKey');
  if (!response.ok) {
    throw new Error(response.statusText);
  }
  const data = await response.json();
  return data.publicKey;
}

async function fetchSystemInfo() {
  const response = await fetch('/systemInfo');
  if (!response.ok) {
    throw new Error(response.statusText);
  }
	const data = await response.json();
	rootDir = data.rootDir || '';
	pathSeparator = data.separator || '/';
	currentPath = normalizePath(rootDir);
}

async function runTypedCommand(event) {
  event.preventDefault();
  const command = commandInput.value.trim();
  if (!command) {
    return;
  }

  const ok = await executeTypedCommand(command);
  if (ok) {
    commandInput.value = '';
  }
}

async function executeTypedCommand(command) {
  const parts = splitCommand(command);
  const action = parts[0]?.toLowerCase();
  if (!action) {
    return false;
  }

  if (action === 'cls' || action === 'clear') {
    showOutput('');
    return true;
  }

  if (action === 'ls' || action === 'dir') {
    await loadDirectory(currentPath, { command });
    return true;
  }

  if (action === 'refresh') {
    await loadDirectory(currentPath, { quiet: true });
    showCommandOutput(command, 'Refreshed: ' + displayCurrentPath());
    return true;
  }

	if (action === 'cd') {
		if (!parts[1]) {
			showCommandOutput(command, displayCurrentPath());
			return true;
		}
		if (parts[1] === '..') {
			const changed = await loadDirectory(parentPath(currentPath), { quiet: true, command });
			if (changed) {
				showCommandOutput(command, '');
			}
      return true;
    }
    const changed = await loadDirectory(joinPath(currentPath, parts.slice(1).join(' ')), {
      quiet: true,
      command,
    });
    if (changed) {
      showCommandOutput(command, '');
    }
    return true;
  }

  if (action === 'mkdir' || action === 'md') {
    const name = parts.slice(1).join(' ');
    if (!name) {
      showCommandOutput(command, 'The syntax of the command is incorrect.');
      return false;
    }
    await createFolderWithName(currentPath, name, command);
    return true;
  }

  if (action === 'rename' || action === 'ren' || action === 'mv') {
    if (parts.length < 3) {
      showCommandOutput(command, 'The syntax of the command is incorrect.');
      return false;
    }
    await renameByName(parts[1], parts.slice(2).join(' '), command);
    return true;
  }

  if (action === 'delete' || action === 'del' || action === 'rm') {
    const name = parts.slice(1).join(' ');
    if (!name) {
      showCommandOutput(command, 'The syntax of the command is incorrect.');
      return false;
    }
    await deleteByName(name, command);
    return true;
  }

  const response = await sendEncryptedCommand({
    action: 'execute',
    path: currentPath,
    command,
  });
  showCommandOutput(command, response.message || (response.success ? '' : 'Command failed.'));
  if (response.success) {
    await loadDirectory(currentPath, { quiet: true });
  }
  return true;
}

function splitCommand(command) {
  const matches = command.match(/"([^"]+)"|'([^']+)'|\S+/g) || [];
  return matches.map((part) => part.replace(/^["']|["']$/g, ''));
}

async function sendEncryptedCommand(payload) {
  if (!isSocketOpen()) {
    return { success: false, message: 'Socket is not open. Connect first.' };
  }
  if (pendingResponse) {
    return { success: false, message: 'A command is already running.' };
  }

  try {
    const ciphertext = await encryptPayload(payload);
    const responsePromise = new Promise((resolve) => {
      const timeout = window.setTimeout(() => {
        pendingResponse = null;
        resolve({
          success: false,
          message: 'Server did not respond within 15 seconds. Check the WebSocket connection and server logs.',
        });
      }, 15000);
      pendingResponse = (response) => {
        window.clearTimeout(timeout);
        resolve(response);
      };
    });
    ws.send(JSON.stringify(ciphertext));
    return responsePromise;
  } catch (error) {
    pendingResponse = null;
    return {
      success: false,
      message: `Unable to encrypt or send command: ${error.message || error}`,
    };
  }
}

async function writeFileInChunks(path, content) {
	const session = createSessionId();
	const chunkSize = 64 * 1024;
	const chunks = content.match(new RegExp(`[\\s\\S]{1,${chunkSize}}`, 'g')) || [''];

	let response = await sendEncryptedCommand({
		action: 'writeFileStart',
		path,
		session,
		content: chunks[0],
	});
	if (!response.success) {
		return response;
	}

	for (const chunk of chunks.slice(1)) {
		response = await sendEncryptedCommand({
			action: 'writeFileAppend',
			path,
			session,
			content: chunk,
		});
		if (!response.success) {
			return response;
		}
	}

	return sendEncryptedCommand({
		action: 'writeFileFinish',
		path,
		session,
	});
}

function createSessionId() {
	const bytes = new Uint8Array(12);
	window.crypto.getRandomValues(bytes);
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function encryptPayload(payload) {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(payload));
  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt'],
  );
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedPayload = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    aesKey,
    plaintext,
  );
  const rawKey = await window.crypto.subtle.exportKey('raw', aesKey);
  const publicKey = await importPublicKey(serverPublicKey);
  const encryptedKey = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    rawKey,
  );
  return {
    key: base64Encode(new Uint8Array(encryptedKey)),
    nonce: base64Encode(nonce),
    ciphertext: base64Encode(new Uint8Array(encryptedPayload)),
  };
}

async function importPublicKey(pem) {
  const binary = pemToArrayBuffer(pem);
  return window.crypto.subtle.importKey(
    'spki',
    binary,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt'],
  );
}

function pemToArrayBuffer(pem) {
  const clean = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(clean);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer;
}

function base64Encode(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function isSocketOpen() {
  return socketReady && ws && ws.readyState === WebSocket.OPEN;
}

function setControlsEnabled(enabled) {
	refreshBtn.disabled = !enabled;
	commandInput.disabled = !enabled;
	commandBtn.disabled = !enabled;
	upBtn.disabled = !enabled || parentPath(currentPath) === currentPath;
	if (!enabled) {
		currentPathText.textContent = '-';
	}
}

function normalizePath(path) {
	let clean = String(path || '').trim().replaceAll('\\', '/');
	clean = clean.replace(/\/+/g, '/');
	const driveMatches = [...clean.matchAll(/[A-Za-z]:\//g)];
	if (driveMatches.length > 0) {
		clean = clean.slice(driveMatches[driveMatches.length - 1].index);
	}
	if (/^[A-Za-z]:[^/]/.test(clean)) {
		clean = `${clean.slice(0, 2)}/${clean.slice(2)}`;
	}
	if (clean === '/') {
		return clean;
	}
	if (/^[A-Za-z]:$/.test(clean)) {
		return `${clean}/`;
	}
	if (/^[A-Za-z]:\/$/.test(clean)) {
		return clean;
	}
	return clean.replace(/\/+$/g, '');
}

function joinPath(parent, name) {
	const target = normalizePath(name);
	if (isAbsolutePath(target)) {
		return target;
	}
	const base = normalizePath(parent || rootDir);
	if (!base || base === '/') {
		return normalizePath('/' + target);
	}
	return normalizePath(`${base}/${target}`);
}

function cleanName(name) {
	return normalizePath(name);
}

function displayCurrentPath() {
	return toSystemPath(currentPath || rootDir);
}

function isAbsolutePath(path) {
	const clean = normalizePath(path);
	return clean.startsWith('/') || /^[A-Za-z]:\//.test(clean);
}

function parentPath(path) {
	const clean = normalizePath(path || rootDir);
	if (!clean || clean === '/') {
		return clean || '/';
	}
	if (/^[A-Za-z]:\/?$/.test(clean)) {
		return clean.endsWith('/') ? clean : `${clean}/`;
	}
	const parts = clean.split('/');
	parts.pop();
	const parent = parts.join('/');
	if (parent === '' && clean.startsWith('/')) {
		return '/';
	}
	if (/^[A-Za-z]:$/.test(parent)) {
		return `${parent}/`;
	}
	return parent || clean;
}

function toSystemPath(path) {
	const clean = normalizePath(path);
	if (pathSeparator === '\\') {
		return clean.replaceAll('/', '\\');
	}
	return clean.replaceAll('\\', '/');
}

async function createFolderWithName(parentPath, name, command = '') {
  const folderName = cleanName(name);
  if (!folderName) {
    showCommandOutput(command, 'The syntax of the command is incorrect.');
    return;
  }

  const response = await sendEncryptedCommand({
    action: 'mkdir',
    path: joinPath(parentPath, folderName),
  });
  if (response.success) {
    await loadDirectory(currentPath, { quiet: true });
    showCommandOutput(command, '');
  } else {
    showCommandOutput(command, response.message || 'Create folder failed.');
  }
}

async function renameByName(oldName, newName, command = '') {
  const fromName = cleanName(oldName);
  const toName = cleanName(newName);
  if (!fromName || !toName) {
    showCommandOutput(command, 'The syntax of the command is incorrect.');
    return;
  }

  const response = await sendEncryptedCommand({
    action: 'rename',
    path: joinPath(currentPath, fromName),
    target: joinPath(currentPath, toName),
  });
  if (response.success) {
    await loadDirectory(currentPath, { quiet: true });
    showCommandOutput(command, '');
  } else {
    showCommandOutput(command, response.message || 'Rename failed.');
  }
}

async function deleteByName(name, command = '') {
  const entryName = cleanName(name);
  if (!entryName) {
    showCommandOutput(command, 'The syntax of the command is incorrect.');
    return;
  }

  const ok = confirm(`Delete "${entryName}"?`);
  if (!ok) {
    return;
  }

  const response = await sendEncryptedCommand({
    action: 'remove',
    path: joinPath(currentPath, entryName),
  });
  if (response.success) {
    await loadDirectory(currentPath, { quiet: true });
    showCommandOutput(command, '');
  } else {
    showCommandOutput(command, response.message || 'Delete failed.');
  }
}

function formatSize(size) {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(value) {
  if (!value) {
    return '-';
  }
  return new Date(value).toLocaleString();
}

function formatDirectoryListing(entries) {
  if (pathSeparator === '\\') {
    return formatWindowsDirectoryListing(entries);
  }
  return formatUnixDirectoryListing(entries);
}

function formatWindowsDirectoryListing(entries) {
  const pathLine = ` Directory of ${displayCurrentPath()}`;
  if (!entries.length) {
    return `${pathLine}\n\nFile Not Found`;
  }

  const sorted = [...entries].sort((a, b) => {
    if (a.isDir !== b.isDir) {
      return a.isDir ? -1 : 1;
    }
    return a.name.localeCompare(b.name);
  });

  const rows = sorted.map((entry) => {
    const date = formatWindowsDate(entry.modTime);
    const type = entry.isDir ? '<DIR>' : '     ';
    const size = entry.isDir ? ''.padStart(14, ' ') : String(entry.size).padStart(14, ' ');
    return `${date}    ${type} ${size} ${entry.name}`;
  });

  return `${pathLine}\n\n${rows.join('\n')}`;
}

function formatUnixDirectoryListing(entries) {
  if (!entries.length) {
    return '';
  }

  const sorted = [...entries].sort((a, b) => {
    if (a.isDir !== b.isDir) {
      return a.isDir ? -1 : 1;
    }
    return a.name.localeCompare(b.name);
  });

  return sorted.map((entry) => {
    const type = entry.isDir ? 'd' : '-';
    return `${type} ${String(entry.size).padStart(10, ' ')} ${formatDate(entry.modTime)} ${entry.name}`;
  }).join('\n');
}

function formatWindowsDate(value) {
  if (!value) {
    return ''.padEnd(20, ' ');
  }
  const date = new Date(value);
  const datePart = date.toLocaleDateString();
  const timePart = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return `${datePart}  ${timePart}`.padEnd(20, ' ');
}

function formatUnknownCommand(action) {
  if (pathSeparator === '\\') {
    return `'${action}' is not recognized as an internal or external command,\noperable program or batch file.`;
  }
  return `${action}: command not found`;
}

function showCommandOutput(command, message) {
  if (!command) {
    showOutput(message);
    return;
  }
  const prompt = `${displayCurrentPath()}>${command}`;
  showOutput(message ? `${prompt}\n${message}` : prompt);
}

function cssEscape(value) {
  if (window.CSS?.escape) {
    return CSS.escape(value);
  }
  return value.replace(/"/g, '\\"');
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function showOutput(message) {
  outputEl.textContent = message;
}
