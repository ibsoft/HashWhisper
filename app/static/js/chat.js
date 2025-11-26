const encoder = new TextEncoder();

const state = {
  currentGroup: null,
  secrets: {},
  keyCache: {},
  seen: {},
  messages: {},
  notifications: { count: 0, mention: false },
  emojiPickerReady: false,
  notificationsAllowed: false,
};

let refreshTimer = null;

let secretResolver = null;
let secretModalInstance = null;
let deleteModalInstance = null;
let pendingDeleteGroupId = null;
const secretState = { groupId: null };
let infoModalInstance = null;
let mediaRecorder = null;
let recordChunks = [];
let isRecording = false;

function linkify(text) {
  if (!text) return '';
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  return text.replace(urlRegex, (url) => `<a href="${url}" target="_blank" rel="noopener">${url}</a>`);
}

function isYouTube(url) {
  return /youtu\.be\//i.test(url) || /youtube\.com\/(watch\?v=|shorts\/)/i.test(url);
}

function youtubeEmbed(url) {
  try {
    let videoId = '';
    const short = url.match(/youtu\.be\/([^?]+)/i);
    const watch = url.match(/v=([^&]+)/i);
    const shorts = url.match(/shorts\/([^?]+)/i);
    videoId = (short && short[1]) || (watch && watch[1]) || (shorts && shorts[1]) || '';
    if (!videoId) return '';
    return `<div class="ratio ratio-16x9 mt-2"><iframe src="https://www.youtube.com/embed/${videoId}" allowfullscreen loading="lazy"></iframe></div>`;
  } catch (e) {
    return '';
  }
}

function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

function getUserTimezone() {
  const shell = document.querySelector('.chat-shell');
  return (shell?.getAttribute('data-user-tz')) || 'UTC';
}

function getCurrentUsername() {
  const shell = document.querySelector('.chat-shell');
  return (shell?.getAttribute('data-username')) || '';
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function formatTime(ts) {
  try {
    const userTz = getUserTimezone();
    const dt = new Date(ts);
    return dt.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', timeZone: userTz, month: 'short', day: 'numeric' });
  } catch (err) {
    return new Date(ts).toLocaleString();
  }
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
  return bytes.buffer;
}

async function deriveKey(secret, groupId) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode(`hashwhisper-${groupId}`),
      iterations: 120000,
      hash: 'SHA-256',
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptText(message, secret, groupId) {
  const key = await deriveKey(secret, groupId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode('HashWhisper:v1') },
    key,
    encoder.encode(message)
  );
  const bytes = new Uint8Array(encrypted);
  const tag = bytes.slice(-16);
  const ciphertext = bytes.slice(0, bytes.length - 16);
  return { ciphertext: toHex(ciphertext), nonce: toHex(iv), tag: toHex(tag) };
}

async function decryptText(payload, secret, groupId) {
  try {
    const key = await deriveKey(secret, groupId);
    const nonce = new Uint8Array(fromHex(payload.nonce));
    const tag = new Uint8Array(fromHex(payload.auth_tag));
    const cipher = new Uint8Array(fromHex(payload.ciphertext));
    const combined = new Uint8Array(cipher.length + tag.length);
    combined.set(cipher);
    combined.set(tag, cipher.length);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: encoder.encode('HashWhisper:v1') },
      key,
      combined
    );
    return new TextDecoder().decode(decrypted);
  } catch (err) {
    console.warn('Decrypt failed', err);
    return '[unable to decrypt]';
  }
}

function highlightMentions(html) {
  const username = getCurrentUsername();
  if (!username) return html;
  const escaped = escapeRegex(username);
  const regex = new RegExp(`@${escaped}(?![\\w@])`, 'gi');
  return html.replace(regex, (match) => `<span class="mention">${match}</span>`);
}

function messageMentionsUser(text) {
  const username = getCurrentUsername();
  if (!username) return false;
  const escaped = escapeRegex(username);
  const regex = new RegExp(`@${escaped}(?![\\w@])`, 'i');
  return regex.test(text || '');
}

function loadPersistedSecrets() {
  try {
    const raw = sessionStorage.getItem('hw-secrets');
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      state.secrets = { ...parsed, ...state.secrets };
    }
  } catch (e) {
    // ignore parse errors
  }
}

function loadLastGroup() {
  try {
    const raw = sessionStorage.getItem('hw-last-group');
    if (!raw) return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  } catch (e) {
    return null;
  }
}

function persistLastGroup(groupId) {
  try {
    sessionStorage.setItem('hw-last-group', String(groupId));
  } catch (e) {
    // ignore
  }
}

function persistSecret(groupId, secret) {
  const gid = Number(groupId);
  if (!gid || !secret) return;
  try {
    const raw = sessionStorage.getItem('hw-secrets');
    const parsed = raw ? JSON.parse(raw) : {};
    parsed[gid] = secret;
    sessionStorage.setItem('hw-secrets', JSON.stringify(parsed));
  } catch (e) {
    // ignore storage errors
  }
}

function removePersistedSecret(groupId) {
  const gid = Number(groupId);
  if (!gid) return;
  try {
    const raw = sessionStorage.getItem('hw-secrets');
    const parsed = raw ? JSON.parse(raw) : {};
    delete parsed[gid];
    sessionStorage.setItem('hw-secrets', JSON.stringify(parsed));
  } catch (e) {
    // ignore storage errors
  }
}

function updateNotificationIcon(delta = 0, mention = false) {
  state.notifications.count = Math.max(0, state.notifications.count + delta);
  state.notifications.mention = state.notifications.mention || mention;
  const badge = document.getElementById('info-count');
  const dot = document.getElementById('info-dot');
  const btn = document.getElementById('info-indicator');
  if (badge) {
    if (state.notifications.count > 0) {
      badge.textContent = state.notifications.count;
      badge.classList.remove('d-none');
    } else {
      badge.classList.add('d-none');
    }
  }
  if (dot) dot.classList.toggle('d-none', state.notifications.count === 0);
  if (btn) {
    btn.classList.toggle('btn-outline-warning', state.notifications.mention);
    btn.title = state.notifications.count
      ? `${state.notifications.count} new ${state.notifications.mention ? ' (mentions highlighted)' : ''}`.trim()
      : 'No new notifications';
  }
}

async function requestNotificationPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    state.notificationsAllowed = true;
    return;
  }
  if (Notification.permission === 'default') {
    try {
      const res = await Notification.requestPermission();
      state.notificationsAllowed = res === 'granted';
    } catch (e) {
      state.notificationsAllowed = false;
    }
  }
}

function showBrowserNotification(title, body) {
  if (!state.notificationsAllowed || !('Notification' in window)) return;
  try {
    new Notification(title, { body, silent: false });
  } catch (e) {
    // ignore
  }
}

function resetNotifications() {
  state.notifications = { count: 0, mention: false };
  updateNotificationIcon(0, false);
}

async function encryptFile(file, secret, groupId) {
  const key = await deriveKey(secret, groupId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const buffer = await file.arrayBuffer();
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode('HashWhisper:v1') },
    key,
    buffer
  );
  const bytes = new Uint8Array(encrypted);
  const tag = bytes.slice(-16);
  const cipher = bytes.slice(0, bytes.length - 16);
  return { cipher, nonce: toHex(iv), tag: toHex(tag) };
}

async function renderMessage(container, msg, self, groupId) {
  const bubble = document.createElement('div');
  bubble.className = `bubble ${self ? 'self' : 'other'}`;
  let meta = {};
  try { meta = JSON.parse(msg.meta || '{}'); } catch (err) { meta = {}; }
  const body = document.createElement('div');
  const metaLine = document.createElement('div');
  metaLine.className = 'meta';
  const uploadedBy = msg.sender_name ? ` • by ${msg.sender_name}` : '';
  const namePart = meta.type === 'media' ? '' : (meta.name ? ' • ' + meta.name : '');
  metaLine.textContent = `${formatTime(msg.created_at)}${namePart}${uploadedBy}`;
  const actions = document.createElement('div');
  actions.className = 'd-flex align-items-center gap-3 mt-2 actions';
  if (meta.type === 'media') {
    body.className = 'd-flex flex-column gap-2';
    const preview = document.createElement('div');
    preview.className = 'w-100 mt-1 media-preview';
    if (meta.blob_id) {
      const renderInline = () => decryptMedia(msg, meta, { target: preview, inline: true, groupId });
      if (!state.secrets[groupId]) {
        ensureSecret(groupId).then((secret) => { if (secret) renderInline(); });
      } else {
        renderInline();
      }
      preview.addEventListener('click', () => openMediaModal(meta));
      const dlBtn = document.createElement('button');
      dlBtn.className = 'btn btn-sm reaction-download align-self-start';
      dlBtn.innerHTML = '<i class="fa-solid fa-download"></i>';
      dlBtn.addEventListener('click', () => decryptMedia(msg, meta, { download: true, groupId }));
      actions.appendChild(dlBtn);
      if ((meta.mime || '').toLowerCase().startsWith('image/')) {
        const copyImgBtn = document.createElement('button');
        copyImgBtn.className = 'btn btn-sm reaction-download align-self-start';
        copyImgBtn.innerHTML = '<i class="fa-solid fa-copy"></i>';
        copyImgBtn.title = 'Copy image';
        copyImgBtn.addEventListener('click', () => copyImageFromMeta(msg, meta, groupId));
        actions.appendChild(copyImgBtn);
      } else if ((meta.mime || '').toLowerCase().startsWith('video/')) {
        const copyLinkBtn = document.createElement('button');
        copyLinkBtn.className = 'btn btn-sm reaction-download align-self-start';
        copyLinkBtn.innerHTML = '<i class="fa-solid fa-link"></i>';
        copyLinkBtn.title = 'Copy video link';
        copyLinkBtn.addEventListener('click', () => copyMediaLink(meta, msg, groupId));
        actions.appendChild(copyLinkBtn);
      }
    }
    body.appendChild(preview);
  } else {
    const text = msg.plaintext || '[cipher]';
    const html = highlightMentions(linkify(text)).replace(/\n/g, '<br>');
    body.innerHTML = html;
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-sm reaction-download align-self-start mt-2';
    copyBtn.innerHTML = '<i class="fa-solid fa-copy"></i>';
    copyBtn.title = 'Copy text';
    copyBtn.addEventListener('click', () => copyTextToClipboard(text));
    actions.appendChild(copyBtn);
    const yt = text.match(/https?:\/\/[^\s]+/);
    if (yt && isYouTube(yt[0])) {
      body.insertAdjacentHTML('beforeend', youtubeEmbed(yt[0]));
    }
  }
  const likeBtn = document.createElement('button');
  likeBtn.className = 'btn btn-sm reaction-like';
  likeBtn.innerHTML = `<i class=\"fa-solid fa-heart\"></i> <span class=\"like-count\">${msg.likes || 0}</span>`;
  likeBtn.title = msg.liked_by && msg.liked_by.length ? `Liked by ${msg.liked_by.join(', ')}` : 'No likes yet';
  const dislikeBtn = document.createElement('button');
  dislikeBtn.className = 'btn btn-sm reaction-dislike';
  dislikeBtn.innerHTML = `<i class=\"fa-solid fa-thumbs-down\"></i> <span class=\"dislike-count\">${msg.dislikes || 0}</span>`;
  dislikeBtn.title = msg.disliked_by && msg.disliked_by.length ? `Disliked by ${msg.disliked_by.join(', ')}` : 'No dislikes yet';
  likeBtn.addEventListener('click', () => reactMessage(msg.id, 'like', likeBtn, dislikeBtn, msg));
  dislikeBtn.addEventListener('click', () => reactMessage(msg.id, 'dislike', likeBtn, dislikeBtn, msg));

  const likedBy = document.createElement('div');
  likedBy.className = 'text-muted small';
  likedBy.textContent = msg.liked_by && msg.liked_by.length ? `Liked by ${msg.liked_by.join(', ')}` : '';

  actions.appendChild(likeBtn);
  actions.appendChild(dislikeBtn);
  bubble.appendChild(body);
  bubble.appendChild(metaLine);
  bubble.appendChild(actions);
  if (likedBy.textContent) bubble.appendChild(likedBy);
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
}

async function decryptMedia(msg, meta, opts = {}) {
  const { download = false, inline = false, target = null, groupId = state.currentGroup } = opts;
  try {
    const secret = await ensureSecret(groupId);
    if (!secret) return;
    const resp = await fetch(`/api/blob/${meta.blob_id}`);
    if (!resp.ok) return showInfoModal('Download failed', 'Could not fetch the encrypted media.');
    const cipherBuffer = await resp.arrayBuffer();
    const key = await deriveKey(secret, groupId);
    const nonce = new Uint8Array(fromHex(msg.nonce));
    const tag = new Uint8Array(fromHex(msg.auth_tag));
    const cipher = new Uint8Array(cipherBuffer);
    const combined = new Uint8Array(cipher.length + tag.length);
    combined.set(cipher);
    combined.set(tag, cipher.length);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: encoder.encode('HashWhisper:v1') },
      key,
      combined
    );
    const blob = new Blob([plaintext], { type: meta.mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    meta.renderedUrl = url;
    if (inline && target) {
      target.innerHTML = '';
      const mime = (meta.mime || '').toLowerCase();
      if (mime.startsWith('image/')) {
        const img = document.createElement('img');
        img.src = url;
        img.alt = meta.name || 'media';
        img.className = 'img-fluid rounded';
        target.appendChild(img);
      } else if (mime.startsWith('video/')) {
        const video = document.createElement('video');
        video.src = url;
        video.controls = true;
        video.className = 'w-100 rounded';
        target.appendChild(video);
      } else if (mime.startsWith('audio/')) {
        const audio = document.createElement('audio');
        audio.src = url;
        audio.controls = true;
        target.appendChild(audio);
      } else {
        const link = document.createElement('a');
        link.href = url;
        link.textContent = 'Open file';
        link.target = '_blank';
        target.appendChild(link);
      }
    }
    if (download) {
      const a = document.createElement('a');
      a.href = url;
      a.download = meta.name || 'media';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  } catch (err) {
    console.error('Media decrypt failed', err);
    if (target) {
      target.innerHTML = '<div class="text-danger small">Unable to decrypt media.</div>';
    } else {
      showInfoModal('Decrypt failed', 'Unable to decrypt media with provided secret.');
    }
  }
}

function ensureSecret(groupId) {
  if (state.secrets[groupId]) return Promise.resolve(state.secrets[groupId]);
  return new Promise((resolve) => {
    secretResolver = resolve;
    const modalEl = document.getElementById('secretModal');
    const gidEl = document.getElementById('secret-group-id');
    const inputEl = document.getElementById('secret-input');
    const errorEl = document.getElementById('secret-error');
    gidEl.value = groupId;
    inputEl.value = '';
    errorEl.classList.add('d-none');
    if (!secretModalInstance) {
      secretModalInstance = bootstrap.Modal.getOrCreateInstance(modalEl);
    }
    secretModalInstance.show();
  });
}

async function loadMessages(groupId, opts = {}) {
  const { skipSecretPrompt = false, notify = true } = opts;
  const list = document.getElementById('message-list');
  if (!state.messages[groupId]) state.messages[groupId] = [];
  const hasExisting = state.messages[groupId].length > 0;
  if (!state.secrets[groupId] && !skipSecretPrompt) {
    await ensureSecret(groupId);
  }

  let data = [];
  try {
    const res = await fetch(`/api/messages?group_id=${groupId}`);
    if (!res.ok) {
      const text = await res.text();
      showInfoModal('Load failed', `Status ${res.status}: ${text || 'Unable to load messages.'}`);
      return;
    }
    data = await res.json();
  } catch (err) {
    showInfoModal('Load failed', 'Could not load messages.');
    console.error('loadMessages error', err);
    return;
  }

  if (!Array.isArray(data)) {
    showInfoModal('Load failed', data.error || 'Unable to load messages.');
    console.error('loadMessages response', data);
    return;
  }
  const lastMsg = data[data.length - 1];
  const lastSeen = state.seen[groupId] || 0;
  const newMessages = hasExisting
    ? data.filter((m) => new Date(m.created_at).getTime() > lastSeen)
    : data;
  if (hasExisting && newMessages.length === 0) return;
  if (!hasExisting) list.innerHTML = '';
  const secret = state.secrets[groupId];
  for (const msg of newMessages) {
    let plaintext = '[encrypted]';
    if (secret && msg.ciphertext) {
      plaintext = await decryptText(msg, secret, groupId);
    }
    msg.plaintext = plaintext;
    const isSelf = msg.sender_id === Number(document.querySelector('.chat-shell').dataset.userId);
    await renderMessage(list, msg, isSelf, groupId);
    state.messages[groupId].push(msg.id);
    if (notify && !isSelf) {
      const mentionHit = messageMentionsUser(plaintext);
      updateNotificationIcon(1, mentionHit);
      showBrowserNotification('New message', plaintext.slice(0, 80) || 'Encrypted message');
    }
  }
  if (list.lastElementChild) {
    list.lastElementChild.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }
  // mark latest seen
  if (lastMsg) {
    state.seen[groupId] = new Date(lastMsg.created_at).getTime();
  } else {
    state.seen[groupId] = 0;
  }
}

async function sendMessage() {
  if (!state.currentGroup) {
    showInfoModal('Select a group', 'Choose a group or DM before sending.');
    return;
  }
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text) {
    showInfoModal('Empty message', 'Type a message before sending.');
    return;
  }
  const secret = await ensureSecret(state.currentGroup);
  if (!secret) return;
  const encrypted = await encryptText(text, secret, state.currentGroup);
  const resp = await fetch('/api/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
    body: JSON.stringify({
      group_id: state.currentGroup,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      auth_tag: encrypted.tag,
      meta: JSON.stringify({ type: 'text', len: text.length }),
    }),
  });
  if (resp.ok) {
    input.value = '';
    await loadMessages(state.currentGroup, { notify: false });
    startAutoRefresh();
  }
}

async function sendFile(file) {
  if (!state.currentGroup) {
    showInfoModal('Select a group', 'Choose a group or DM before uploading.');
    return;
  }
  if (!file) {
    showInfoModal('No file selected', 'Pick a file or record a voice note to upload.');
    return;
  }
  const maxBytes = Number(document.querySelector('.chat-shell').dataset.maxBytes || 0);
  if (maxBytes && file.size > maxBytes) {
    showInfoModal('Upload blocked', 'File exceeds maximum encrypted upload size.');
    return;
  }
  const secret = await ensureSecret(state.currentGroup);
  if (!secret) return;
  toggleUploadSpinner(true);
  const encrypted = await encryptFile(file, secret, state.currentGroup);
  const form = new FormData();
  form.append('file', new Blob([encrypted.cipher], { type: file.type || 'application/octet-stream' }), `cipher-${file.name}`);
  form.append('group_id', state.currentGroup);
  form.append('nonce', encrypted.nonce);
  form.append('auth_tag', encrypted.tag);
  form.append('meta', JSON.stringify({ type: 'media', name: file.name, size: file.size, mime: file.type }));
  const resp = await fetch('/api/upload', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() }, body: form });
  toggleUploadSpinner(false);
  if (resp.ok) {
    await loadMessages(state.currentGroup, { notify: false });
    startAutoRefresh();
  }
}

function toggleUploadSpinner(show) {
  const spinner = document.getElementById('upload-spinner');
  if (!spinner) return;
  spinner.classList.toggle('d-none', !show);
}

async function toggleRecording() {
  if (isRecording) {
    mediaRecorder.stop();
    isRecording = false;
    document.getElementById('recording-indicator')?.classList.add('d-none');
    document.getElementById('record-btn')?.classList.remove('btn-danger');
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    recordChunks = [];
    const mimeOptions = ['audio/webm', 'audio/mp4', 'audio/ogg'];
    let chosen = '';
    for (const m of mimeOptions) {
      if (MediaRecorder.isTypeSupported(m)) { chosen = m; break; }
    }
    mediaRecorder = new MediaRecorder(stream, chosen ? { mimeType: chosen } : undefined);
    mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) recordChunks.push(e.data); };
    mediaRecorder.onstop = async () => {
      const type = chosen || 'audio/webm';
      const blob = new Blob(recordChunks, { type });
      const ext = type.split('/')[1] || 'webm';
      const file = new File([blob], `voice-${Date.now()}.${ext}`, { type });
      await sendFile(file);
      stream.getTracks().forEach((t) => t.stop());
    };
    mediaRecorder.start();
    isRecording = true;
    document.getElementById('recording-indicator')?.classList.remove('d-none');
    document.getElementById('record-btn')?.classList.add('btn-danger');
  } catch (err) {
    console.error('Recording failed', err);
    showInfoModal('Microphone blocked', 'Allow microphone access to record a voice note.');
  }
}

async function copyTextToClipboard(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showInfoModal('Copied', 'Content copied to clipboard.');
  } catch (err) {
    showInfoModal('Copy failed', 'Could not copy to clipboard in this browser.');
  }
}

async function copyImageFromMeta(msg, meta, groupId) {
  try {
    if (!meta.renderedUrl) {
      await decryptMedia(msg, meta, { inline: false, groupId });
    }
    if (!meta.renderedUrl) {
      showInfoModal('Copy failed', 'No image available to copy.');
      return;
    }
    const resp = await fetch(meta.renderedUrl);
    const blob = await resp.blob();
    await navigator.clipboard.write([
      new ClipboardItem({ [blob.type]: blob })
    ]);
    showInfoModal('Copied', 'Image copied to clipboard.');
  } catch (err) {
    showInfoModal('Copy failed', 'Could not copy image to clipboard.');
  }
}

async function copyMediaLink(meta, msg, groupId) {
  try {
    if (!meta.renderedUrl) {
      await decryptMedia(msg, meta, { inline: false, groupId });
    }
    if (!meta.renderedUrl) {
      showInfoModal('Copy failed', 'No media link available.');
      return;
    }
    await copyTextToClipboard(meta.renderedUrl);
  } catch (err) {
    showInfoModal('Copy failed', 'Could not copy link.');
  }
}

function bindUI() {
  const list = document.getElementById('message-list');
  loadPersistedSecrets();
  document.getElementById('send-btn')?.addEventListener('click', sendMessage);
  document.getElementById('message-input')?.addEventListener('keyup', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
    signalTyping();
  });

  requestNotificationPermission();

  document.getElementById('attach-btn')?.addEventListener('click', () => {
    document.getElementById('file-input').click();
  });
  document.getElementById('file-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    sendFile(file);
    e.target.value = '';
  });

  document.getElementById('record-btn')?.addEventListener('click', toggleRecording);

  initEmojiPicker();

  // join handled inline

  document.querySelectorAll('[data-group-id]').forEach(attachGroupButtonHandler);
  updateSecretDots();
  restoreLastGroup();

  (async () => {
    if (state.currentGroup) return;
    const first = document.querySelector('[data-group-id]');
    if (first) {
      const gid = Number(first.getAttribute('data-group-id'));
      const label = first.getAttribute('data-group-name') || first.querySelector('.group-name')?.textContent.trim();
      await setCurrentGroup(gid, label || 'Chat');
    }
  })();

  document.querySelectorAll('.delete-group').forEach(attachDeleteGroupHandler);

  const joinToggle = document.getElementById('join-secret-toggle');
  if (joinToggle) {
    joinToggle.addEventListener('click', () => {
      const input = document.getElementById('join-secret');
      if (!input) return;
      const isHidden = input.getAttribute('type') === 'password';
      input.setAttribute('type', isHidden ? 'text' : 'password');
      joinToggle.innerHTML = isHidden ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
    });
  }

  document.getElementById('join-btn')?.addEventListener('click', async () => {
    const secret = document.getElementById('join-secret').value.trim();
    const groupName = (document.getElementById('join-group-name')?.value || '').trim();
    if (!groupName || !secret) return showInfoModal('Join failed', 'Provide group name and secret.');
    const resp = await fetch('/groups/join', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
      body: JSON.stringify({ group_name: groupName, secret }),
    });
    if (resp.ok) {
      const data = await resp.json();
      state.secrets[data.group_id] = secret;
      const list = document.querySelector('.contact-list');
      if (list && !list.querySelector(`[data-group-id="${data.group_id}"]`)) {
        addGroupToSidebar(data.group_id, groupName);
      }
      setCurrentGroup(data.group_id, groupName);
      document.getElementById('join-secret').value = '';
      const nameInput = document.getElementById('join-group-name');
      if (nameInput) nameInput.value = '';
    } else {
      showInfoModal('Join failed', 'Unable to join this group with the provided secret.');
    }
  });

  const modalEl = document.getElementById('secretModal');
  if (modalEl) {
    secretModalInstance = bootstrap.Modal.getOrCreateInstance(modalEl);
    document.getElementById('secret-save')?.addEventListener('click', () => {
      const gid = Number(document.getElementById('secret-group-id').value);
      const val = (document.getElementById('secret-input').value || '').trim();
      const remember = document.getElementById('remember-secret')?.checked;
      const errorEl = document.getElementById('secret-error');
      if (!val) {
        errorEl.classList.remove('d-none');
        return;
      }
      errorEl.classList.add('d-none');
      state.secrets[gid] = val;
      if (remember) {
        persistSecret(gid, val);
      } else {
        removePersistedSecret(gid);
      }
      if (secretResolver) {
        secretResolver(val);
        secretResolver = null;
      }
      secretModalInstance.hide();
    });
    modalEl.addEventListener('hidden.bs.modal', () => {
      if (secretResolver) {
        secretResolver(null);
        secretResolver = null;
      }
      const remember = document.getElementById('remember-secret');
      if (remember) remember.checked = false;
    });
  }

  const deleteModalEl = document.getElementById('deleteGroupModal');
  if (deleteModalEl) {
    deleteModalInstance = bootstrap.Modal.getOrCreateInstance(deleteModalEl);
    document.getElementById('confirm-delete-group')?.addEventListener('click', async () => {
      if (!pendingDeleteGroupId) return;
      const resp = await fetch(`/groups/${pendingDeleteGroupId}/delete`, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken() },
      });
      if (resp.ok) {
        removeGroupFromSidebar(pendingDeleteGroupId);
        if (state.currentGroup === pendingDeleteGroupId) {
          state.currentGroup = null;
          document.getElementById('chat-title').textContent = 'Select a group';
          const listEl = document.getElementById('message-list');
          if (listEl) listEl.innerHTML = '';
        }
      } else {
        showInfoModal('Delete failed', 'Could not delete this group.');
      }
    });
    deleteModalEl.addEventListener('hidden.bs.modal', () => {
      pendingDeleteGroupId = null;
    });
  }

  // Fetch users for DM list
  const userList = document.getElementById('user-list');

  const dmStartBtn = document.getElementById('dm-start-btn');
  if (dmStartBtn) {
    dmStartBtn.addEventListener('click', async () => {
      const uid = Number(document.getElementById('dm-user-id').value);
      const secret = (document.getElementById('dm-secret').value || '').trim();
      if (!uid || !secret) return;
      const resp = await fetch('/api/dm/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify({ user_id: uid, secret }),
      });
      if (resp.ok) {
        const data = await resp.json();
        state.secrets[data.group_id] = secret;
        state.currentGroup = data.group_id;
        document.getElementById('chat-title').textContent = data.name;
        await loadMessages(data.group_id);
        document.getElementById('dm-secret').value = '';
        bootstrap.Modal.getOrCreateInstance(document.getElementById('dmModal')).hide();
        startAutoRefresh();
      }
    });
  }

  const infoBtn = document.getElementById('info-indicator');
  if (infoBtn) {
    infoBtn.addEventListener('click', () => {
      resetNotifications();
    });
  }

  // checkGroupNotifications disabled to reduce rate limits
  startAutoRefresh();
}

function connectPresence() {
  const label = document.getElementById('presence-label');
  const typingIndicator = document.getElementById('typing-indicator');
  startPresencePoll(label, typingIndicator);
}

function startPresencePoll(label, typingIndicator) {
  setInterval(() => {
    label.textContent = 'Presence: online';
    typingIndicator.classList.add('d-none');
  }, 15000);
}

function openDmModal(userId) {
  const modal = document.getElementById('dmModal');
  if (!modal) return;
  document.getElementById('dm-user-id').value = userId;
  document.getElementById('dm-secret').value = '';
  bootstrap.Modal.getOrCreateInstance(modal).show();
}

function loadGroupUsers(groupId) {
  const userList = document.getElementById('user-list');
  if (!userList || !groupId) return;
  userList.innerHTML = '<div class="text-muted small">Loading…</div>';
  fetch(`/api/users?group_id=${groupId}`)
    .then((res) => res.ok ? res.json() : [])
    .then((users) => {
      if (!Array.isArray(users)) return;
      userList.innerHTML = '';
      if (!users.length) {
        userList.innerHTML = '<div class="text-muted small">No other members.</div>';
        return;
      }
      users.forEach((u) => {
        const item = document.createElement('button');
        item.className = 'list-group-item list-group-item-action bg-transparent text-start text-light border-0';
        item.innerHTML = `<i class="fa-solid fa-user me-2"></i><span class="username">${u.username}</span>`;
        item.addEventListener('click', () => openDmModal(u.id));
        userList.appendChild(item);
      });
    })
    .catch(() => {
      userList.innerHTML = '<div class="text-muted small">Unable to load members.</div>';
    });
}

async function restoreLastGroup() {
  const last = loadLastGroup();
  if (!last) return;
  const btn = document.querySelector(`[data-group-id="${last}"]`);
  const label = btn?.getAttribute('data-group-name') || btn?.querySelector('.group-name')?.textContent.trim();
  if (btn && label) {
    await setCurrentGroup(last, label);
  }
}

function updateSecretDots() {
  document.querySelectorAll('[data-secret-dot]').forEach((el) => {
    const gid = Number(el.getAttribute('data-secret-dot'));
    const on = !!state.secrets[gid];
    el.classList.toggle('on', on);
  });
}

async function checkGroupNotifications() {
  try {
    const res = await fetch('/api/groups/summary');
    if (!res.ok) return;
    const data = await res.json();
    if (!Array.isArray(data)) return;
    data.forEach((g) => {
      const latest = g.latest ? new Date(g.latest).getTime() : 0;
      const seen = state.seen[g.group_id] || 0;
      const hasNew = latest > seen;
      const dot = document.querySelector(`[data-secret-dot="${g.group_id}"]`);
      if (dot) dot.classList.toggle('on', hasNew || !!state.secrets[g.group_id]);
    });
  } catch (err) {
    // swallow notification errors to avoid breaking UI
  }
}

function openMediaModal(meta) {
  const modalBody = document.getElementById('mediaModalBody');
  if (!modalBody || !meta || !meta.renderedUrl) return;
  modalBody.innerHTML = '';
  const mime = (meta.mime || '').toLowerCase();
  if (mime.startsWith('image/')) {
    const img = document.createElement('img');
    img.src = meta.renderedUrl;
    img.className = 'img-fluid rounded';
    modalBody.appendChild(img);
  } else if (mime.startsWith('video/')) {
    const video = document.createElement('video');
    video.src = meta.renderedUrl;
    video.controls = true;
    video.autoplay = true;
    video.className = 'w-100 rounded';
    modalBody.appendChild(video);
  }
  const modalEl = document.getElementById('mediaModal');
  if (modalEl) bootstrap.Modal.getOrCreateInstance(modalEl).show();
}

function showInfoModal(title, message) {
  const modal = document.getElementById('infoModal');
  if (!modal) return;
  document.getElementById('infoModalTitle').textContent = title || 'Notice';
  document.getElementById('infoModalBody').textContent = message || '';
  bootstrap.Modal.getOrCreateInstance(modal).show();
}

async function reactMessage(id, value, likeBtn, dislikeBtn, msg) {
  const resp = await fetch(`/api/messages/${id}/react`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
    body: JSON.stringify({ value }),
  });
  if (!resp.ok) return;
  const data = await resp.json();
  const likeCount = data.likes ?? msg.likes ?? 0;
  const dislikeCount = data.dislikes ?? msg.dislikes ?? 0;
  const likedBy = data.liked_by || [];
  const dislikedBy = data.disliked_by || [];
  const likeEl = likeBtn.querySelector('.like-count');
  const dislikeEl = dislikeBtn.querySelector('.dislike-count');
  if (likeEl) likeEl.textContent = likeCount;
  if (dislikeEl) dislikeEl.textContent = dislikeCount;
  likeBtn.title = likedBy.length ? `Liked by ${likedBy.join(', ')}` : 'No likes yet';
  dislikeBtn.title = dislikedBy.length ? `Disliked by ${dislikedBy.join(', ')}` : 'No dislikes yet';
  // update liked-by text if present
  const container = likeBtn.closest('.bubble');
  const likedByEl = container?.querySelector('.text-muted.small');
  if (likedByEl) likedByEl.textContent = likedBy.length ? `Liked by ${likedBy.join(', ')}` : '';
  // update dislike tooltip in meta if needed
}

let typingTimeout;
function signalTyping() {
  clearTimeout(typingTimeout);
  fetch('/api/presence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
    body: JSON.stringify({ status: 'online', typing: true }),
  });
  typingTimeout = setTimeout(() => {
    fetch('/api/presence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
      body: JSON.stringify({ status: 'online', typing: false }),
    });
  }, 1500);
}

bindUI();
connectPresence();

function startAutoRefresh() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    if (state.currentGroup && state.secrets[state.currentGroup]) {
      loadMessages(state.currentGroup, { skipSecretPrompt: true });
    }
  }, 45000);
}

async function setCurrentGroup(groupId, groupName) {
  state.currentGroup = Number(groupId);
  document.getElementById('chat-title').textContent = groupName || 'Chat';
  state.messages[state.currentGroup] = [];
  state.seen[state.currentGroup] = 0;
  const list = document.getElementById('message-list');
  if (list) list.innerHTML = '';
  await ensureSecret(state.currentGroup);
  await loadMessages(state.currentGroup, { notify: false });
  loadGroupUsers(state.currentGroup);
  updateSecretDots();
  startAutoRefresh();
}

function initEmojiPicker() {
  const btn = document.getElementById('emoji-btn');
  const picker = document.getElementById('emoji-picker');
  const input = document.getElementById('message-input');
  if (!btn || !picker || !input) return;
  const emojis = [
    '😀','😁','😂','🤣','😅','😊','😍','😘','😎','🤩','😇','😉','🙃','😜','🤔','🤨','😐','😑','😶','🙄',
    '😏','😴','🤯','🥳','😤','😢','😭','😡','🤬','🤢','🤮','🤧','🥶','🥵','🤒','🤕','🤑','🤠','😈','👻',
    '💀','🤖','🎃','🙈','🙉','🙊','👀','👋','👍','👎','👏','🙌','🙏','💪','💯','🔥','✨','💫','🎉',
    '❤️','🧡','💛','💚','💙','💜','🖤','🤍','💔','💕','💖','💗','💓','💞','💢','💤','💥','💨','💦',
    '🍀','☀️','🌙','⭐','⚡','☁️','🌈','❄️','☂️'
  ];
  const render = () => {
    if (state.emojiPickerReady) return;
    picker.innerHTML = '';
    emojis.forEach((emoji) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = emoji;
      b.addEventListener('click', () => {
        const cursor = input.selectionStart || input.value.length;
        const before = input.value.slice(0, cursor);
        const after = input.value.slice(cursor);
        input.value = `${before}${emoji}${after}`;
        input.focus();
        toggleEmojiPicker(false);
      });
      picker.appendChild(b);
    });
    state.emojiPickerReady = true;
  };
  const toggleEmojiPicker = (force) => {
    render();
    const show = typeof force === 'boolean' ? force : picker.classList.contains('d-none');
    picker.classList.toggle('d-none', !show);
  };
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleEmojiPicker();
  });
  document.addEventListener('click', (e) => {
    if (!picker.classList.contains('d-none') && !picker.contains(e.target) && e.target !== btn) {
      toggleEmojiPicker(false);
    }
  });
}

function attachGroupButtonHandler(btn) {
  btn.addEventListener('click', async () => {
    const gid = Number(btn.getAttribute('data-group-id'));
    const label = btn.getAttribute('data-group-name') || btn.querySelector('.group-name')?.textContent.trim() || 'Chat';
    await setCurrentGroup(gid, label);
    resetNotifications();
    persistLastGroup(gid);
  });
}

function attachDeleteGroupHandler(btn) {
  btn.addEventListener('click', async (e) => {
    e.stopPropagation();
    const groupId = Number(btn.getAttribute('data-delete-group'));
    const name = btn.getAttribute('data-group-name') || 'this group';
    if (!groupId) return;
    pendingDeleteGroupId = groupId;
    const nameEl = document.getElementById('delete-group-name');
    if (nameEl) nameEl.textContent = name;
    if (!deleteModalInstance) {
      deleteModalInstance = bootstrap.Modal.getOrCreateInstance(document.getElementById('deleteGroupModal'));
    }
    deleteModalInstance.show();
  });
}

function addGroupToSidebar(groupId, groupName) {
  const container = document.querySelector('.contact-list');
  if (!container) return;
  const wrapper = document.createElement('div');
  wrapper.className = 'list-group-item d-flex justify-content-between align-items-center bg-transparent text-start text-light border-0';
  const btn = document.createElement('button');
  btn.className = 'btn btn-link text-start text-light flex-grow-1 position-relative';
  btn.setAttribute('data-group-id', groupId);
  btn.setAttribute('data-group-name', groupName);
  btn.innerHTML = `<i class="fa-solid fa-hashtag me-2"></i><span class="group-name">${groupName}</span>
    <span class="secret-dot ms-2" data-secret-dot="${groupId}"></span>`;
  attachGroupButtonHandler(btn);
  wrapper.appendChild(btn);
  container.appendChild(wrapper);
}

function removeGroupFromSidebar(groupId) {
  const btn = document.querySelector(`[data-group-id="${groupId}"]`);
  const wrapper = btn?.closest('.list-group-item');
  if (wrapper) wrapper.remove();
}
