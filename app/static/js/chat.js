const encoder = new TextEncoder();

const state = {
  currentGroup: null,
  secrets: {},
  keyCache: {},
  seen: {},
};

let refreshTimer = null;

let secretResolver = null;
let secretModalInstance = null;
let deleteModalInstance = null;
let pendingDeleteGroupId = null;
const secretState = { groupId: null };
let infoModalInstance = null;

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

function formatTime(ts) {
  try {
    const userTz = getUserTimezone();
    const dt = new Date(ts);
    return dt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', timeZone: userTz });
  } catch (err) {
    return new Date(ts).toLocaleTimeString();
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
    }
    body.appendChild(preview);
  } else {
    const text = msg.plaintext || '[cipher]';
    body.innerHTML = linkify(text);
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
  const { skipSecretPrompt = false } = opts;
  const list = document.getElementById('message-list');
  list.innerHTML = '';
  if (!state.secrets[groupId]) {
    if (skipSecretPrompt) return;
    await ensureSecret(groupId);
  }
  const res = await fetch(`/api/messages?group_id=${groupId}`);
  const data = await res.json();
  const secret = state.secrets[groupId];
  for (const msg of data) {
    let plaintext = '[encrypted]';
    if (secret && msg.ciphertext) {
      plaintext = await decryptText(msg, secret, groupId);
    }
    msg.plaintext = plaintext;
    await renderMessage(list, msg, msg.sender_id === Number(document.querySelector('.chat-shell').dataset.userId), groupId);
  }
  if (list.lastElementChild) {
    list.lastElementChild.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }
  // mark latest seen
  const lastMsg = data[data.length - 1];
  if (lastMsg) {
    state.seen[groupId] = new Date(lastMsg.created_at).getTime();
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
    await loadMessages(state.currentGroup);
    startAutoRefresh();
  }
}

async function sendFile(file) {
  if (!state.currentGroup) {
    showInfoModal('Select a group', 'Choose a group or DM before uploading.');
    return;
  }
  if (!file) return;
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
    await loadMessages(state.currentGroup);
    startAutoRefresh();
  }
}

function toggleUploadSpinner(show) {
  const spinner = document.getElementById('upload-spinner');
  if (!spinner) return;
  spinner.classList.toggle('d-none', !show);
}

function bindUI() {
  const list = document.getElementById('message-list');
  document.getElementById('send-btn')?.addEventListener('click', sendMessage);
  document.getElementById('message-input')?.addEventListener('keyup', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
    signalTyping();
  });

  document.getElementById('attach-btn')?.addEventListener('click', () => {
    document.getElementById('file-input').click();
  });
  document.getElementById('file-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    sendFile(file);
    e.target.value = '';
  });

  document.querySelectorAll('[data-group-id]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      state.currentGroup = Number(btn.getAttribute('data-group-id'));
      document.getElementById('chat-title').textContent = btn.textContent.trim();
      await ensureSecret(state.currentGroup);
      await loadMessages(state.currentGroup);
      loadGroupUsers(state.currentGroup);
      startAutoRefresh();
    });
  });

  document.querySelectorAll('.delete-group').forEach((btn) => {
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
  });

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
      location.reload();
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
      const errorEl = document.getElementById('secret-error');
      if (!val) {
        errorEl.classList.remove('d-none');
        return;
      }
      errorEl.classList.add('d-none');
      state.secrets[gid] = val;
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
        location.reload();
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

  setInterval(checkGroupNotifications, 10000);
  startAutoRefresh();
}

function connectPresence() {
  const label = document.getElementById('presence-label');
  const typingIndicator = document.getElementById('typing-indicator');
  const es = new EventSource('/events/presence');
  es.onmessage = (event) => {
    if (!event.data) return;
    const data = JSON.parse(event.data);
    if (data.type === 'ping') return;
    label.textContent = `Presence: user ${data.user_id} is ${data.status}`;
    typingIndicator.classList.toggle('d-none', !data.typing);
  };
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
        item.textContent = u.username;
        item.addEventListener('click', () => openDmModal(u.id));
        userList.appendChild(item);
      });
    })
    .catch(() => {
      userList.innerHTML = '<div class="text-muted small">Unable to load members.</div>';
    });
}

async function checkGroupNotifications() {
  const res = await fetch('/api/groups/summary');
  if (!res.ok) return;
  const data = await res.json();
  data.forEach((g) => {
    const latest = g.latest ? new Date(g.latest).getTime() : 0;
    const seen = state.seen[g.group_id] || 0;
    const badge = document.querySelector(`[data-group-id="${g.group_id}"] .group-badge`);
    if (badge) {
      const hasNew = latest > seen;
      badge.classList.toggle('d-none', !hasNew);
    }
  });
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
  }, 7000);
}
