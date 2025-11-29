const encoder = new TextEncoder();

const state = {
  currentGroup: null,
  secrets: {},
  keyCache: {},
  seen: {},
  oldest: {},
  loadingOlder: {},
  loadingMessages: {},
  copyCounts: {},
  mediaCache: new Map(),
  messages: {},
  notifications: { count: 0, mention: false },
  emojiPickerReady: false,
  notificationsAllowed: false,
  freezeRefresh: false,
  presenceSeen: {},
};

let refreshTimer = null;
let audioCtx = null;

let secretResolver = null;
let secretModalInstance = null;
let deleteModalInstance = null;
let deleteMessageModalInstance = null;
let pendingDeleteMessageId = null;
let pendingDeleteGroupId = null;
const secretState = { groupId: null };
let infoModalInstance = null;
let mediaRecorder = null;
let recordChunks = [];
let isRecording = false;
let presenceSource = null;
let sseRetryDelay = 1000;
let sseRefreshDebounce = null;
let messageSpinnerState = { visible: false, showTimer: null, hideTimer: null, start: 0 };
const CLIPBOARD_DEBUG = window.__HW_CLIPBOARD_DEBUG !== false; // set to false to silence copy logs
const GROUP_DEBUG = window.__HW_GROUP_DEBUG !== false; // set to false to silence group select logs
const PRESENCE_TOAST_COOLDOWN = 15000; // ms

function updateScrollTopButton() {
  const scrollTopBtn = document.getElementById('scroll-top-btn');
  const list = document.getElementById('message-list');
  if (!scrollTopBtn) return;
  const hasListOverflow = list && list.scrollHeight - list.clientHeight > 20;
  const scroller = hasListOverflow ? list : document.scrollingElement || document.documentElement;
  const scrollable = scroller && scroller.scrollHeight - scroller.clientHeight > 20;
  if (!scrollable) {
    scrollTopBtn.classList.remove('show');
    scrollTopBtn.setAttribute('aria-hidden', 'true');
    return;
  }
  const nearTop = scroller.scrollTop <= 20;
  const nearBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 20;
  const direction = nearTop && !nearBottom ? 'down' : 'up';
  const icon = scrollTopBtn.querySelector('i');
  if (icon) icon.className = direction === 'down' ? 'fa-solid fa-arrow-down' : 'fa-solid fa-arrow-up';
  scrollTopBtn.dataset.direction = direction;
  scrollTopBtn.setAttribute('aria-label', direction === 'down' ? 'Scroll to bottom' : 'Scroll to top');
  scrollTopBtn.title = direction === 'down' ? 'Go to newest' : 'Go to top';
  scrollTopBtn.classList.add('show');
  scrollTopBtn.setAttribute('aria-hidden', 'false');
}

function isNearBottom(listEl, threshold = 120) {
  if (!listEl) return true;
  const distance = listEl.scrollHeight - listEl.scrollTop - listEl.clientHeight;
  return distance < threshold;
}

function scrollToBottom(listEl) {
  if (!listEl) return;
  const go = () => {
    listEl.scrollTop = listEl.scrollHeight;
    if (listEl.lastElementChild) {
      listEl.lastElementChild.scrollIntoView({ block: 'end' });
    }
  };
  go();
  requestAnimationFrame(go);
  setTimeout(go, 80);
}

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

function getCurrentUserId() {
  const shell = document.querySelector('.chat-shell');
  const raw = shell?.getAttribute('data-user-id');
  const parsed = raw ? Number(raw) : null;
  return Number.isFinite(parsed) ? parsed : null;
}

function getCurrentUsername() {
  const shell = document.querySelector('.chat-shell');
  return (shell?.getAttribute('data-username')) || '';
}

function getDefaultAvatar() {
  const shell = document.querySelector('.chat-shell');
  return shell?.dataset?.defaultAvatar || '/static/img/icon.svg';
}

function allowMessageDelete() {
  const shell = document.querySelector('.chat-shell');
  return (shell?.dataset?.allowDelete || 'false') === 'true';
}

function aiActionsEnabled() {
  const shell = document.querySelector('.chat-shell');
  return (shell?.dataset?.aiEnabled || 'false') === 'true';
}

function makeCopyButton(messageId, title, onCopy) {
  const btn = document.createElement('button');
  btn.className = 'btn btn-sm reaction-download align-self-start copy-btn';
  btn.title = title || 'Copy';
  const icon = document.createElement('i');
  icon.className = 'fa-solid fa-copy';
  const countSpan = document.createElement('span');
  countSpan.className = 'copy-count ms-1';
  countSpan.textContent = state.copyCounts[messageId] || 0;
  btn.appendChild(icon);
  btn.appendChild(countSpan);
  btn.addEventListener('click', async () => {
    let ok = false;
    try {
      if (CLIPBOARD_DEBUG) console.debug('[copy] click', { messageId, title });
      ok = await onCopy();
    } catch (err) {
      if (CLIPBOARD_DEBUG) console.error('[copy] handler error', err);
      ok = false;
    }
    // Treat undefined as success to avoid blocking counter/feedback on soft failures.
    const success = ok !== false;
    if (CLIPBOARD_DEBUG) console.debug('[copy] result', { success, ok });
    if (success) {
      state.copyCounts[messageId] = (state.copyCounts[messageId] || 0) + 1;
      countSpan.textContent = state.copyCounts[messageId];
    }
  });
  return btn;
}

function ensureToastBridge() {
  if (window.showToast) return;
  const fallbackToast = (type = 'info', title = '', message = '') => {
    const text = title ? `${title}: ${message}` : message;
    if (type === 'error') alert(text || 'Notice');
    else console.log(text);
  };
  if (typeof bootstrap === 'undefined' || !bootstrap.Toast) {
    window.showToast = fallbackToast;
    return;
  }
  const containerId = 'hw-toast-container';
  let container = document.getElementById(containerId);
  if (!container) {
    container = document.createElement('div');
    container.id = containerId;
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    document.body.appendChild(container);
  }
  const typeClass = (type) => {
    const map = { success: 'success', info: 'info', warning: 'warning', error: 'danger' };
    return map[type] || 'info';
  };
  window.showToast = (type = 'info', title = '', message = '') => {
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${typeClass(type)} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">
          ${title ? `<strong class="me-1">${title}</strong>` : ''}${message || ''}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    `;
    container.appendChild(toastEl);
    const toast = bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 3500, autohide: true });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
  };
}

function parseChatCommand(text) {
  if (!text.startsWith('/')) return null;
  const [cmd, ...rest] = text.trim().split(/\s+/);
  const target = rest.join(' ').trim();
  const me = getCurrentUsername() || 'Someone';
  const cmdLower = cmd.toLowerCase();
  if (cmdLower === '/ai') {
    if (!target) return null;
    return { action: 'ai', icon: '🤖', text: target };
  }
  if (cmdLower === '/slap' || cmdLower === '/slaps') {
    if (!target) return null;
    return { action: 'slap', icon: '🤚🐟', text: `${me} slaps ${target} with a wet trout` };
  }
  if (cmdLower === '/wave' || cmdLower === '/waves') {
    return { action: 'wave', icon: '👋', text: `${me} waves enthusiastically` };
  }
  if (cmdLower === '/shrug') {
    return { action: 'shrug', icon: '🤷', text: `${me} shrugs` };
  }
  if (cmdLower === '/me') {
    if (!target) return null;
    return { action: 'me', icon: '✨', text: `${me} ${target}` };
  }
  return null;
}

function deriveActionFromText(meta, plaintext) {
  if (meta && meta.action) return meta;
  if (!plaintext || !plaintext.startsWith('/')) return meta || {};
  const cmd = parseChatCommand(plaintext);
  if (!cmd) return meta || {};
  return { action: cmd.action, icon: cmd.icon, act_text: cmd.text };
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

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeLanguage(langRaw) {
  if (!langRaw) return '';
  const lang = langRaw.toLowerCase();
  if (lang === 'py' || lang === 'python') return 'python';
  if (lang === 'cs' || lang === 'csharp' || lang === 'c#') return 'csharp';
  return lang;
}

function simpleHighlight(code, lang) {
  const safe = escapeHtml(code || '');
  let highlighted = safe
    .replace(/("[^"]*"|'[^']*')/g, '<span class="code-str">$1</span>')
    .replace(/(#.*)$/gm, '<span class="code-cmt">$1</span>')
    .replace(/(\/\/.*)$/gm, '<span class="code-cmt">$1</span>')
    .replace(/(\/\*[^]*?\*\/)/gm, '<span class="code-cmt">$1</span>')
    .replace(/(\b\d+(?:\.\d+)?\b)/g, '<span class="code-num">$1</span>');
  const kwMap = {
    python: ['def', 'return', 'import', 'from', 'as', 'class', 'for', 'while', 'if', 'elif', 'else', 'try', 'except', 'with', 'lambda', 'yield', 'pass', 'raise', 'in', 'is', 'not', 'and', 'or', 'None', 'True', 'False'],
    csharp: ['public', 'private', 'protected', 'internal', 'class', 'struct', 'interface', 'void', 'int', 'string', 'bool', 'return', 'using', 'namespace', 'new', 'var', 'foreach', 'for', 'while', 'if', 'else', 'switch', 'case', 'break', 'continue', 'null', 'true', 'false', 'async', 'await', 'static'],
  };
  const kws = kwMap[lang] || [];
  if (kws.length) {
    const regex = new RegExp(`\\b(${kws.join('|')})\\b`, 'g');
    highlighted = highlighted.replace(regex, '<span class="code-kw">$1</span>');
  }
  return highlighted;
}

function renderCodeBlock(code, langRaw) {
  const lang = normalizeLanguage(langRaw);
  const label = lang === 'python' ? 'Python' : lang === 'csharp' ? 'C#' : (lang ? lang.toUpperCase() : 'Code');
  const body = simpleHighlight(code || '', lang);
  return `
    <div class="code-block" data-lang="${label}">
      <div class="code-block__meta">
        <span class="code-pill">${label}</span>
      </div>
      <pre><code class="code code-${lang || 'plain'}">${body}</code></pre>
    </div>
  `;
}

function renderPlainTextSegment(text) {
  const safe = escapeHtml(text || '');
  return highlightMentions(linkify(safe)).replace(/\n/g, '<br>');
}

function renderRichText(text) {
  if (!text) return '';
  const parts = [];
  const fenceRegex = /```([\w#+-]+)?\s*[\r\n]([\s\S]*?)```|\[code(?:\s+lang=([\w#+-]+))?\]([\s\S]*?)\[\/code\]/gi;
  let lastIndex = 0;
  let match;
  while ((match = fenceRegex.exec(text)) !== null) {
    const before = text.slice(lastIndex, match.index);
    if (before) parts.push(renderPlainTextSegment(before));
    const langRaw = match[1] || match[3] || '';
    const code = match[2] || match[4] || '';
    parts.push(renderCodeBlock(code, langRaw));
    lastIndex = match.index + match[0].length;
  }
  const tail = text.slice(lastIndex);
  if (tail) parts.push(renderPlainTextSegment(tail));
  return parts.join('');
}

function loadPersistedSecrets() {
  try {
    const uid = getCurrentUserId();
    const keySession = uid ? `hw-secrets-${uid}` : 'hw-secrets';
    const keyLocal = uid ? `hw-secrets-${uid}` : 'hw-secrets';
    const rawSession = sessionStorage.getItem(keySession);
    const rawLocal = localStorage.getItem(keyLocal);
    const parsed = rawSession ? JSON.parse(rawSession) : rawLocal ? JSON.parse(rawLocal) : {};
    if (parsed && typeof parsed === 'object') {
      state.secrets = { ...parsed, ...state.secrets };
    }
  } catch (e) {
    // ignore parse errors
  }
}

function loadLastGroup() {
  try {
    const uid = getCurrentUserId();
    const keySession = uid ? `hw-last-group-${uid}` : 'hw-last-group';
    const keyLocal = uid ? `hw-last-group-${uid}` : 'hw-last-group';
    const rawSession = sessionStorage.getItem(keySession);
    const rawLocal = localStorage.getItem(keyLocal);
    const raw = rawSession || rawLocal;
    if (!raw) return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  } catch (e) {
    return null;
  }
}

function persistLastGroup(groupId) {
  try {
    const uid = getCurrentUserId();
    const keySession = uid ? `hw-last-group-${uid}` : 'hw-last-group';
    const keyLocal = uid ? `hw-last-group-${uid}` : 'hw-last-group';
    sessionStorage.setItem(keySession, String(groupId));
    localStorage.setItem(keyLocal, String(groupId));
  } catch (e) {
    // ignore
  }
}

function persistSecret(groupId, secret) {
  const gid = Number(groupId);
  if (!gid || !secret) return;
  try {
    const uid = getCurrentUserId();
    const keySession = uid ? `hw-secrets-${uid}` : 'hw-secrets';
    const keyLocal = uid ? `hw-secrets-${uid}` : 'hw-secrets';
    const rawSession = sessionStorage.getItem(keySession);
    const rawLocal = localStorage.getItem(keyLocal);
    const parsed = rawSession ? JSON.parse(rawSession) : rawLocal ? JSON.parse(rawLocal) : {};
    parsed[gid] = secret;
    const serialized = JSON.stringify(parsed);
    sessionStorage.setItem(keySession, serialized);
    localStorage.setItem(keyLocal, serialized);
  } catch (e) {
    // ignore storage errors
  }
}

function removePersistedSecret(groupId) {
  const gid = Number(groupId);
  if (!gid) return;
  try {
    const uid = getCurrentUserId();
    const keySession = uid ? `hw-secrets-${uid}` : 'hw-secrets';
    const keyLocal = uid ? `hw-secrets-${uid}` : 'hw-secrets';
    const rawSession = sessionStorage.getItem(keySession);
    const rawLocal = localStorage.getItem(keyLocal);
    const parsed = rawSession ? JSON.parse(rawSession) : rawLocal ? JSON.parse(rawLocal) : {};
    delete parsed[gid];
    const serialized = JSON.stringify(parsed);
    sessionStorage.setItem(keySession, serialized);
    localStorage.setItem(keyLocal, serialized);
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

function ensureAudio() {
  if (!audioCtx) {
    try {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    } catch (e) {
      audioCtx = null;
    }
  }
  return audioCtx;
}

async function resumeAudio() {
  const ctx = ensureAudio();
  if (ctx && ctx.state === 'suspended') {
    try {
      await ctx.resume();
    } catch (e) {
      // ignore
    }
  }
}

function playSound(kind) {
  const ctx = ensureAudio();
  if (!ctx) return;
  if (ctx.state === 'suspended') {
    ctx.resume().catch(() => {});
  }
  const freqMap = {
    like: 880,
    dislike: 220,
    inbound: 660,
    outbound: 520,
  };
  const duration = 0.12;
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.frequency.value = freqMap[kind] || 480;
  gain.gain.setValueAtTime(0.05, ctx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
  osc.connect(gain).connect(ctx.destination);
  osc.start();
  osc.stop(ctx.currentTime + duration);
}

function updateBubbleReactions(bubble, msg) {
  if (!bubble) return;
  const likeEl = bubble.querySelector('.like-count');
  const dislikeEl = bubble.querySelector('.dislike-count');
  if (likeEl) likeEl.textContent = msg.likes ?? 0;
  if (dislikeEl) dislikeEl.textContent = msg.dislikes ?? 0;
  const likeBtn = bubble.querySelector('.reaction-like');
  const dislikeBtn = bubble.querySelector('.reaction-dislike');
  if (likeBtn) likeBtn.title = msg.liked_by?.length ? `Liked by ${msg.liked_by.join(', ')}` : 'No likes yet';
  if (dislikeBtn) dislikeBtn.title = msg.disliked_by?.length ? `Disliked by ${msg.disliked_by.join(', ')}` : 'No dislikes yet';
  const likedByEl = bubble.querySelector('.text-muted.small');
  if (likedByEl) likedByEl.textContent = msg.liked_by?.length ? `Liked by ${msg.liked_by.join(', ')}` : '';
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

async function renderMessage(container, msg, self, groupId, opts = {}) {
  const { prepend = false } = opts;
  const bubble = document.createElement('div');
  bubble.className = `bubble ${self ? 'self' : 'other'}`;
  bubble.setAttribute('data-message-id', msg.id);
  let meta = {};
  try { meta = JSON.parse(msg.meta || '{}'); } catch (err) { meta = {}; }
  const body = document.createElement('div');
  const metaLine = document.createElement('div');
  metaLine.className = 'meta';
  const uploadedBy = msg.sender_name ? ` • by ${msg.sender_name}` : '';
  metaLine.textContent = `${formatTime(msg.created_at)}${uploadedBy}`;
  const actions = document.createElement('div');
  actions.className = 'd-flex align-items-center gap-3 mt-2 actions';
  const actionMeta = deriveActionFromText(meta, msg.plaintext);
  const isAction = actionMeta && (actionMeta.action || (msg.plaintext || '').startsWith('/'));

  if (meta.type === 'media') {
    body.className = 'd-flex flex-column gap-2';
    const preview = document.createElement('div');
    preview.className = 'w-100 mt-1 media-preview';
    if (meta.blob_id) {
      const mime = (meta.mime || '').toLowerCase();
      const isAudio = mime.startsWith('audio/');
      const isDoc = mime.startsWith('application/');
      if (isAudio) {
        preview.classList.add('media-audio');
        preview.innerHTML = '';
        const iconWrap = document.createElement('div');
        iconWrap.className = 'd-flex justify-content-center';
        iconWrap.innerHTML = '<i class="fa-solid fa-music fa-2x text-muted"></i>';
        const nameRow = document.createElement('div');
        nameRow.className = 'text-muted small fw-semibold filename-row text-center';
        nameRow.textContent = meta.name || 'Audio';
        const playerWrap = document.createElement('div');
        playerWrap.className = 'w-100 mt-2';
        preview.appendChild(iconWrap);
        preview.appendChild(nameRow);
        preview.appendChild(playerWrap);
        const renderInline = () => decryptMedia(msg, meta, { target: playerWrap, inline: true, groupId });
        if (!state.secrets[groupId]) {
          ensureSecret(groupId).then((secret) => { if (secret) renderInline(); });
        } else {
          renderInline();
        }
      } else if (!isDoc) {
        preview.innerHTML = '';
        if (meta.name) {
          const nameRow = document.createElement('div');
          nameRow.className = 'text-muted small fw-semibold filename-row';
          nameRow.textContent = meta.name;
          body.appendChild(nameRow);
        }
        const renderInline = () => decryptMedia(msg, meta, { target: preview, inline: true, groupId });
        if (!state.secrets[groupId]) {
          ensureSecret(groupId).then((secret) => { if (secret) renderInline(); });
        } else {
          renderInline();
        }
        preview.addEventListener('click', async () => {
          if (!meta.renderedUrl) {
            await decryptMedia(msg, meta, { inline: false, groupId });
          }
          openMediaModal(meta);
        });
      } else {
        preview.innerHTML = '';
        const docWrap = document.createElement('div');
        docWrap.className = 'd-flex flex-column align-items-center text-center w-100';
        const iconRow = document.createElement('div');
        iconRow.className = 'text-muted';
        if (isAudio) {
          iconRow.innerHTML = '<i class="fa-solid fa-music fa-2x"></i>';
        } else {
          iconRow.innerHTML = '<i class="fa-solid fa-file-lines fa-2x"></i>';
        }
        const nameRow = document.createElement('div');
        nameRow.className = 'text-muted small filename-row mt-1';
        nameRow.textContent = meta.name || 'Document';
        docWrap.appendChild(iconRow);
        docWrap.appendChild(nameRow);
        preview.appendChild(docWrap);
      }
      const dlBtn = document.createElement('button');
      dlBtn.className = 'btn btn-sm reaction-download align-self-start';
      dlBtn.innerHTML = '<i class="fa-solid fa-download"></i>';
      dlBtn.addEventListener('click', () => decryptMedia(msg, meta, { download: true, groupId }));
      actions.appendChild(dlBtn);
      if (mime.startsWith('image/')) {
        const copyImgBtn = makeCopyButton(msg.id, 'Copy image', () => copyImageFromMeta(msg, meta, groupId));
        actions.appendChild(copyImgBtn);
      }
    }
    body.appendChild(preview);
  } else if (isAction) {
    if (actionMeta.action === 'ai') bubble.classList.add('ai');
    body.className = 'action-box';
    body.innerHTML = '';
    const iconLine = document.createElement('div');
    iconLine.className = 'action-icon text-center';
    const actIcon = actionMeta.icon || (actionMeta.action === 'slap' ? '🤚🐟' : actionMeta.action === 'wave' ? '👋' : actionMeta.action === 'shrug' ? '🤷' : '✨');
    iconLine.textContent = actIcon;
    const textLine = document.createElement('div');
    textLine.className = 'text-center w-100 fw-bold';
    const actText = actionMeta.act_text || actionMeta.text || msg.plaintext || '';
    let displayText = actText;
    if (actionMeta.icon && displayText.startsWith(actionMeta.icon)) {
      const regex = new RegExp(`^${escapeRegex(actionMeta.icon)}\\s*`);
      displayText = displayText.replace(regex, '');
    }
    textLine.textContent = displayText;
    body.appendChild(iconLine);
    body.appendChild(textLine);
    const actionGifs = {
      slap: 'slap.gif',
      wave: 'wave.gif',
      shrug: 'shrug.gif',
    };
    if (actionMeta.action && actionGifs[actionMeta.action]) {
      const gif = document.createElement('img');
      gif.src = `${window.location.origin}/static/img/${actionGifs[actionMeta.action]}`;
      gif.alt = actionMeta.action;
      gif.className = 'action-gif mt-2';
      body.appendChild(gif);
    }
  } else {
    const text = msg.plaintext || '[cipher]';
    const html = renderRichText(text);
    body.innerHTML = html;
    const contentLength = Number.isFinite(meta?.len) ? meta.len : text.length;
    if (contentLength > 240 || text.split(/\s+/).some((word) => word.length > 42)) {
      bubble.classList.add('long-text');
    }
    const copyBtn = makeCopyButton(msg.id, 'Copy text', () => copyTextToClipboard(text));
    copyBtn.classList.add('mt-2');
    actions.appendChild(copyBtn);
    const yt = text.match(/https?:\/\/[^\s]+/);
    if (yt && isYouTube(yt[0])) {
      body.insertAdjacentHTML('beforeend', youtubeEmbed(yt[0]));
    }
  }
  if (self && allowMessageDelete()) {
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-sm btn-outline-danger';
    deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
    deleteBtn.title = 'Delete message';
    deleteBtn.addEventListener('click', () => {
      pendingDeleteMessageId = msg.id;
      const modalEl = document.getElementById('deleteMessageModal');
      if (!deleteMessageModalInstance && modalEl) {
        deleteMessageModalInstance = bootstrap.Modal.getOrCreateInstance(modalEl);
      }
      deleteMessageModalInstance?.show();
    });
    actions.prepend(deleteBtn);
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
  if (prepend && container.firstChild) {
    container.insertBefore(bubble, container.firstChild);
  } else {
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
  }
}

async function decryptMedia(msg, meta, opts = {}) {
  const { download = false, inline = false, target = null, groupId = state.currentGroup } = opts;
  try {
    const secret = await ensureSecret(groupId);
    if (!secret) return;
    // Use cached decrypted URL if available
    const cached = state.mediaCache.get(meta.blob_id);
    if (cached && cached.url) {
      meta.renderedUrl = cached.url;
    }
    let url = meta.renderedUrl;
    if (!url) {
      const resp = await fetch(`/api/blob/${meta.blob_id}`, { cache: 'force-cache' });
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
      url = URL.createObjectURL(blob);
      meta.renderedUrl = url;
      state.mediaCache.set(meta.blob_id, { url });
    }
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
      } else if (mime === 'application/pdf') {
        // PDF preview intentionally disabled; only download available.
        target.innerHTML = '<div class="text-muted small">PDF ready. Use Download to view.</div>';
      } else if (mime.startsWith('application/')) {
        target.innerHTML = '<div class="text-muted small">Document ready. Use Download to view.</div>';
      } else {
        target.innerHTML = '<div class="text-muted small">File ready. Use Download.</div>';
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

function toggleMessageSpinner(show) {
  const spinner = document.getElementById('message-loading');
  if (!spinner) return;
  const MIN_VISIBLE = 220;
  const SHOW_DELAY = 120;
  const clearTimers = () => {
    if (messageSpinnerState.showTimer) {
      clearTimeout(messageSpinnerState.showTimer);
      messageSpinnerState.showTimer = null;
    }
    if (messageSpinnerState.hideTimer) {
      clearTimeout(messageSpinnerState.hideTimer);
      messageSpinnerState.hideTimer = null;
    }
  };

  if (show) {
    // Cancel pending hides and avoid re-showing if already visible
    if (messageSpinnerState.hideTimer) {
      clearTimeout(messageSpinnerState.hideTimer);
      messageSpinnerState.hideTimer = null;
    }
    if (messageSpinnerState.visible) return;
    clearTimers();
    messageSpinnerState.showTimer = setTimeout(() => {
      spinner.classList.remove('d-none');
      messageSpinnerState.visible = true;
      messageSpinnerState.start = Date.now();
    }, SHOW_DELAY);
    return;
  }

  // Hide with minimum visible duration
  if (messageSpinnerState.showTimer) {
    clearTimeout(messageSpinnerState.showTimer);
    messageSpinnerState.showTimer = null;
  }
  if (!messageSpinnerState.visible) return;
  const elapsed = Date.now() - (messageSpinnerState.start || 0);
  const hideNow = () => {
    spinner.classList.add('d-none');
    messageSpinnerState.visible = false;
    messageSpinnerState.start = 0;
  };
  if (elapsed >= MIN_VISIBLE) {
    hideNow();
  } else {
    messageSpinnerState.hideTimer = setTimeout(() => {
      hideNow();
      messageSpinnerState.hideTimer = null;
    }, MIN_VISIBLE - elapsed);
  }
}

async function loadMessages(groupId, opts = {}) {
  const {
    skipSecretPrompt = false,
    notify = true,
    forceRefresh = false,
    before = null,
    prepend = false,
    forceLatest = false,
    showSpinner = true,
  } = opts;
  const list = document.getElementById('message-list');
  const wasNearBottom = isNearBottom(list);
  const prevHeight = list?.scrollHeight || 0;
  const prevScrollTop = list?.scrollTop || 0;
  if (state.loadingMessages[groupId]) return;
  state.loadingMessages[groupId] = true;
  const allowSpinner = showSpinner && !prepend;
  let spinnerShown = false;
  try {
    if (!state.messages[groupId]) state.messages[groupId] = [];
    if (!state.oldest[groupId]) state.oldest[groupId] = null;
    const hasExisting = state.messages[groupId].length > 0 && !forceRefresh;
    if (!state.secrets[groupId] && !skipSecretPrompt) {
      await ensureSecret(groupId);
      if (!state.secrets[groupId]) return; // user cancelled
    }
    if (allowSpinner) {
      toggleMessageSpinner(true);
      spinnerShown = true;
    }

    let data = [];
    try {
      const url = new URL(`/api/messages`, window.location.origin);
      url.searchParams.set('group_id', groupId);
      if (before) url.searchParams.set('before', before);
      const res = await fetch(url.toString(), { cache: 'no-store' });
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
    const newMessages = forceRefresh
      ? data
      : hasExisting
        ? data.filter((m) => new Date(m.created_at).getTime() > lastSeen)
        : data;
    if (hasExisting && newMessages.length === 0 && !forceRefresh && !prepend) return;
    if (!hasExisting || forceRefresh) {
      if (!forceRefresh) {
        list.innerHTML = '';
        state.messages[groupId] = [];
      }
    }
    const secret = state.secrets[groupId];
    let playedInbound = false;
    const targetMessages = newMessages;
    for (const msg of targetMessages) {
      const bubble = list.querySelector(`[data-message-id="${msg.id}"]`);
      if (forceRefresh && bubble) {
        updateBubbleReactions(bubble, msg);
        continue;
      }
      if (state.messages[groupId].includes(msg.id) && prepend) continue;
      let plaintext = '[encrypted]';
      if (secret && msg.ciphertext) {
        plaintext = await decryptText(msg, secret, groupId);
      }
      msg.plaintext = plaintext;
      const isSelf = msg.sender_id === Number(document.querySelector('.chat-shell').dataset.userId);
      await renderMessage(list, msg, isSelf, groupId, { prepend });
      if (!state.messages[groupId].includes(msg.id)) {
        state.messages[groupId].push(msg.id);
      }
      if (notify && !isSelf) {
        const mentionHit = messageMentionsUser(plaintext);
        updateNotificationIcon(1, mentionHit);
        showBrowserNotification('New message', plaintext.slice(0, 80) || 'Encrypted message');
        if (!playedInbound) {
          playSound('inbound');
          playedInbound = true;
        }
      }
    }
    if (prepend && list) {
      const newHeight = list.scrollHeight;
      const delta = newHeight - prevHeight;
      list.scrollTop = prevScrollTop + delta;
    } else if (forceRefresh && list && !forceLatest) {
      const newHeight = list.scrollHeight;
      const delta = newHeight - prevHeight;
      list.scrollTop = prevScrollTop + delta;
    } else if (forceLatest && list) {
      [0, 80, 200, 400].forEach((delay) => setTimeout(() => scrollToBottom(list), delay));
    } else if (wasNearBottom && !prepend && list?.lastElementChild) {
      list.lastElementChild.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
    // Update scroll-top control visibility after rendering messages.
    requestAnimationFrame(() => {
      if (typeof updateScrollTopButton === 'function') updateScrollTopButton();
    });
    // mark latest seen
    if (lastMsg) {
      state.seen[groupId] = new Date(lastMsg.created_at).getTime();
    }
    if (newMessages.length) {
      const oldest = newMessages[0];
      state.oldest[groupId] = oldest.created_at;
    } else if (!prepend) {
      state.seen[groupId] = 0;
    }
  } finally {
    state.loadingMessages[groupId] = false;
    if (spinnerShown) toggleMessageSpinner(false);
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
  const command = parseChatCommand(text);
  if (command?.action === 'ai') {
    input.value = '';
    await handleAiQuestion(command.text);
    return;
  }
  const payloadText = command ? `${command.icon || ''} ${command.text}`.trim() : text;
  const ok = await sendEncryptedMessage(payloadText, {
    type: 'text',
    len: payloadText.length,
    ...(command ? { action: command.action, icon: command.icon, text: command.text } : {}),
  });
  if (ok) {
    input.value = '';
    await loadMessages(state.currentGroup, { notify: false });
    startAutoRefresh();
    playSound('outbound');
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
  } else {
    let reason = 'Upload failed.';
    try {
      const data = await resp.json();
      reason = data.reason || data.error || reason;
    } catch (e) {
      // ignore parse
    }
    if (resp.status === 400 && reason === 'Upload failed.') {
      reason = 'File exceeds maximum size or type is blocked.';
    }
    showInfoModal('Upload blocked', reason);
  }
}

function toggleUploadSpinner(show) {
  const spinner = document.getElementById('upload-spinner');
  if (!spinner) return;
  spinner.classList.toggle('d-none', !show);
}

async function sendEncryptedMessage(text, meta = {}) {
  if (!state.currentGroup) {
    showInfoModal('Select a group', 'Choose a group first.');
    return false;
  }
  const content = (text || '').trim();
  if (!content) return false;
  const secret = await ensureSecret(state.currentGroup);
  if (!secret) return false;
  const encrypted = await encryptText(content, secret, state.currentGroup);
  const payloadMeta = {
    type: 'text',
    len: content.length,
    ...meta,
  };
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
      meta: JSON.stringify(payloadMeta),
    }),
  });
  return resp.ok;
}

function appendLocalBubble(text, { self = false, ai = false, spinner = false, small = false, actionIcon = '', actionStack = false } = {}) {
  const list = document.getElementById('message-list');
  if (!list) return null;
  const bubble = document.createElement('div');
  bubble.className = `bubble ${self ? 'self' : 'other'} ${ai ? 'ai' : ''}`;
  const body = document.createElement('div');
  if (spinner) {
    body.className = 'ai-thinking';
    body.innerHTML = `<i class="fa-solid fa-robot"></i> <span>${text}</span> <div class="spinner-border spinner-border-sm text-accent" role="status"></div>`;
  } else if (actionStack && actionIcon) {
    body.className = 'action-stack';
    body.innerHTML = `<div class="action-icon">${actionIcon}</div><div class="action-text">${text}</div>`;
  } else {
    body.textContent = actionIcon ? `${actionIcon} ${text}` : text;
  }
  bubble.appendChild(body);
  if (small) {
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = 'AI assistant';
    bubble.appendChild(meta);
  }
  list.appendChild(bubble);
  scrollToBottom(list);
  return bubble;
}

async function handleAiQuestion(question) {
  if (!aiActionsEnabled()) {
    showInfoModal('AI disabled', 'AI actions are turned off.');
    return;
  }
  if (!question) {
    showInfoModal('Need a question', 'Type something after /ai.');
    return;
  }
  const secret = await ensureSecret(state.currentGroup);
  if (!secret) return;
  const username = getCurrentUsername() || 'You';
  const questionText = `${username} asks AI: ${question}`;
  const userBubble = appendLocalBubble(questionText, {
    self: true,
    ai: false,
    spinner: false,
    actionIcon: '🤖',
    actionStack: true,
  });
  const thinkingBubble = appendLocalBubble('Thinking...', { ai: true, spinner: true, small: true });
  await sendEncryptedMessage(questionText, { action: 'ai', icon: '🤖', act_text: questionText });
  try {
    const resp = await fetch('/api/ai/ask', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
      body: JSON.stringify({ question }),
    });
    if (!resp.ok) {
      let msg = 'AI request failed';
      try {
        const errJson = await resp.json();
        if (errJson.error === 'ratelimit') {
          msg = 'Too many AI requests. Try again in a bit.';
        } else {
          msg = errJson.detail || errJson.error || msg;
        }
      } catch (e) {
        const text = await resp.text();
        msg = text || msg;
      }
      throw new Error(msg);
    }
    const data = await resp.json();
    const answer = data.answer || 'No response.';
    const answerText = `AI: ${answer}`;
    await sendEncryptedMessage(answerText, { action: 'ai', icon: '🤖', act_text: answerText });
  } catch (err) {
    if (window.showToast) {
      window.showToast('error', 'AI error', err?.message || 'AI unavailable right now.');
    }
    if (thinkingBubble) {
      thinkingBubble.innerHTML = '';
      const body = document.createElement('div');
      body.textContent = err?.message || 'AI unavailable right now.';
      thinkingBubble.appendChild(body);
      const meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = 'AI assistant';
      thinkingBubble.appendChild(meta);
    }
  } finally {
    if (thinkingBubble) {
      const spinnerEl = thinkingBubble.querySelector('.spinner-border');
      if (spinnerEl) spinnerEl.remove();
    }
    if (userBubble) userBubble.remove();
    if (thinkingBubble) thinkingBubble.remove();
    await loadMessages(state.currentGroup, { notify: false, forceRefresh: true, forceLatest: true, showSpinner: false });
  }
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
  if (!text) return false;
  const success = await writeClipboardText(text);
  if (success) {
    showInfoModal('Copied', 'Content copied to clipboard.');
  } else {
    if (CLIPBOARD_DEBUG) console.warn('[copy-text] failed');
    showInfoModal('Copy failed', 'Could not copy to clipboard in this browser.');
  }
  if (CLIPBOARD_DEBUG) console.debug('[copy-text]', { text, success });
  return success;
}

async function copyImageFromMeta(msg, meta, groupId) {
  let copied = false;
  try {
    if (!meta.renderedUrl) {
      if (CLIPBOARD_DEBUG) console.debug('[copy-image] decrypting to get URL');
      await decryptMedia(msg, meta, { inline: false, groupId });
    }
    if (!meta.renderedUrl) {
      showInfoModal('Copy failed', 'No image available to copy.');
      if (CLIPBOARD_DEBUG) console.warn('[copy-image] no renderedUrl after decrypt');
      return false;
    }
    if (CLIPBOARD_DEBUG) console.debug('[copy-image] fetched url', meta.renderedUrl);
    const resp = await fetch(meta.renderedUrl);
    const blob = await resp.blob();
    // Prefer binary copy when supported, otherwise fall back to URL text.
    if (window.ClipboardItem && navigator.clipboard && navigator.clipboard.write) {
      try {
        await navigator.clipboard.write([new ClipboardItem({ [blob.type]: blob })]);
        copied = true;
        showInfoModal('Copied', 'Image copied to clipboard.');
        if (CLIPBOARD_DEBUG) console.debug('[copy-image] binary copy success');
        return true;
      } catch (err) {
        if (CLIPBOARD_DEBUG) console.warn('[copy-image] binary copy failed, fallback to URL', err);
        // fall back to link copy below
      }
    }
  } catch (err) {
    if (CLIPBOARD_DEBUG) console.error('[copy-image] failed', err);
    try {
      // ignore and attempt link copy below
    } catch (e) {
      // ignore
    }
  }
  if (!copied && meta.renderedUrl) {
    const urlCopied = await writeClipboardText(meta.renderedUrl);
    if (urlCopied) {
      showInfoModal('Copied link', 'Image link copied. Paste to share.');
      if (CLIPBOARD_DEBUG) console.debug('[copy-image] url copy success');
      return true;
    }
  }
  if (CLIPBOARD_DEBUG) console.warn('[copy-image] all copy attempts failed');
  showInfoModal('Copy failed', 'Could not copy image to clipboard in this browser.');
  return false;
}

async function copyMediaLink(meta, msg, groupId) {
  try {
    if (!meta.renderedUrl) {
      await decryptMedia(msg, meta, { inline: false, groupId });
    }
    if (!meta.renderedUrl) {
      showInfoModal('Copy failed', 'No media link available.');
      if (CLIPBOARD_DEBUG) console.warn('[copy-link] no renderedUrl');
      return false;
    }
    if (CLIPBOARD_DEBUG) console.debug('[copy-link] trying text copy', meta.renderedUrl);
    return await copyTextToClipboard(meta.renderedUrl);
  } catch (err) {
    showInfoModal('Copy failed', 'Could not copy link.');
    if (CLIPBOARD_DEBUG) console.error('[copy-link] failed', err);
    return false;
  }
}

async function writeClipboardText(text) {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      if (CLIPBOARD_DEBUG) console.debug('[clipboard] navigator.clipboard.writeText success');
      return true;
    }
  } catch (err) {
    if (CLIPBOARD_DEBUG) console.warn('[clipboard] navigator.clipboard.writeText failed', err);
    // fall through to legacy path
  }
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '-1000px';
    textarea.setAttribute('aria-hidden', 'true');
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    const succeeded = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (CLIPBOARD_DEBUG) console.debug('[clipboard] execCommand copy result', succeeded);
    return succeeded;
  } catch (err) {
    if (CLIPBOARD_DEBUG) console.error('[clipboard] execCommand failed', err);
    return false;
  }
}

function bindUI() {
  const list = document.getElementById('message-list');
  const scrollTopBtn = document.getElementById('scroll-top-btn');
  loadPersistedSecrets();
  document.getElementById('send-btn')?.addEventListener('click', (e) => {
    resumeAudio();
    sendMessage();
  });
  document.getElementById('message-input')?.addEventListener('keyup', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
    signalTyping();
  });

  document.getElementById('attach-btn')?.addEventListener('click', () => {
    resumeAudio();
    document.getElementById('file-input').click();
  });
  document.getElementById('file-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    sendFile(file);
    e.target.value = '';
  });

  document.getElementById('record-btn')?.addEventListener('click', () => {
    resumeAudio();
    toggleRecording();
  });
  document.getElementById('refresh-btn')?.addEventListener('click', () => {
    if (state.currentGroup && state.secrets[state.currentGroup]) {
      loadMessages(state.currentGroup, { skipSecretPrompt: true, notify: false, forceRefresh: true, forceLatest: true });
    }
  });

  initEmojiPicker();

  // join handled inline

  document.querySelectorAll('[data-group-id]').forEach(attachGroupButtonHandler);
  updateSecretDots();
  restoreLastGroup();

  const deleteMessageModalEl = document.getElementById('deleteMessageModal');
  if (deleteMessageModalEl) {
    deleteMessageModalInstance = bootstrap.Modal.getOrCreateInstance(deleteMessageModalEl);
    document.getElementById('confirm-delete-message')?.addEventListener('click', async () => {
      if (!pendingDeleteMessageId || !state.currentGroup) return;
      const bubble = document.querySelector(`[data-message-id="${pendingDeleteMessageId}"]`);
      await deleteMessage(pendingDeleteMessageId, state.currentGroup, bubble);
      pendingDeleteMessageId = null;
      deleteMessageModalInstance.hide();
    });
    deleteMessageModalEl.addEventListener('hidden.bs.modal', () => { pendingDeleteMessageId = null; });
  }

  (async () => {
    if (state.currentGroup) return;
    const first = document.querySelector('[data-group-id]');
    if (first) {
      const gid = Number(first.getAttribute('data-group-id'));
      const label = first.getAttribute('data-group-name') || first.querySelector('.group-name')?.textContent.trim();
      await setCurrentGroup(gid, label || 'Chat', { forceLatest: true });
    }
  })();

  document.querySelectorAll('.delete-group').forEach(attachDeleteGroupHandler);

  const sidebarEl = document.getElementById('groupSidebar');
  if (sidebarEl) {
    const collapseInst = bootstrap.Collapse.getOrCreateInstance(sidebarEl, { toggle: false });
    collapseInst.hide();
    const sidebarToggle = document.querySelector('[data-bs-target="#groupSidebar"]');
    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', (e) => {
        e.preventDefault();
        collapseInst.toggle();
      });
    }
    sidebarEl.addEventListener('show.bs.collapse', () => { state.freezeRefresh = true; });
    sidebarEl.addEventListener('hide.bs.collapse', () => { state.freezeRefresh = false; startAutoRefresh(); });
  }

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

  if (scrollTopBtn) {
    scrollTopBtn.addEventListener('click', () => {
      if (!list) return;
      const dir = scrollTopBtn.dataset.direction || 'up';
      const hasListOverflow = list && list.scrollHeight - list.clientHeight > 20;
      if (dir === 'down') {
        if (hasListOverflow) {
          scrollToBottom(list);
        } else {
          const scroller = document.scrollingElement || document.documentElement;
          scroller.scrollTo({ top: scroller.scrollHeight, behavior: 'smooth' });
        }
      } else {
        if (hasListOverflow) {
          list.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      }
    });
    // Ensure the button sits between the message list and input without overlaying content.
    const btnContainer = scrollTopBtn.parentElement;
    if (btnContainer) {
      btnContainer.style.display = 'flex';
      btnContainer.style.justifyContent = 'flex-end';
      btnContainer.style.padding = '0 0.25rem 0.5rem 0.25rem';
    }
    window.addEventListener('scroll', updateScrollTopButton, { passive: true });
  }

  const msgList = list;
  if (msgList) {
    msgList.addEventListener('scroll', () => {
      updateScrollTopButton();
      const gid = state.currentGroup;
      if (!gid || state.loadingOlder[gid]) return;
      if (msgList.scrollTop < 20 && state.oldest[gid]) {
        state.loadingOlder[gid] = true;
        loadMessages(gid, { before: state.oldest[gid], prepend: true, notify: false, skipSecretPrompt: true })
          .finally(() => { state.loadingOlder[gid] = false; });
      }
    });
    updateScrollTopButton();
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
      setCurrentGroup(data.group_id, groupName, { forceLatest: true });
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
      const rememberPermanent = document.getElementById('remember-secret-permanent')?.checked;
      const errorEl = document.getElementById('secret-error');
      if (!val) {
        errorEl.classList.remove('d-none');
        return;
      }
      fetch('/api/groups/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify({ group_id: gid, secret: val }),
      }).then((resp) => {
        if (!resp.ok) {
          errorEl.classList.remove('d-none');
          errorEl.textContent = 'Secret did not match this group.';
          return;
        }
        errorEl.classList.add('d-none');
        state.secrets[gid] = val;
        if (remember) {
          persistSecret(gid, val);
        } else {
          removePersistedSecret(gid);
        }
        if (rememberPermanent) {
          try {
            const rawLocal = localStorage.getItem('hw-secrets');
            const parsed = rawLocal ? JSON.parse(rawLocal) : {};
            parsed[gid] = val;
            localStorage.setItem('hw-secrets', JSON.stringify(parsed));
          } catch (e) {
            // ignore
          }
        }
        if (secretResolver) {
          secretResolver(val);
          secretResolver = null;
        }
        secretModalInstance.hide();
      }).catch(() => {
        errorEl.classList.remove('d-none');
        errorEl.textContent = 'Could not verify secret. Try again.';
      });
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
        deleteModalInstance.hide();
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
        const list = document.querySelector('.contact-list');
        if (list && !list.querySelector(`[data-group-id="${data.group_id}"]`)) {
          addGroupToSidebar(data.group_id, data.name || 'DM', { deletable: true });
          updateSecretDots();
        }
        await setCurrentGroup(data.group_id, data.name || 'Chat', { forceLatest: true });
        document.getElementById('dm-secret').value = '';
        bootstrap.Modal.getOrCreateInstance(document.getElementById('dmModal')).hide();
        const sidebarEl = document.getElementById('groupSidebar');
        if (sidebarEl) {
          const inst = bootstrap.Collapse.getOrCreateInstance(sidebarEl, { toggle: false });
          inst.hide();
        }
      }
    });
  }

  const infoBtn = document.getElementById('info-indicator');
  if (infoBtn) {
    infoBtn.addEventListener('click', () => {
      requestNotificationPermission();
      resetNotifications();
    });
  }

  // checkGroupNotifications disabled to reduce rate limits
  startAutoRefresh();
}

function connectPresence() {
  const label = document.getElementById('presence-label');
  const typingIndicator = document.getElementById('typing-indicator');
  if (presenceSource) {
    presenceSource.close();
  }
  try {
    const source = new EventSource('/events/presence');
    presenceSource = source;
    source.onopen = () => {
      sseRetryDelay = 1000;
      if (label) label.textContent = 'Live updates';
    };
    source.onerror = () => {
      source.close();
      presenceSource = null;
      if (label) label.textContent = 'Reconnecting…';
      setTimeout(connectPresence, Math.min(sseRetryDelay, 30000));
      sseRetryDelay = Math.min(sseRetryDelay * 2, 30000);
      startAutoRefresh();
    };
    source.onmessage = (event) => {
      let payload = null;
      try {
        payload = JSON.parse(event.data);
      } catch (err) {
        return;
      }
      if (!payload || payload.type === 'ping') return;
      if (!payload.event || payload.event === 'presence') {
        if (label && payload.status) {
          label.textContent = `Presence: ${payload.status}`;
        }
        if (typingIndicator) {
          const isSelf = Number(document.querySelector('.chat-shell')?.dataset.userId || 0) === payload.user_id;
          typingIndicator.classList.toggle('d-none', !payload.typing || isSelf);
        }
        maybeShowPresenceToast(payload);
        return;
      }
      if (payload.event === 'message') {
        scheduleMessageRefresh(payload.group_id, { notify: true, forceRefresh: true });
      }
      if (payload.event === 'reaction') {
        scheduleMessageRefresh(payload.group_id, { notify: false, forceRefresh: true, spinner: false });
      }
      if (payload.event === 'delete') {
        const gid = payload.group_id;
        const mid = payload.message_id;
        if (gid && state.messages[gid]) {
          state.messages[gid] = state.messages[gid].filter((id) => id !== mid);
        }
        const list = document.getElementById('message-list');
        const bubble = list?.querySelector(`[data-message-id="${mid}"]`);
        bubble?.remove();
        scheduleMessageRefresh(gid, { notify: false, forceRefresh: true, spinner: false });
      }
    };
  } catch (err) {
    startAutoRefresh();
  }
}

function maybeShowPresenceToast(payload) {
  try {
    const { user_id: uid, username, status, group_id: gid } = payload || {};
    const currentUserId = getCurrentUserId();
    if (!uid || uid === currentUserId) return;
    if (!gid || gid !== state.currentGroup) return;
    if (status !== 'online') return;
    const key = `${gid}:${uid}`;
    const now = Date.now();
    const last = state.presenceSeen[key] || 0;
    if (now - last < PRESENCE_TOAST_COOLDOWN) return;
    state.presenceSeen[key] = now;
    const name = username || 'Someone';
    if (window.showToast) {
      window.showToast('info', 'New connection', `User ${name} connected`);
    }
  } catch (err) {
    // ignore presence toast errors
  }
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
        const avatar = u.avatar_url || getDefaultAvatar();
        item.innerHTML = `<img class="avatar avatar-sm me-2" src="${avatar}" alt="${u.username} avatar" onerror="this.src='${getDefaultAvatar()}'"><span class="username">${u.username}</span>`;
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
    await setCurrentGroup(last, label, { forceLatest: true });
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

function showInfoModal(title, message, type = 'info') {
  ensureToastBridge();
  const noticeTitle = title || 'Notice';
  const noticeMsg = message || '';
  let usedToast = false;
  try {
    if (window.showToast) {
      window.showToast(type, noticeTitle, noticeMsg);
      usedToast = true;
    }
  } catch (err) {
    usedToast = false;
  }
  if (usedToast) return;
  // Fallback only if toast unavailable/failed.
  const modalEl = document.getElementById('infoModal');
  const modalTitle = document.getElementById('infoModalTitle');
  const modalBody = document.getElementById('infoModalBody');
  if (modalEl && modalTitle && modalBody && typeof bootstrap !== 'undefined') {
    modalTitle.textContent = noticeTitle;
    modalBody.textContent = noticeMsg;
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
    return;
  }
  alert((title ? `${title}: ` : '') + (message || ''));
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
  msg.likes = likeCount;
  msg.dislikes = dislikeCount;
  likeBtn.title = likedBy.length ? `Liked by ${likedBy.join(', ')}` : 'No likes yet';
  dislikeBtn.title = dislikedBy.length ? `Disliked by ${dislikedBy.join(', ')}` : 'No dislikes yet';
  // update liked-by text if present
  const container = likeBtn.closest('.bubble');
  const likedByEl = container?.querySelector('.text-muted.small');
  if (likedByEl) likedByEl.textContent = likedBy.length ? `Liked by ${likedBy.join(', ')}` : '';
  // keep scroll position by avoiding full list reloads
  playSound(value === 'like' ? 'like' : 'dislike');
}

async function deleteMessage(id, groupId, bubble) {
  const resp = await fetch(`/api/messages/${id}`, {
    method: 'DELETE',
    headers: { 'X-CSRFToken': getCsrfToken() },
  });
  if (!resp.ok) {
    showInfoModal('Delete failed', 'Could not delete this message.');
    return false;
  }
  const data = await resp.json();
  if (!data?.ok) {
    showInfoModal('Delete failed', data.error || 'Unable to delete message.');
    return false;
  }
  if (state.messages[groupId]) {
    state.messages[groupId] = state.messages[groupId].filter((mid) => mid !== id);
  }
  if (bubble?.remove) {
    bubble.remove();
  } else {
    const existing = document.querySelector(`[data-message-id="${id}"]`);
    existing?.remove();
  }
  if (groupId) {
    scheduleMessageRefresh(groupId, { notify: false, forceRefresh: true, spinner: false });
  }
  try {
    if (window.showToast) {
      window.showToast('success', 'Deleted', 'Message removed.');
    }
  } catch (err) {
    showInfoModal('Deleted', 'Message removed.');
  }
  return true;
}

let typingTimeout;
function signalTyping() {
  clearTimeout(typingTimeout);
  sendPresenceStatus(state.currentGroup, { typing: true });
  typingTimeout = setTimeout(() => {
    sendPresenceStatus(state.currentGroup, { typing: false });
  }, 1500);
}

function sendPresenceStatus(groupId, { status = 'online', typing = false } = {}) {
  if (!groupId) return;
  fetch('/api/presence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
    body: JSON.stringify({ status, typing, group_id: groupId }),
  }).catch(() => {});
}

bindUI();
connectPresence();

function startAutoRefresh() {
  clearInterval(refreshTimer);
  // Refresh is now event-driven via SSE; polling disabled.
}

function scheduleMessageRefresh(groupId, { notify = true, forceRefresh = false, spinner = true } = {}) {
  if (!groupId || groupId !== state.currentGroup) return;
  if (sseRefreshDebounce) return;
  sseRefreshDebounce = setTimeout(() => {
    loadMessages(groupId, { skipSecretPrompt: true, notify, forceRefresh, showSpinner: spinner });
    sseRefreshDebounce = null;
  }, 250);
}

async function setCurrentGroup(groupId, groupName, { forceLatest = true } = {}) {
  if (GROUP_DEBUG) console.debug('[group] setCurrentGroup start', { groupId, groupName, forceLatest });
  state.currentGroup = Number(groupId);
  document.getElementById('chat-title').textContent = groupName || 'Chat';
  state.messages[state.currentGroup] = [];
  state.seen[state.currentGroup] = 0;
  const list = document.getElementById('message-list');
  if (list) list.innerHTML = '';
  const secret = await ensureSecret(state.currentGroup);
  if (!secret) {
    if (GROUP_DEBUG) console.warn('[group] ensureSecret returned falsy', { groupId });
    state.currentGroup = null;
    if (list) list.innerHTML = '';
    document.getElementById('chat-title').textContent = 'Select a group';
    return;
  }
  if (GROUP_DEBUG) console.debug('[group] secret obtained, loading messages');
  await loadMessages(state.currentGroup, { notify: false, forceLatest });
  if (forceLatest && list) {
    [0, 80, 200, 400].forEach((delay) => setTimeout(() => scrollToBottom(list), delay));
  }
  loadGroupUsers(state.currentGroup);
  updateSecretDots();
  startAutoRefresh();
  persistLastGroup(state.currentGroup);
  sendPresenceStatus(state.currentGroup, { typing: false, status: 'online' });
  if (GROUP_DEBUG) console.debug('[group] setCurrentGroup done', { currentGroup: state.currentGroup });
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
    if (GROUP_DEBUG) console.debug('[group] sidebar click', { gid, label });
    await setCurrentGroup(gid, label, { forceLatest: true });
    sendPresenceStatus(gid, { typing: false, status: 'online' });
    resetNotifications();
    persistLastGroup(gid);
    const sidebarEl = document.getElementById('groupSidebar');
    if (sidebarEl) {
      const inst = bootstrap.Collapse.getOrCreateInstance(sidebarEl, { toggle: false });
      inst.hide();
      state.freezeRefresh = false;
      setTimeout(() => { state.freezeRefresh = false; }, 300);
    }
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

function addGroupToSidebar(groupId, groupName, { deletable = false } = {}) {
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
  if (deletable) {
    const del = document.createElement('button');
    del.className = 'btn btn-outline-danger btn-sm delete-group';
    del.setAttribute('data-delete-group', groupId);
    del.setAttribute('data-group-name', groupName);
    del.innerHTML = '<i class="fa-solid fa-trash"></i>';
    attachDeleteGroupHandler(del);
    wrapper.appendChild(del);
  }
  container.appendChild(wrapper);
}

function removeGroupFromSidebar(groupId) {
  const btn = document.querySelector(`[data-group-id="${groupId}"]`);
  const wrapper = btn?.closest('.list-group-item');
  if (wrapper) wrapper.remove();
}
