const CACHE_VERSION = 'v17';
const CACHE_NAME = `hashwhisper-cache-${CACHE_VERSION}`;
const ASSETS = [
  '/',
  '/static/css/styles.css',
  '/static/js/main.js',
  '/static/js/chat.js',
  '/static/img/icon.svg',
  '/static/manifest.json',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((k) => (k === CACHE_NAME ? null : caches.delete(k))))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  const isStatic = url.origin === self.location.origin && (url.pathname.startsWith('/static/') || url.pathname === '/');
  const isHtml = request.headers.get('accept')?.includes('text/html');

  if (!isStatic && !isHtml) return;

  event.respondWith(networkFirst(request));
});

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    const copy = response.clone();
    caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
    return response;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    throw err;
  }
}
