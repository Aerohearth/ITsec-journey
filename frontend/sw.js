const CACHE = 'socforge-v1';
const SHELL = ['./index.html', './manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Never intercept API calls to the backend
  if (url.port === '8000') return;
  e.respondWith(caches.match(e.request).then(hit => hit || fetch(e.request)));
});
