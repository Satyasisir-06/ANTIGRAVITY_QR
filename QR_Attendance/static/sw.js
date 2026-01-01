
const CACHE_NAME = 'qr-attendance-v1';
const ASSETS = [
    '/',
    '/static/style.css',
    '/static/backjs.js',
    '/static/manifest.json',
    '/static/icon-192.png',
    '/static/icon-512.png',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
];

// Install Event: Cache assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(ASSETS);
        })
    );
});

// Activate Event: Cleanup old caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
            );
        })
    );
});

// Fetch Event: Serve from cache, fallback to network
self.addEventListener('fetch', event => {
    // Only cache GET requests
    if (event.request.method !== 'GET') return;

    event.respondWith(
        caches.match(event.request).then(cachedResponse => {
            return cachedResponse || fetch(event.request).catch(() => {
                // If offline and request is for page navigation, show offline fallback (optional)
                if (event.request.mode === 'navigate') {
                    // return caches.match('/offline.html'); 
                }
            });
        })
    );
});
