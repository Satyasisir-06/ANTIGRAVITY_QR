// =============================================================================
// SERVICE WORKER - Enhanced Caching for Performance
// Implements: Cache-first for static, Network-first for API, Stale-while-revalidate
// =============================================================================

const CACHE_VERSION = 'v2';
const STATIC_CACHE = `qr-attendance-static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `qr-attendance-dynamic-${CACHE_VERSION}`;
const IMAGE_CACHE = `qr-attendance-images-${CACHE_VERSION}`;

// Static assets to cache immediately
const STATIC_ASSETS = [
    '/',
    '/static/style.css',
    '/static/backjs.js',
    '/static/performance.css',
    '/static/performance.js',
    '/static/manifest.json',
    '/static/icon-192.png',
    '/static/icon-512.png',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
];

// Routes that should use network-first strategy
const NETWORK_FIRST_ROUTES = [
    '/api/',
    '/get_qr',
    '/mark_attendance',
    '/start_session',
    '/finalize_session',
    '/student/refresh_attendance',
    '/admin/'
];

// Routes to never cache
const NO_CACHE_ROUTES = [
    '/logout',
    '/login'
];

// =============================================================================
// INSTALL EVENT - Pre-cache static assets
// =============================================================================
self.addEventListener('install', event => {
    console.log('[SW] Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('[SW] Pre-caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                // Skip waiting to activate immediately
                return self.skipWaiting();
            })
    );
});

// =============================================================================
// ACTIVATE EVENT - Clean up old caches
// =============================================================================
self.addEventListener('activate', event => {
    console.log('[SW] Activating...');
    
    event.waitUntil(
        caches.keys()
            .then(keys => {
                return Promise.all(
                    keys
                        .filter(key => {
                            // Delete old version caches
                            return key.startsWith('qr-attendance') && 
                                   key !== STATIC_CACHE && 
                                   key !== DYNAMIC_CACHE &&
                                   key !== IMAGE_CACHE;
                        })
                        .map(key => {
                            console.log('[SW] Deleting old cache:', key);
                            return caches.delete(key);
                        })
                );
            })
            .then(() => {
                // Claim all clients immediately
                return self.clients.claim();
            })
    );
});

// =============================================================================
// FETCH EVENT - Smart caching strategies
// =============================================================================
self.addEventListener('fetch', event => {
    const request = event.request;
    const url = new URL(request.url);

    // Only handle GET requests
    if (request.method !== 'GET') {
        return;
    }

    // Skip no-cache routes
    if (NO_CACHE_ROUTES.some(route => url.pathname.startsWith(route))) {
        return;
    }

    // Determine caching strategy
    if (isStaticAsset(url)) {
        // Cache-first for static assets
        event.respondWith(cacheFirst(request, STATIC_CACHE));
    } else if (isImageAsset(url)) {
        // Cache-first for images with fallback
        event.respondWith(cacheFirstWithFallback(request, IMAGE_CACHE));
    } else if (isNetworkFirstRoute(url)) {
        // Network-first for API calls
        event.respondWith(networkFirst(request, DYNAMIC_CACHE));
    } else {
        // Stale-while-revalidate for HTML pages
        event.respondWith(staleWhileRevalidate(request, DYNAMIC_CACHE));
    }
});

// =============================================================================
// CACHING STRATEGIES
// =============================================================================

// Cache-first: Try cache, fall back to network
async function cacheFirst(request, cacheName) {
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
        return cachedResponse;
    }
    
    try {
        const networkResponse = await fetch(request);
        if (networkResponse.ok) {
            const cache = await caches.open(cacheName);
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
    } catch (error) {
        console.log('[SW] Cache-first network error:', error);
        return new Response('Offline', { status: 503 });
    }
}

// Cache-first with image placeholder fallback
async function cacheFirstWithFallback(request, cacheName) {
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
        return cachedResponse;
    }
    
    try {
        const networkResponse = await fetch(request);
        if (networkResponse.ok) {
            const cache = await caches.open(cacheName);
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
    } catch (error) {
        // Return a placeholder for images
        return new Response(
            '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect fill="#f0f0f0" width="100" height="100"/><text x="50" y="50" text-anchor="middle" dy=".3em" fill="#999">Offline</text></svg>',
            { headers: { 'Content-Type': 'image/svg+xml' } }
        );
    }
}

// Network-first: Try network, fall back to cache
async function networkFirst(request, cacheName) {
    try {
        const networkResponse = await fetch(request);
        if (networkResponse.ok) {
            const cache = await caches.open(cacheName);
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
    } catch (error) {
        console.log('[SW] Network-first falling back to cache');
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        return new Response(JSON.stringify({ error: 'Offline' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// Stale-while-revalidate: Return cache immediately, update in background
async function staleWhileRevalidate(request, cacheName) {
    const cache = await caches.open(cacheName);
    const cachedResponse = await caches.match(request);
    
    // Fetch in background
    const fetchPromise = fetch(request).then(networkResponse => {
        if (networkResponse.ok) {
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
    }).catch(error => {
        console.log('[SW] Background fetch failed:', error);
        return null;
    });
    
    // Return cached response immediately, or wait for network
    return cachedResponse || fetchPromise;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function isStaticAsset(url) {
    const staticExtensions = ['.css', '.js', '.woff', '.woff2', '.ttf', '.eot'];
    return staticExtensions.some(ext => url.pathname.endsWith(ext)) ||
           url.pathname.startsWith('/static/') ||
           url.hostname === 'cdnjs.cloudflare.com';
}

function isImageAsset(url) {
    const imageExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico'];
    return imageExtensions.some(ext => url.pathname.endsWith(ext));
}

function isNetworkFirstRoute(url) {
    return NETWORK_FIRST_ROUTES.some(route => url.pathname.startsWith(route));
}

// =============================================================================
// BACKGROUND SYNC (for offline attendance marking)
// =============================================================================

self.addEventListener('sync', event => {
    if (event.tag === 'sync-attendance') {
        event.waitUntil(syncPendingAttendance());
    }
});

async function syncPendingAttendance() {
    // Get pending attendance from IndexedDB (if implemented)
    // This is a placeholder for future offline-first functionality
    console.log('[SW] Syncing pending attendance...');
}

// =============================================================================
// PUSH NOTIFICATIONS (optional)
// =============================================================================

self.addEventListener('push', event => {
    if (!event.data) return;
    
    const data = event.data.json();
    const options = {
        body: data.body || 'New notification',
        icon: '/static/icon-192.png',
        badge: '/static/icon-192.png',
        vibrate: [100, 50, 100],
        data: { url: data.url || '/' }
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title || 'QR Attendance', options)
    );
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    
    event.waitUntil(
        clients.openWindow(event.notification.data.url)
    );
});

console.log('[SW] Service Worker loaded');
