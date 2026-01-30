/* =============================================================================
   PERFORMANCE.JS - Mobile Performance & Scroll Optimization
   Fixes: Scroll lag, jank, freezing, lazy loading, and mobile UX
   ============================================================================= */

(function() {
    'use strict';

    // ==========================================================================
    // 1. INTERSECTION OBSERVER - Lazy Loading
    // ==========================================================================

    const lazyLoadObserver = new IntersectionObserver(
        (entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const el = entry.target;

                    // Handle lazy images
                    if (el.tagName === 'IMG' && el.dataset.src) {
                        el.src = el.dataset.src;
                        el.removeAttribute('data-src');
                    }

                    // Handle lazy background images
                    if (el.dataset.bg) {
                        el.style.backgroundImage = `url(${el.dataset.bg})`;
                        el.removeAttribute('data-bg');
                    }

                    // Add loaded class for CSS transitions
                    el.classList.add('loaded');
                    el.classList.remove('lazy');

                    // Unobserve after loading
                    observer.unobserve(el);
                }
            });
        },
        {
            rootMargin: '100px 0px', // Load 100px before entering viewport
            threshold: 0.01
        }
    );

    // Initialize lazy loading
    function initLazyLoading() {
        // Observe all lazy elements
        document.querySelectorAll('.lazy, [data-lazy], img[data-src], [data-bg]').forEach(el => {
            lazyLoadObserver.observe(el);
        });
    }

    // ==========================================================================
    // 2. PASSIVE SCROLL LISTENERS
    // ==========================================================================

    // Store original addEventListener
    const originalAddEventListener = EventTarget.prototype.addEventListener;

    // Events that should be passive by default
    const passiveEvents = ['touchstart', 'touchmove', 'wheel', 'scroll'];

    // Override addEventListener to make scroll events passive
    EventTarget.prototype.addEventListener = function(type, listener, options) {
        let modifiedOptions = options;

        if (passiveEvents.includes(type)) {
            if (typeof options === 'boolean') {
                modifiedOptions = { capture: options, passive: true };
            } else if (typeof options === 'object' || options === undefined) {
                modifiedOptions = { ...options, passive: true };
            }
        }

        return originalAddEventListener.call(this, type, listener, modifiedOptions);
    };

    // ==========================================================================
    // 3. REQUESTANIMATIONFRAME SCROLL HANDLER
    // ==========================================================================

    let scrollTicking = false;
    let lastScrollY = 0;
    const scrollCallbacks = [];

    // Throttled scroll handler using RAF
    function onScroll() {
        lastScrollY = window.scrollY || window.pageYOffset;

        if (!scrollTicking) {
            requestAnimationFrame(() => {
                scrollCallbacks.forEach(callback => {
                    try {
                        callback(lastScrollY);
                    } catch (e) {
                        console.error('Scroll callback error:', e);
                    }
                });
                scrollTicking = false;
            });
            scrollTicking = true;
        }
    }

    // Register scroll callback (use this instead of direct scroll listeners)
    window.registerScrollCallback = function(callback) {
        if (typeof callback === 'function') {
            scrollCallbacks.push(callback);
        }
    };

    // Remove scroll callback
    window.unregisterScrollCallback = function(callback) {
        const index = scrollCallbacks.indexOf(callback);
        if (index > -1) {
            scrollCallbacks.splice(index, 1);
        }
    };

    // ==========================================================================
    // 4. DEBOUNCE & THROTTLE UTILITIES
    // ==========================================================================

    // Debounce function
    window.debounce = function(func, wait = 100) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func.apply(this, args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    };

    // Throttle function
    window.throttle = function(func, limit = 16) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    };

    // RAF-based throttle
    window.rafThrottle = function(func) {
        let ticking = false;
        return function executedFunction(...args) {
            if (!ticking) {
                requestAnimationFrame(() => {
                    func.apply(this, args);
                    ticking = false;
                });
                ticking = true;
            }
        };
    };

    // ==========================================================================
    // 5. PREVENT LAYOUT THRASHING
    // ==========================================================================

    // Batch DOM reads and writes
    const domBatch = {
        reads: [],
        writes: [],
        scheduled: false,

        read(fn) {
            this.reads.push(fn);
            this.schedule();
            return this;
        },

        write(fn) {
            this.writes.push(fn);
            this.schedule();
            return this;
        },

        schedule() {
            if (!this.scheduled) {
                this.scheduled = true;
                requestAnimationFrame(() => this.flush());
            }
        },

        flush() {
            // Execute all reads first
            const reads = this.reads;
            const writes = this.writes;

            this.reads = [];
            this.writes = [];
            this.scheduled = false;

            reads.forEach(fn => fn());
            writes.forEach(fn => fn());
        }
    };

    window.domBatch = domBatch;

    // ==========================================================================
    // 6. VISIBILITY OBSERVER - Optimize off-screen elements
    // ==========================================================================

    const visibilityObserver = new IntersectionObserver(
        (entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.remove('offscreen');
                    entry.target.style.willChange = 'transform, opacity';
                } else {
                    entry.target.classList.add('offscreen');
                    entry.target.style.willChange = 'auto';
                }
            });
        },
        {
            rootMargin: '50px',
            threshold: 0
        }
    );

    // Observe elements for visibility optimization
    function initVisibilityOptimization() {
        document.querySelectorAll('.stat-card, .record-card, .session-card, .running-class-card').forEach(el => {
            visibilityObserver.observe(el);
        });
    }

    // ==========================================================================
    // 7. SKELETON LOADER HELPERS
    // ==========================================================================

    window.showSkeleton = function(container, count = 3, type = 'card') {
        if (!container) return;

        let html = '';
        for (let i = 0; i < count; i++) {
            switch (type) {
                case 'card':
                    html += '<div class="skeleton skeleton-card"></div>';
                    break;
                case 'stat':
                    html += '<div class="skeleton skeleton-stat"></div>';
                    break;
                case 'row':
                    html += `
                        <div class="skeleton-row">
                            <div class="skeleton skeleton-text"></div>
                            <div class="skeleton skeleton-text short"></div>
                            <div class="skeleton skeleton-text"></div>
                        </div>
                    `;
                    break;
                case 'text':
                    html += '<div class="skeleton skeleton-text"></div>';
                    break;
            }
        }
        container.innerHTML = html;
    };

    window.hideSkeleton = function(container) {
        if (!container) return;
        const skeletons = container.querySelectorAll('.skeleton, .skeleton-row');
        skeletons.forEach(s => s.remove());
    };

    // ==========================================================================
    // 8. IMAGE LOADING OPTIMIZATION
    // ==========================================================================

    // Preload critical images
    window.preloadImage = function(src) {
        return new Promise((resolve, reject) => {
            const img = new Image();
            img.onload = () => resolve(img);
            img.onerror = reject;
            img.src = src;
        });
    };

    // Load image with placeholder
    window.loadImageWithPlaceholder = function(imgElement, src, placeholder = '') {
        if (!imgElement) return;

        if (placeholder) {
            imgElement.src = placeholder;
        }

        const tempImg = new Image();
        tempImg.onload = () => {
            imgElement.src = src;
            imgElement.classList.add('loaded');
        };
        tempImg.src = src;
    };

    // ==========================================================================
    // 9. TOUCH OPTIMIZATION
    // ==========================================================================

    // Detect touch device
    const isTouchDevice = ('ontouchstart' in window) || 
                          (navigator.maxTouchPoints > 0) || 
                          (navigator.msMaxTouchPoints > 0);

    if (isTouchDevice) {
        document.body.classList.add('touch-device');
    }

    // Fast click for touch devices (removes 300ms delay)
    function initFastClick() {
        if (!isTouchDevice) return;

        document.addEventListener('touchstart', function(e) {
            const target = e.target.closest('button, a, .tab-btn, .page-btn');
            if (target) {
                target.classList.add('touch-active');
            }
        }, { passive: true });

        document.addEventListener('touchend', function(e) {
            const active = document.querySelector('.touch-active');
            if (active) {
                active.classList.remove('touch-active');
            }
        }, { passive: true });
    }

    // ==========================================================================
    // 10. SCROLL POSITION RESTORATION
    // ==========================================================================

    // Save scroll position before page unload
    window.addEventListener('beforeunload', () => {
        sessionStorage.setItem('scrollPosition', window.scrollY);
    });

    // Restore scroll position (optional, call when needed)
    window.restoreScrollPosition = function() {
        const savedPosition = sessionStorage.getItem('scrollPosition');
        if (savedPosition) {
            window.scrollTo(0, parseInt(savedPosition, 10));
            sessionStorage.removeItem('scrollPosition');
        }
    };

    // ==========================================================================
    // 11. NETWORK-AWARE LOADING
    // ==========================================================================

    // Check connection quality
    window.getConnectionQuality = function() {
        if ('connection' in navigator) {
            const conn = navigator.connection;
            if (conn.saveData) return 'save-data';
            if (conn.effectiveType === '4g') return 'high';
            if (conn.effectiveType === '3g') return 'medium';
            return 'low';
        }
        return 'unknown';
    };

    // Reduce animations on slow connections
    function adaptToConnection() {
        const quality = window.getConnectionQuality();
        if (quality === 'low' || quality === 'save-data') {
            document.body.classList.add('reduce-motion');
            // Reduce image quality if possible
            document.querySelectorAll('img[data-src-low]').forEach(img => {
                img.dataset.src = img.dataset.srcLow;
            });
        }
    }

    // ==========================================================================
    // 12. IDLE CALLBACK - Defer non-critical work
    // ==========================================================================

    // Request idle callback polyfill
    window.requestIdleCallback = window.requestIdleCallback || function(cb) {
        const start = Date.now();
        return setTimeout(() => {
            cb({
                didTimeout: false,
                timeRemaining: () => Math.max(0, 50 - (Date.now() - start))
            });
        }, 1);
    };

    window.cancelIdleCallback = window.cancelIdleCallback || function(id) {
        clearTimeout(id);
    };

    // Queue non-critical tasks
    const idleTasks = [];
    let idleScheduled = false;

    window.queueIdleTask = function(task) {
        idleTasks.push(task);
        if (!idleScheduled) {
            idleScheduled = true;
            requestIdleCallback(processIdleTasks);
        }
    };

    function processIdleTasks(deadline) {
        while (idleTasks.length > 0 && deadline.timeRemaining() > 0) {
            const task = idleTasks.shift();
            try {
                task();
            } catch (e) {
                console.error('Idle task error:', e);
            }
        }

        if (idleTasks.length > 0) {
            requestIdleCallback(processIdleTasks);
        } else {
            idleScheduled = false;
        }
    }

    // ==========================================================================
    // 13. MUTATION OBSERVER - Auto-optimize new content
    // ==========================================================================

    const contentObserver = new MutationObserver((mutations) => {
        mutations.forEach(mutation => {
            mutation.addedNodes.forEach(node => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    // Auto-observe new lazy elements
                    if (node.classList && (node.classList.contains('lazy') || node.dataset.lazy)) {
                        lazyLoadObserver.observe(node);
                    }

                    // Find lazy elements within added node
                    if (node.querySelectorAll) {
                        node.querySelectorAll('.lazy, [data-lazy], img[data-src]').forEach(el => {
                            lazyLoadObserver.observe(el);
                        });
                    }

                    // Optimize new cards
                    if (node.classList && 
                        (node.classList.contains('record-card') || 
                         node.classList.contains('session-card') ||
                         node.classList.contains('stat-card'))) {
                        visibilityObserver.observe(node);
                    }
                }
            });
        });
    });

    // ==========================================================================
    // 14. PERFORMANCE MONITORING
    // ==========================================================================

    window.performanceMetrics = {
        // Measure task duration
        measureTask(name, fn) {
            const start = performance.now();
            const result = fn();
            const duration = performance.now() - start;
            console.log(`[Perf] ${name}: ${duration.toFixed(2)}ms`);
            return result;
        },

        // Report long tasks
        reportLongTasks() {
            if ('PerformanceObserver' in window) {
                const observer = new PerformanceObserver((list) => {
                    list.getEntries().forEach(entry => {
                        if (entry.duration > 50) {
                            console.warn(`[Long Task] Duration: ${entry.duration.toFixed(2)}ms`);
                        }
                    });
                });
                observer.observe({ entryTypes: ['longtask'] });
            }
        },

        // Get FPS
        measureFPS(duration = 1000) {
            return new Promise(resolve => {
                let frames = 0;
                const start = performance.now();

                function countFrame() {
                    frames++;
                    if (performance.now() - start < duration) {
                        requestAnimationFrame(countFrame);
                    } else {
                        const fps = Math.round(frames / (duration / 1000));
                        resolve(fps);
                    }
                }

                requestAnimationFrame(countFrame);
            });
        }
    };

    // ==========================================================================
    // 15. INITIALIZATION
    // ==========================================================================

    function init() {
        // Initialize on DOM ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', onReady);
        } else {
            onReady();
        }
    }

    function onReady() {
        // Core initializations
        initLazyLoading();
        initFastClick();
        initVisibilityOptimization();

        // Start scroll listener
        window.addEventListener('scroll', onScroll, { passive: true });

        // Start content observer
        contentObserver.observe(document.body, {
            childList: true,
            subtree: true
        });

        // Adapt to network
        adaptToConnection();

        // Report long tasks in development
        if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
            window.performanceMetrics.reportLongTasks();
        }

        // Mark page as loaded
        document.body.classList.add('page-loaded');

        // Hide loading overlay if exists
        const loadingOverlay = document.querySelector('.page-loading');
        if (loadingOverlay) {
            loadingOverlay.classList.add('hidden');
            setTimeout(() => loadingOverlay.remove(), 300);
        }

        console.log('[Performance] Optimizations initialized');
    }

    // Start initialization
    init();

})();
