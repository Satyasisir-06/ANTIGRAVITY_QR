// --- Student Panel Tab & Calculator Logic ---
function showTab(tabId) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
        tab.style.display = 'none';
    });

    // Remove active class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    const selectedTab = document.getElementById(tabId + '-tab');
    if (selectedTab) {
        selectedTab.classList.add('active');
        selectedTab.style.display = 'block';
    }

    // Activate button
    const clickedBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    if (clickedBtn) {
        clickedBtn.classList.add('active');
    }

    // Save preference
    localStorage.setItem('activeStudentTab', tabId);
}

function calculateAttendance() {
    const attended = parseInt(document.getElementById('calc-attended').value) || 0;
    const total = parseInt(document.getElementById('calc-total').value) || 0;
    const future = parseInt(document.getElementById('calc-future').value) || 0;
    const target = parseInt(document.getElementById('calc-target').value) || 75;

    // Current percentage
    const currentPercentage = total > 0 ? (attended / total * 100) : 0;
    document.getElementById('current-percentage').textContent = currentPercentage.toFixed(2) + '%';
    document.getElementById('current-detail').textContent = `${attended} / ${total} classes`;

    // Total classes by end of semester
    const totalFinal = total + future;

    // Classes needed to reach target at end of semester
    const classesNeededForTarget = Math.ceil((target / 100) * totalFinal);
    const mustAttendMore = Math.max(0, classesNeededForTarget - attended);

    document.getElementById('must-attend').textContent = mustAttendMore;
    document.getElementById('attend-detail').textContent = mustAttendMore > future ?
        `Need ${mustAttendMore - future} more than remaining!` :
        `Out of ${future} remaining classes`;

    // Classes can skip
    const maxSkippable = future - mustAttendMore;
    const canSkip = Math.max(0, maxSkippable);

    document.getElementById('can-skip').textContent = canSkip;
    document.getElementById('skip-detail').textContent = `While maintaining ${target}%`;

    // Alert message
    const alertDiv = document.getElementById('attendance-alert');
    const alertMsg = document.getElementById('alert-message');

    if (currentPercentage >= target) {
        alertDiv.className = 'attendance-success';
        if (canSkip > 0) {
            alertMsg.innerHTML = `<strong>Great!</strong> You're above ${target}%. You can safely skip up to <strong>${canSkip}</strong> future classes.`;
        } else {
            alertMsg.innerHTML = `<strong>Good!</strong> You're at ${target}%. Attend all remaining classes to maintain your percentage.`;
        }
    } else if (currentPercentage >= target - 10) {
        alertDiv.className = 'attendance-warning';
        alertMsg.innerHTML = `<strong>Warning!</strong> Your attendance is ${currentPercentage.toFixed(1)}%. You need to attend at least <strong>${mustAttendMore}</strong> more classes to reach ${target}%.`;
    } else {
        alertDiv.className = 'attendance-danger attendance-warning';
        alertMsg.innerHTML = `<strong>Critical!</strong> Your attendance is only ${currentPercentage.toFixed(1)}%. You must attend <strong>${mustAttendMore}</strong> classes to reach ${target}%.`;
    }
}

function calculateScenario() {
    const attended = parseInt(document.getElementById('calc-attended').value) || 0;
    const total = parseInt(document.getElementById('calc-total').value) || 0;
    const future = parseInt(document.getElementById('calc-future').value) || 0;
    const skipCount = parseInt(document.getElementById('skip-scenario').value) || 0;

    const totalFinal = total + future;
    const attendedFinal = attended + (future - skipCount);
    const projectedPercentage = totalFinal > 0 ? (attendedFinal / totalFinal * 100) : 0;

    const resultEl = document.getElementById('projected-percentage');
    resultEl.textContent = projectedPercentage.toFixed(2) + '%';

    if (projectedPercentage >= 75) {
        resultEl.style.color = '#28a745';
    } else if (projectedPercentage >= 65) {
        resultEl.style.color = '#ffc107';
    } else {
        resultEl.style.color = '#dc3545';
    }
}
let timerInterval;
const activeQRTimers = {};
const activeClassTimers = {};
// serverClockOffset is set globally in admin.html

async function generateQR() {
    const subject = document.getElementById('subject').value;
    const branch = document.getElementById('branch').value;
    const qrResult = document.getElementById('qrResult');
    const qrImage = document.getElementById('qrImage');
    const genBtn = document.getElementById('genBtn');

    if (!subject || !branch) {
        alert('Please enter Subject and select Branch');
        return;
    }

    genBtn.disabled = true;
    genBtn.innerText = "Generating...";

    try {
        const res = await fetch('/get_qr', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subject, branch })
        });

        const data = await res.json();

        if (data.qr_image) {
            qrImage.src = "data:image/png;base64," + data.qr_image;
            qrResult.style.display = 'block';
            startTimer(data.expiry);
        } else {
            alert('Error generating QR');
        }
    } catch (e) {
        console.error(e);
        alert('Internal Error');
    }

    genBtn.disabled = false;
    genBtn.innerText = "Generate Session QR";
}

function startTimer(expiryTimestamp) {
    const timerElem = document.getElementById('timer');

    if (timerInterval) clearInterval(timerInterval);

    function update() {
        const now = Date.now() / 1000;
        const diff = expiryTimestamp - now;

        if (diff <= 0) {
            timerElem.innerText = "EXPIRED";
            timerElem.style.color = "red";
            document.getElementById('qrImage').style.opacity = "0.2";
            clearInterval(timerInterval);
            return;
        }

        const minutes = Math.floor(diff / 60);
        const seconds = Math.floor(diff % 60);
        timerElem.innerText = `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
        timerElem.style.color = "var(--danger-color)";
        document.getElementById('qrImage').style.opacity = "1";
    }

    update();
    timerInterval = setInterval(update, 1000);
}

async function manualAttendance(e) {
    e.preventDefault();
    const roll = document.getElementById('m_roll').value;
    const name = document.getElementById('m_name').value;
    const subject = document.getElementById('m_subject').value;
    const branch = document.getElementById('m_branch').value;
    const msg = document.getElementById('manualMsg');

    // Create a valid expiry for immediate use
    const exp = (Date.now() / 1000) + 60;

    try {
        const res = await fetch('/mark_attendance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ roll, name, subject, branch, exp })
        });
        const data = await res.json();

        if (data.success) {
            msg.innerText = "Attendance Marked!";
            msg.style.color = "var(--success-color)";
            document.getElementById('manualForm').reset();
            setTimeout(() => msg.innerText = "", 3000);
        } else {
            msg.innerText = data.message;
            msg.style.color = "var(--danger-color)";
        }
    } catch (err) {
        msg.innerText = "Error marking attendance";
    }
}

async function addSubject() {
    const name = document.getElementById('new_subject').value;
    if (!name) return;

    if (!confirm('Add subject: ' + name + '?')) return;

    try {
        const res = await fetch('/add_subject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) location.reload();
    } catch (e) {
        alert('Error adding subject');
    }
}

async function registerStudent() {
    const u = document.getElementById('ns_user').value;
    const p = document.getElementById('ns_pass').value;
    if (!u || !p) return;

    try {
        const res = await fetch('/register_student', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();
        alert(data.message);
        if (data.success) {
            document.getElementById('ns_user').value = '';
            document.getElementById('ns_pass').value = '';
        }
    } catch (e) {
        alert('Error registering student');
    }
}

async function deleteSubject(id) {
    if (!confirm('Delete this subject?')) return;

    try {
        const res = await fetch('/delete_subject/' + id, { method: 'POST' });
        const data = await res.json();

        if (data.success) {
            const el = document.getElementById('sub-tag-' + id);
            if (el) el.remove();
        } else {
            alert(data.message);
        }
    } catch (e) {
        alert('Error deleting subject');
    }
}

// Dark Mode Logic
// --- Session Configuration ---
// --- Session Configuration (Multi-Session Support) ---

function toggleSessionForm() {
    const form = document.getElementById('start-session-form');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

async function startSession() {
    const subject = document.getElementById('s_subject').value;
    const branch = document.getElementById('s_branch').value;
    const classType = document.querySelector('input[name="ctype"]:checked').value;

    if (!subject) {
        alert("Please select a subject");
        return;
    }

    console.log("Starting Session:", { subject, branch, classType });
    try {
        const res = await fetch('/start_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subject: subject, branch: branch, class_type: classType })
        });
        const data = await res.json();

        if (data.success) {
            // Remove "No Sessions" message if it exists
            const noMsg = document.getElementById('no-sessions-msg');
            if (noMsg) noMsg.remove();

            // Create Card HTML
            const grid = document.getElementById('active-sessions-grid');
            const cardHtml = createSessionCardHtml({
                id: data.session_id,
                subject: subject,
                branch: branch,
                class_type: classType,
                token: data.token,
                end_time: data.end_time
            });

            grid.insertAdjacentHTML('afterbegin', cardHtml);

            // Set QR (Already handled in createSessionCardHtml if we pass token)

            // Start Timers
            startClassTimer(data.session_id, data.end_timestamp, subject);
            startQRTimer(data.session_id, 120);

            // Reset and Close Form
            document.getElementById('s_subject').value = '';
            toggleSessionForm();
        } else {
            alert("Error: " + data.message);
        }
    } catch (e) {
        console.error(e);
        alert("Network Error");
    }
}

function createSessionCardHtml(s) {
    const typeLabel = s.class_type + (s.class_type === 'Lab' ? ' (3h)' : ' (1h)');
    return `
        <div id="session-card-${s.id}" class="session-card animate-pop">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                <div>
                    <h3 style="margin: 0; color: var(--primary-color);">${s.subject}</h3>
                    <div style="font-size: 0.9rem; color: #666; margin-top: 4px;">
                        <span style="font-weight: bold;">${s.branch}</span> • ${typeLabel}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 0.75rem; text-transform: uppercase; color: #888;">Ends In</div>
                    <div id="class-timer-${s.id}" style="font-size: 1.4rem; font-weight: bold; font-family: monospace;">00:00:00</div>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 140px 1fr; gap: 15px;">
                <div class="qr-container">
                    <img src="/get_qr_img/${s.token}" id="qr-image-${s.id}" style="width: 100%; display: block; margin: 0 auto;">
                    <div style="font-size: 0.75rem; font-weight: bold; color: var(--danger-color); margin-top: 5px;">
                         <span id="qr-timer-${s.id}">02:00</span>
                    </div>
                </div>
                <div style="display: flex; flex-direction: column; justify-content: space-between;">
                    <div style="font-size: 0.85rem; color: #666;">
                        <i class="fas fa-qrcode"></i> <a href="/scan_session?token=${s.token}" target="_blank" style="color: var(--primary-color);">Open Scan Link</a>
                    </div>
                    <button onclick="finalizeAttendance(${s.id}, false, this)" class="danger" style="width: 100%; padding: 8px; font-size: 0.9rem;">
                        <i class="fas fa-flag-checkered"></i> Finalize
                    </button>
                </div>
            </div>
        </div>
    `;
}

function startClassTimer(sessionId, endTimestamp, subjectName = "Session") {
    // endTimestamp is Unix seconds from server
    const endDate = new Date(endTimestamp * 1000);

    if (activeClassTimers[sessionId]) clearInterval(activeClassTimers[sessionId]);

    const display = document.getElementById(`class-timer-${sessionId}`);
    if (!display) return;

    activeClassTimers[sessionId] = setInterval(() => {
        const adjustedNow = new Date(Date.now() + window.serverClockOffset);
        const diff = endDate - adjustedNow;

        if (diff <= 0) {
            clearInterval(activeClassTimers[sessionId]);
            display.textContent = "00:00:00";
            // Check if we should auto-finalize or just alert
            // Removed blocking alert to allow seamless auto-finalization
            finalizeAttendance(sessionId, true); // true for auto
            return;
        }

        const h = Math.floor(diff / (1000 * 60 * 60));
        const m = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const s = Math.floor((diff % (1000 * 60)) / 1000);

        display.textContent = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }, 1000);
}

function startQRTimer(sessionId, totalSeconds) {
    if (activeQRTimers[sessionId]) clearInterval(activeQRTimers[sessionId]);

    const display = document.getElementById(`qr-timer-${sessionId}`);
    const img = document.getElementById(`qr-image-${sessionId}`);
    if (!display) return;

    // Calculate remaining based on current time and start_time if possible?
    // For now, simplicity:
    let remaining = totalSeconds;

    activeQRTimers[sessionId] = setInterval(() => {
        remaining--;

        const m = Math.floor(remaining / 60);
        const s = remaining % 60;
        display.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;

        if (remaining <= 0) {
            clearInterval(activeQRTimers[sessionId]);
            display.textContent = "EXPIRED";
            display.style.color = "red";
            if (img) img.style.opacity = "0.2";
        }
    }, 1000);
}

async function finalizeAttendance(sessionId, auto = false, btnRef = null) {
    console.log("finalizeAttendance called:", { sessionId, auto });
    if (!sessionId) return;

    if (!auto && !confirm("Finalize this session? Unmarked students will be marked ABSENT.")) return;

    // Use passed button or try to find it (fallback)
    let btn = btnRef;
    if (!btn && window.event && window.event.target) {
        btn = window.event.target.closest('button');
    }

    const originalHtml = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    }

    try {
        const res = await fetch('/finalize_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });

        if (!res.ok) {
            throw new Error(`Server status: ${res.status}`);
        }

        const data = await res.json();

        if (data.success) {
            if (!auto) showToast({ name: 'Session Finalized', roll: 'Success', branch: '' });

            // Remove card from UI
            const card = document.getElementById(`session-card-${sessionId}`);
            if (card) {
                card.style.transition = "all 0.5s ease";
                card.style.opacity = "0";
                card.style.transform = "scale(0.9)";
                setTimeout(() => card.remove(), 500);
            }

            // If grid empty, show no-sessions message (delayed check)
            setTimeout(() => {
                const grid = document.getElementById('active-sessions-grid');
                if (grid && grid.children.length === 0) {
                    // Check if a message already exists to avoid duplicates
                    if (!document.getElementById('no-sessions-msg')) {
                        grid.innerHTML = '<div id="no-sessions-msg" style="grid-column: 1 / -1; text-align: center; color: #666; padding: 20px;">No active sessions. Start a class to begin.</div>';
                    }
                }
            }, 500);

        } else {
            console.error("Finalize Failed:", data.message);
            if (!auto) alert("Error: " + data.message);
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        }
    } catch (e) {
        console.error("Finalize Network Error:", e);
        if (!auto) alert("Network Error: " + e.message);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }
}

// --- End Session Logic ---

function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('darkMode', isDark);

    // Update icon if exists
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Init Dark Mode
document.addEventListener('DOMContentLoaded', () => {
    // Only auto-enable if explicitly stored as true
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
        const icon = document.getElementById('theme-icon');
        if (icon) icon.className = 'fas fa-sun';
    }
});

function togglePassword(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);

    if (input.type === "password") {
        input.type = "text";
        icon.className = "fas fa-eye-slash";
    } else {
        input.type = "password";
        icon.className = "fas fa-eye";
    }
}

// Auto-Refresh Dashboard Stats (Live)
function updateDashboardStats() {
    const cse = document.getElementById('stat-cse');
    if (!cse) return; // Not on admin dashboard

    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            if (data.error) return;
            document.getElementById('stat-cse').innerText = data.cse;
            document.getElementById('stat-ece').innerText = data.ece;
            document.getElementById('stat-eee').innerText = data.eee;
            document.getElementById('stat-mech').innerText = data.mech;
            document.getElementById('stat-civil').innerText = data.civil;
        })
        .catch(err => console.error('Stats Update Fail', err));
}

// Start polling every 3 seconds
setInterval(updateDashboardStats, 3000);

async function addHoliday() {
    const date = document.getElementById('h_date').value;
    const endDate = document.getElementById('h_end_date').value;
    const desc = document.getElementById('h_desc').value;

    if (!date || !desc) return alert("Start Date and Occasion are required");

    try {
        const res = await fetch('/add_holiday', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                date: date,
                end_date: endDate,
                description: desc
            })
        });
        const data = await res.json();
        if (data.success) {
            location.reload();
        } else {
            alert(data.message);
        }
    } catch (e) {
        alert("Error adding holiday");
    }
}

async function deleteHoliday(ids) {
    if (!confirm('Remove this holiday/range?')) return;

    // Ensure ids is an array
    const idList = Array.isArray(ids) ? ids : [ids];

    try {
        const res = await fetch('/delete_holidays_bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: idList })
        });
        const data = await res.json();
        if (data.success) {
            location.reload(); // Easier than manual DOM removal for ranges
        }
    } catch (e) {
        alert("Error deleting holiday");
    }
}

// PWA Service Worker Registration
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/sw.js')
            .then(reg => console.log('Service Worker Registered (Scope: ' + reg.scope + ')'))
            .catch(err => console.log('Service Worker Error: ' + err));
    });
}

// Force Finalize All Expired Sessions
async function forceFinalizeAllExpired() {
    if (!confirm('Manually finalize all expired sessions?\n\nThis will mark all students who haven\'t scanned as ABSENT for expired sessions.')) {
        return;
    }

    try {
        const btn = event.target.closest('button');
        const originalHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Finalizing...';

        const res = await fetch('/api/force_finalize_all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await res.json();

        if (data.success) {
            if (data.finalized_count > 0) {
                alert(`✓ Successfully finalized ${data.finalized_count} expired session(s)!`);
                // Reload to refresh the session list
                location.reload();
            } else {
                alert('✓ ' + data.message);
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        } else {
            alert('Error: ' + data.message);
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    } catch (e) {
        console.error('Force finalize error:', e);
        alert('Network error: ' + e.message);
        const btn = event.target.closest('button');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }
}

