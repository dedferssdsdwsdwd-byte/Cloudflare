// @ts-nocheck
/**
 * ==============================================================================
 * 🚀 VLESS PROXY MANAGER - ULTIMATE ROBUST EDITION
 * ==============================================================================
 * 
 * - Full UI (Admin & User)
 * - Error-Proof VLESS Core
 * - Top-Level Hoisting to prevent ReferenceErrors
 * - Global Try-Catch to prevent 1101 Errors
 * 
 * @version 4.0.0
 */

import { connect } from 'cloudflare:sockets';

// ==============================================================================
// 1. TOP-LEVEL UTILITIES (HOISTED)
// ==============================================================================

function safeCloseWebSocket(socket) {
    try {
        if (socket && (socket.readyState === 1 || socket.readyState === 0)) {
            socket.close();
        }
    } catch (e) {
        console.error('Error closing WebSocket:', e);
    }
}

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

function stringifyUUID(v) {
    const arr = [...v];
    const toHex = (n) => (n < 16 ? '0' : '') + n.toString(16);
    return (
        arr.slice(0, 4).map(toHex).join('') + '-' +
        arr.slice(4, 6).map(toHex).join('') + '-' +
        arr.slice(6, 8).map(toHex).join('') + '-' +
        arr.slice(8, 10).map(toHex).join('') + '-' +
        arr.slice(10).map(toHex).join('')
    );
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

function generateNonce() {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 16; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

function formatBytes(bytes) {
    if (!+bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ==============================================================================
// 2. CONFIGURATION & CONSTANTS
// ==============================================================================

const CONST = {
    VERSION: '4.0.0',
    DEFAULT_UUID: 'd342d11e-d424-4583-b36e-524ab1f0afa4'
};

const Config = {
    fromEnv(env) {
        return {
            uuid: env.UUID || CONST.DEFAULT_UUID,
            adminKey: env.ADMIN_KEY || 'admin',
            adminPath: env.ADMIN_PATH || 'admin',
            proxyIPs: (env.PROXYIP || '').split(',').filter(Boolean).map(i => i.trim()),
            enableLandingProxy: env.ENABLE_LANDING_PROXY === 'true',
            landingPageUrl: env.LANDING_PAGE_URL || 'https://www.google.com',
        };
    }
};

// ==============================================================================
// 3. DATABASE LAYER
// ==============================================================================

const Database = {
    async init(env) {
        if (!env.DB) return;
        const schema = [
            `CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                notes TEXT,
                traffic_limit INTEGER,
                traffic_used INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1,
                expiration_date TEXT,
                expiration_time TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS proxy_health (
                address TEXT PRIMARY KEY,
                latency INTEGER,
                is_healthy INTEGER DEFAULT 1,
                last_check DATETIME DEFAULT CURRENT_TIMESTAMP
            )`
        ];
        try {
            const batch = schema.map(query => env.DB.prepare(query));
            await env.DB.batch(batch);
            
            // Seed default
            const check = await env.DB.prepare("SELECT count(*) as count FROM users").first();
            if (check && check.count === 0) {
                const cfg = Config.fromEnv(env);
                await env.DB.prepare("INSERT INTO users (uuid, notes, traffic_limit) VALUES (?, ?, ?)")
                    .bind(cfg.uuid, 'Admin User', 0).run();
            }
        } catch (e) {
            console.warn('DB Init Warning:', e.message);
        }
    },

    async getUser(env, uuid) {
        if (!env.DB) {
            const cfg = Config.fromEnv(env);
            if (uuid === cfg.uuid) return { uuid: cfg.uuid, notes: 'Superuser', active: 1, traffic_used: 0 };
            return null;
        }
        try {
            return await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
        } catch (e) {
            // Fallback for superuser if DB fails
            const cfg = Config.fromEnv(env);
            if (uuid === cfg.uuid) return { uuid: cfg.uuid, notes: 'Superuser (DB Fail)', active: 1, traffic_used: 0 };
            return null;
        }
    },

    async getAllUsers(env) {
        if (!env.DB) return [];
        try {
            const res = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
            return res.results || [];
        } catch (e) { return []; }
    },

    async updateUserTraffic(env, uuid, bytes) {
        if (!env.DB) return;
        try {
            await env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?").bind(bytes, uuid).run();
        } catch (e) {}
    },

    async createUser(env, note) {
         if (!env.DB) return false;
         const newUUID = crypto.randomUUID();
         await env.DB.prepare("INSERT INTO users (uuid, notes, traffic_limit) VALUES (?, ?, ?)").bind(newUUID, note, 0).run();
         return true;
    },

    async deleteUser(env, uuid) {
        if (!env.DB) return false;
        await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
        return true;
    }
};

// ==============================================================================
// 4. FRONTEND ASSETS & TEMPLATES
// ==============================================================================

const ASSETS = {
    CSS: `
    :root {
        --bg-body: #0f172a; --bg-card: #1e293b; --bg-input: #334155;
        --text-main: #f8fafc; --text-muted: #94a3b8;
        --primary: #3b82f6; --primary-hover: #2563eb;
        --success: #10b981; --danger: #ef4444; --warning: #f59e0b;
        --border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; outline: none; }
    body { font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg-body); color: var(--text-main); min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .flex { display: flex; } .flex-col { flex-direction: column; } .items-center { align-items: center; } .justify-between { justify-content: space-between; }
    .gap-2 { gap: 0.5rem; } .gap-4 { gap: 1rem; } .w-full { width: 100%; } .hidden { display: none; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; }
    .card { background-color: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    .btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; border: none; gap: 0.5rem; font-weight: 500; font-size: 0.875rem; transition: all 0.2s; }
    .btn-primary { background-color: var(--primary); color: white; } .btn-primary:hover { background-color: var(--primary-hover); }
    .btn-danger { background-color: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
    .btn-ghost { background: transparent; color: var(--text-muted); } .btn-ghost:hover { color: var(--text-main); background: rgba(255,255,255,0.05); }
    .input { width: 100%; background-color: var(--bg-body); border: 1px solid var(--border); color: var(--text-main); padding: 0.625rem; border-radius: 8px; font-size: 0.875rem; }
    .input:focus { border-color: var(--primary); }
    .table-container { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th { background-color: rgba(0,0,0,0.2); padding: 12px 16px; font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); }
    td { padding: 16px; border-top: 1px solid var(--border); font-size: 0.875rem; }
    .toast { position: fixed; bottom: 20px; right: 20px; background: var(--bg-card); border: 1px solid var(--border); padding: 1rem; border-radius: 8px; transform: translateY(100px); opacity: 0; transition: all 0.3s; z-index: 1000; }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.success { border-left: 4px solid var(--success); }
    .toast.error { border-left: 4px solid var(--danger); }
    .badge { padding: 2px 8px; border-radius: 99px; font-size: 0.7rem; font-weight: 600; }
    .badge-success { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.2); }
    .badge-warning { background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.2); }
    .login-wrapper { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: radial-gradient(circle at center, #1e293b 0%, #0f172a 100%); }
    .login-card { width: 100%; max-width: 400px; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fade { animation: fadeIn 0.4s ease-out forwards; }
    `
};

function buildAdminUI(config, nonce) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS Manager | Admin</title>
    <style nonce="${nonce}">${ASSETS.CSS}</style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
</head>
<body class="bg-body text-main">
    <div id="app" class="flex h-screen overflow-hidden">
        <aside class="w-64 bg-card h-full fixed md:static transform -translate-x-full md:translate-x-0 transition-transform duration-200 border-r border-border z-30 flex flex-col" id="sidebar">
            <div class="p-6 border-b border-border flex items-center justify-between">
                <h1 class="text-xl font-bold flex items-center gap-2 m-0"><span class="text-primary">⚡</span> VLESS<span class="text-muted">PRO</span></h1>
                <button class="md:hidden text-muted" onclick="toggleSidebar()">✕</button>
            </div>
            <nav class="flex-1 p-4 space-y-2 overflow-y-auto">
                <button onclick="router('dashboard')" class="w-full btn btn-ghost justify-start active" id="nav-dashboard">Dashboard</button>
                <button onclick="router('users')" class="w-full btn btn-ghost justify-start" id="nav-users">Users</button>
                <button onclick="router('settings')" class="w-full btn btn-ghost justify-start" id="nav-settings">Settings</button>
            </nav>
            <div class="p-4 border-t border-border">
                <button onclick="logout()" class="w-full btn btn-danger justify-start text-sm">Sign Out</button>
            </div>
        </aside>
        <main class="flex-1 h-full overflow-y-auto relative w-full">
            <header class="md:hidden h-16 border-b border-border flex items-center justify-between px-4 bg-card sticky top-0 z-20">
                <span class="font-bold text-lg">Dashboard</span>
                <button onclick="toggleSidebar()" class="btn btn-ghost p-2">Menu</button>
            </header>
            <div class="container py-8 px-4 md:px-8">
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 animate-fade">
                    <div><h2 class="text-2xl font-bold" id="page-title">Overview</h2></div>
                    <div class="flex items-center gap-3"><button onclick="refreshData()" class="btn btn-ghost border border-border bg-card">Refresh</button></div>
                </div>

                <!-- DASHBOARD VIEW -->
                <div id="view-dashboard" class="view-section animate-fade">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        <div class="card">
                            <p class="text-sm text-muted font-medium uppercase">Total Users</p>
                            <h3 class="text-3xl font-bold mt-2" id="stat-total-users">0</h3>
                        </div>
                        <div class="card">
                            <p class="text-sm text-muted font-medium uppercase">Total Traffic</p>
                            <h3 class="text-3xl font-bold mt-2 text-primary" id="stat-total-traffic">0 B</h3>
                        </div>
                    </div>
                </div>

                <!-- USERS VIEW -->
                <div id="view-users" class="view-section hidden animate-fade">
                    <div class="card">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-lg font-bold">Registered Users</h3>
                            <button onclick="openModal('create')" class="btn btn-primary">+ New User</button>
                        </div>
                        <div class="table-container">
                            <table class="w-full">
                                <thead><tr><th>Status</th><th>Details</th><th>Traffic</th><th>Actions</th></tr></thead>
                                <tbody id="user-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- SETTINGS VIEW -->
                <div id="view-settings" class="view-section hidden animate-fade">
                    <div class="card">
                        <h3 class="text-lg font-bold mb-4">Configuration</h3>
                        <p class="mb-2">Admin Path: <code class="text-primary">/${config.adminPath}</code></p>
                        <p class="mb-2">Landing Page: <code class="text-primary">${config.landingPageUrl}</code></p>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- CREATE USER MODAL -->
    <div id="modal-create" class="fixed inset-0 bg-black/80 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-lg relative" onclick="event.stopPropagation()">
            <h3 class="text-xl font-bold mb-4">Create New User</h3>
            <form id="create-user-form" onsubmit="event.preventDefault(); saveUser();">
                <label class="block mb-2 text-sm text-muted">User Note / Name</label>
                <input type="text" id="new-note" class="input mb-4" placeholder="e.g. My Phone" required>
                <div class="flex justify-end gap-3">
                    <button type="button" onclick="closeModal('create')" class="btn btn-ghost">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </div>
            </form>
        </div>
    </div>

    <!-- QR MODAL -->
    <div id="modal-qr" class="fixed inset-0 bg-black/90 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-sm relative text-center" onclick="event.stopPropagation()">
            <button onclick="closeModal('qr')" class="absolute top-4 right-4 text-muted text-xl">&times;</button>
            <h3 class="text-xl font-bold mb-6">Connection QR</h3>
            <div class="bg-white p-4 rounded-xl inline-block mb-6"><div id="admin-qr-target"></div></div>
            <button onclick="copyToClip(window.currentQRLink)" class="btn btn-primary w-full">Copy Link</button>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    <script nonce="${nonce}">
        // LOGIC
        let users = [];
        window.currentQRLink = '';

        function router(view) {
            document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
            document.getElementById('view-' + view).classList.remove('hidden');
            
            document.querySelectorAll('nav button').forEach(el => el.classList.remove('active', 'text-primary'));
            document.getElementById('nav-' + view).classList.add('active', 'text-primary');

            const sidebar = document.getElementById('sidebar');
            if(!sidebar.classList.contains('-translate-x-full') && window.innerWidth < 768) toggleSidebar();

            if(view === 'users') fetchUsers();
        }

        function toggleSidebar() { document.getElementById('sidebar').classList.toggle('-translate-x-full'); }

        async function fetchStats() {
            try {
                const res = await fetch('?action=get_stats');
                const data = await res.json();
                document.getElementById('stat-total-users').innerText = data.total;
                document.getElementById('stat-total-traffic').innerText = formatBytes(data.traffic);
            } catch(e) {}
        }

        async function fetchUsers() {
            const tbody = document.getElementById('user-table-body');
            tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4">Loading...</td></tr>';
            try {
                const res = await fetch('?action=get_users');
                users = await res.json();
                renderUsers(users);
            } catch(e) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-danger">Error loading users</td></tr>';
            }
        }

        function renderUsers(list) {
            const tbody = document.getElementById('user-table-body');
            if(list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4">No users found</td></tr>';
                return;
            }
            tbody.innerHTML = list.map(u => \`
                <tr>
                    <td><span class="badge badge-success">Active</span></td>
                    <td><div class="font-bold">\${u.notes}</div><div class="text-xs text-muted font-mono">\${u.uuid}</div></td>
                    <td>\${formatBytes(u.traffic_used)}</td>
                    <td>
                        <button onclick="showQR('\${u.uuid}')" class="btn btn-ghost text-primary p-1">QR</button>
                        <button onclick="deleteUser('\${u.uuid}')" class="btn btn-ghost text-danger p-1">Del</button>
                    </td>
                </tr>
            \`).join('');
        }

        async function saveUser() {
            const note = document.getElementById('new-note').value;
            if(!note) return;
            await fetch('?action=create_user', { method: 'POST', body: JSON.stringify({ note }) });
            closeModal('create'); fetchUsers(); fetchStats(); document.getElementById('create-user-form').reset();
        }

        async function deleteUser(uuid) {
            if(!confirm('Delete this user?')) return;
            await fetch('?action=delete_user', { method: 'POST', body: JSON.stringify({ uuid }) });
            fetchUsers(); fetchStats();
        }

        function generateLink(uuid) {
            const host = window.location.hostname;
            return \`vless://\${uuid}@\${host}:443?encryption=none&security=tls&type=ws&host=\${host}&path=%2F#\${host}\`;
        }

        function showQR(uuid) {
            window.currentQRLink = generateLink(uuid);
            document.getElementById('admin-qr-target').innerHTML = '';
            new QRCode(document.getElementById('admin-qr-target'), {
                text: window.currentQRLink, width: 200, height: 200
            });
            openModal('qr');
        }

        function copyToClip(str) { navigator.clipboard.writeText(str); showToast('Copied to clipboard'); }
        function showToast(msg) {
            const t = document.getElementById('toast');
            t.textContent = msg; t.className = 'toast show success';
            setTimeout(() => t.classList.remove('show'), 3000);
        }

        function openModal(id) { document.getElementById('modal-'+id).classList.remove('hidden'); }
        function closeModal(id) { document.getElementById('modal-'+id).classList.add('hidden'); }
        
        function formatBytes(bytes) {
            if (!+bytes) return '0 B';
            const k=1024, i=Math.floor(Math.log(bytes)/Math.log(k));
            return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+' '+['B','KB','MB','GB','TB'][i];
        }

        function refreshData() { fetchStats(); if(!document.getElementById('view-users').classList.contains('hidden')) fetchUsers(); }
        function logout() { document.cookie = "auth_token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;"; window.location.reload(); }

        fetchStats();
    </script>
</body>
</html>`;
}

function buildLoginPage(path, error) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title><style>${ASSETS.CSS}</style></head><body>
    <div class="login-wrapper">
        <div class="card login-card animate-fade">
            <div class="text-center mb-8"><h1 class="text-3xl font-bold text-primary">VLESS PRO</h1></div>
            ${error ? `<div class="bg-red-500/10 text-danger p-3 rounded mb-4 text-center">${error}</div>` : ''}
            <form action="/${path}" method="POST">
                <input type="password" name="password" class="input text-center text-lg mb-4" placeholder="Admin Key" required autofocus>
                <button type="submit" class="btn btn-primary w-full py-3">Login</button>
            </form>
        </div>
    </div></body></html>`;
}

function buildUserUI(userData, config) {
    const totalGB = userData.traffic_limit ? (userData.traffic_limit / 1073741824).toFixed(2) : '∞';
    const usedGB = (userData.traffic_used / 1073741824).toFixed(2);
    
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>My Subscription</title><style>${ASSETS.CSS}</style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script></head><body>
    <div class="container py-8 max-w-2xl">
        <div class="flex justify-between mb-8 animate-fade">
            <div><h1 class="text-2xl font-bold">My Subscription</h1><p class="text-muted text-sm">Active &bull; ${userData.notes}</p></div>
        </div>
        
        <div class="card mb-6 animate-fade">
            <div class="flex justify-between items-end mb-4">
                <div><p class="text-sm text-muted">Data Usage</p><h2 class="text-3xl font-bold">${usedGB} <span class="text-sm font-normal">GB</span></h2></div>
                <div><p class="text-sm text-muted">of ${totalGB} GB</p></div>
            </div>
            <div class="w-full bg-border h-4 rounded-full overflow-hidden">
                <div class="bg-success h-full" style="width: 100%"></div>
            </div>
        </div>

        <div class="card mb-6 animate-fade">
            <h3 class="font-bold mb-4">Connection Links</h3>
            <div class="grid gap-3">
                <button onclick="copyLink('vless')" class="btn btn-ghost border border-border justify-between">
                    <span>VLESS Link (Universal)</span> <span class="text-primary">Copy</span>
                </button>
                 <button onclick="openQR()" class="btn btn-ghost border border-border justify-between">
                    <span>Show QR Code</span> <span class="text-primary">View</span>
                </button>
                <div class="grid grid-cols-2 gap-3">
                    <button onclick="copyLink('clash')" class="btn btn-ghost border border-border text-sm">Copy Clash</button>
                    <button onclick="copyLink('singbox')" class="btn btn-ghost border border-border text-sm">Copy Sing-Box</button>
                </div>
            </div>
        </div>
    </div>

    <!-- QR Modal -->
    <div id="modal-qr" class="fixed inset-0 bg-black/90 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-sm relative text-center">
            <button onclick="closeModal()" class="absolute top-4 right-4 text-white text-xl">&times;</button>
            <h3 class="font-bold mb-6">Scan to Connect</h3>
            <div class="bg-white p-4 rounded-xl inline-block mb-4"><div id="qrcode"></div></div>
        </div>
    </div>
    <div id="toast" class="toast"></div>

    <script>
        const CONFIG = { uuid: "${userData.uuid}", host: window.location.hostname };
        const vlessLink = \`vless://\${CONFIG.uuid}@\${CONFIG.host}:443?encryption=none&security=tls&type=ws&host=\${CONFIG.host}&path=%2F#\${CONFIG.host}\`;
        
        new QRCode(document.getElementById("qrcode"), { text: vlessLink, width: 200, height: 200 });

        function copyLink(type) {
            let link = vlessLink;
            if(type === 'clash') link = location.origin + '/sub/' + CONFIG.uuid + '?format=clash';
            if(type === 'singbox') link = location.origin + '/sub/' + CONFIG.uuid + '?format=singbox';
            
            navigator.clipboard.writeText(link).then(() => {
                const t = document.getElementById('toast');
                t.textContent = 'Copied to clipboard!'; t.className = 'toast show success';
                setTimeout(() => t.classList.remove('show'), 2000);
            });
        }
        function openQR() { document.getElementById('modal-qr').classList.remove('hidden'); }
        function closeModal() { document.getElementById('modal-qr').classList.add('hidden'); }
    </script></body></html>`;
}

// ==============================================================================
// 5. VLESS LOGIC (SOCKETS & PARSING)
// ==============================================================================

async function handleUDPOutbound(webSocket, vlessResponseHeader, log) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query', {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            
            if (webSocket.readyState === 1) {
                if (isHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isHeaderSent = true;
                }
            }
        }
    })).catch((err) => {
        log('DNS UDP Pipe Error:', err);
    });

    const writer = transformStream.writable.getWriter();
    return {
        write: (chunk) => writer.write(chunk)
    };
}

async function handleTCPOutbound(remoteSocket, addressRemote, portRemote, rawData, webSocket, responseHeader, log, env, uuid, ctx) {
    const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
    remoteSocket.value = tcpSocket;
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawData);
    writer.releaseLock();

    tcpSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (uuid && env.DB && ctx) {
                ctx.waitUntil(Database.updateUserTraffic(env, uuid, chunk.byteLength));
            }
            if (webSocket.readyState === 1) {
                if (responseHeader) {
                    webSocket.send(await new Blob([responseHeader, chunk]).arrayBuffer());
                    responseHeader = null;
                } else {
                    webSocket.send(chunk);
                }
            }
        },
        close() { safeCloseWebSocket(webSocket); },
        abort(reason) { safeCloseWebSocket(webSocket); }
    })).catch((err) => {
        safeCloseWebSocket(webSocket);
    });

    return tcpSocket;
}

async function parseVlessHeader(buffer) {
    if (buffer.byteLength < 24) return { hasError: true, message: 'Invalid data length' };
    const view = new DataView(buffer);
    const version = view.getUint8(0);
    const uuid = stringifyUUID(new Uint8Array(buffer.slice(1, 17)));
    const optLength = view.getUint8(17);
    const command = view.getUint8(18 + optLength);
    
    const isUDP = command === 2;
    const portIndex = 19 + optLength;
    const portRemote = view.getUint16(portIndex);
    const addressIndex = portIndex + 2;
    const addressType = view.getUint8(addressIndex);

    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressRemote = '';

    if (addressType === 1) {
        addressLength = 4;
        addressRemote = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
    } else if (addressType === 2) {
        addressLength = view.getUint8(addressValueIndex);
        addressValueIndex++;
        addressRemote = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
    } else if (addressType === 3) {
        addressLength = 16;
        addressRemote = "[" + Array.from(new Uint16Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength))).map(v => v.toString(16)).join(':') + "]";
    } else {
        return { hasError: true, message: `Invalid addressType: ${addressType}` };
    }

    if (!addressRemote) return { hasError: true, message: 'Address is empty' };

    return {
        hasError: false,
        addressRemote,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        vlessVersion: new Uint8Array([version]),
        isUDP,
        uuid
    };
}

async function vlessOverWSHandler(request, env, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);

    const readableWebSocketStream = new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (event.data) controller.enqueue(event.data);
            });
            webSocket.addEventListener('close', () => {
                safeCloseWebSocket(webSocket);
                controller.close();
            });
            webSocket.addEventListener('error', (err) => {
                controller.error(err);
            });
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel(reason) { safeCloseWebSocket(webSocket); }
    });

    let remoteSocketWapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const { hasError, message, portRemote, addressRemote, rawDataIndex, vlessVersion, isUDP, uuid } = await parseVlessHeader(chunk);

            if (hasError) {
                safeCloseWebSocket(webSocket);
                return;
            }

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp" : "tcp"}`;

            const user = await Database.getUser(env, uuid);
            if (!user) {
                safeCloseWebSocket(webSocket);
                return;
            }

            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                    const dnsPipe = await handleUDPOutbound(webSocket, new Uint8Array([vlessVersion[0], 0]), log);
                    udpStreamWrite = dnsPipe.write;
                    udpStreamWrite(chunk.slice(rawDataIndex));
                    return;
                } else {
                    safeCloseWebSocket(webSocket);
                    return;
                }
            }

            await handleTCPOutbound(remoteSocketWapper, addressRemote, portRemote, chunk.slice(rawDataIndex), webSocket, new Uint8Array([vlessVersion[0], 0]), log, env, uuid, ctx);
        },
        abort(reason) { safeCloseWebSocket(webSocket); }
    })).catch((err) => {
        safeCloseWebSocket(webSocket);
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ==============================================================================
// 6. SUBSCRIPTION & EXPORT
// ==============================================================================

const Subscriptions = {
    toClash(user, host) {
        if (!user || !user.uuid) return "# Error: User data invalid";
        return `port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
mode: rule
log-level: info
allow-lan: true
external-controller: 0.0.0.0:9090
proxies:
  - name: ${host}
    server: ${host}
    port: 443
    type: vless
    uuid: ${user.uuid}
    cipher: auto
    tls: true
    udp: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /
      headers:
        Host: ${host}
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - ${host}
      - DIRECT
rules:
  - MATCH,PROXY`;
    },
    toSingbox(user, host) {
        if (!user || !user.uuid) return JSON.stringify({ error: "User data invalid" });
        return JSON.stringify({
            "log": { "level": "info", "timestamp": true },
            "inbounds": [{ "type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30", "auto_route": true, "strict_route": true }],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "proxy",
                    "server": host,
                    "server_port": 443,
                    "uuid": user.uuid,
                    "flow": "",
                    "tls": { "enabled": true, "server_name": host, "insecure": true },
                    "transport": { "type": "ws", "path": "/", "headers": { "Host": host } }
                },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [{ "outbound": "direct", "ip_cidr": ["geoip:private"] }, { "outbound": "proxy", "port": [80, 443] }]
            }
        }, null, 2);
    }
};

export default {
    async fetch(request, env, ctx) {
        try {
            if (!env.UUID) return new Response('Setup Required: Env UUID missing', { status: 503 });

            const config = Config.fromEnv(env);
            await Database.init(env);
            const url = new URL(request.url);

            if (request.headers.get('Upgrade') === 'websocket') {
                return await vlessOverWSHandler(request, env, ctx);
            }

            if (url.pathname === '/robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200 });

            // ADMIN PANEL
            if (url.pathname.startsWith('/' + config.adminPath)) {
                // Login API
                if (request.method === 'POST' && url.pathname === '/' + config.adminPath) {
                    const formData = await request.formData();
                    if (formData.get('password') === config.adminKey) {
                        return new Response(null, {
                            status: 302,
                            headers: {
                                'Set-Cookie': `auth_token=${config.adminKey}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
                                'Location': '/' + config.adminPath
                            }
                        });
                    }
                    return new Response(buildLoginPage(config.adminPath, 'Invalid Password'), { headers: {'Content-Type': 'text/html'} });
                }

                // Auth Check
                const cookie = request.headers.get('Cookie') || '';
                if (!cookie.includes(`auth_token=${config.adminKey}`)) {
                    return new Response(buildLoginPage(config.adminPath), { headers: {'Content-Type': 'text/html'} });
                }

                // Admin API
                const action = url.searchParams.get('action');
                if (action) {
                    if (action === 'get_users') {
                        const users = await Database.getAllUsers(env);
                        return new Response(JSON.stringify(users), { headers: { 'Content-Type': 'application/json' } });
                    }
                    if (action === 'get_stats') {
                        const users = await Database.getAllUsers(env);
                        const total = users.length;
                        const traffic = users.reduce((acc, u) => acc + (u.traffic_used || 0), 0);
                        return new Response(JSON.stringify({ total, traffic }), { headers: { 'Content-Type': 'application/json' } });
                    }
                    if (action === 'create_user' && request.method === 'POST') {
                        const body = await request.json();
                        await Database.createUser(env, body.note);
                        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
                    }
                    if (action === 'delete_user' && request.method === 'POST') {
                        const body = await request.json();
                        await Database.deleteUser(env, body.uuid);
                        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
                    }
                }

                // Render Dashboard
                const nonce = generateNonce();
                return new Response(buildAdminUI(config, nonce), { headers: { 'Content-Type': 'text/html' } });
            }

            // USER PORTAL
            if (url.pathname.startsWith('/sub/')) {
                const uuid = url.pathname.split('/')[2];
                if (!uuid || !isValidUUID(uuid)) return new Response('Invalid UUID', { status: 400 });

                const user = await Database.getUser(env, uuid);
                if (!user) return new Response('User Not Found', { status: 404 });

                // Update activity (non-blocking)
                if (env.DB && ctx) ctx.waitUntil(env.DB.prepare("UPDATE users SET active = 1 WHERE uuid = ?").bind(uuid).run());

                const format = url.searchParams.get('format');
                const host = url.hostname;

                if (format === 'clash') return new Response(Subscriptions.toClash(user, host), { headers: { 'Content-Type': 'text/yaml', 'Content-Disposition': `attachment; filename="${host}.yaml"` } });
                if (format === 'singbox') return new Response(Subscriptions.toSingbox(user, host), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="${host}.json"` } });

                return new Response(buildUserUI(user, config), { headers: { 'Content-Type': 'text/html' } });
            }

            // REVERSE PROXY
            if (config.enableLandingProxy) {
                try {
                    const proxyUrl = new URL(config.landingPageUrl);
                    const proxyReq = new Request(proxyUrl.origin + url.pathname + url.search, {
                        method: request.method,
                        headers: request.headers,
                        body: request.body,
                        redirect: 'follow'
                    });
                    proxyReq.headers.set('Host', proxyUrl.hostname);
                    proxyReq.headers.set('Referer', proxyUrl.origin);
                    const res = await fetch(proxyReq);
                    return res;
                } catch (e) {}
            }

            return new Response('404 Not Found', { status: 404 });

        } catch (err) {
            return new Response(`Error: ${err.message}\n${err.stack}`, { status: 500 });
        }
    },
    async scheduled(event, env, ctx) {
        try {
            await Database.init(env);
            if (env.DB) {
                 await env.DB.prepare(`UPDATE users SET active = 0 WHERE active = 1 AND expiration_date IS NOT NULL AND datetime(expiration_date || ' ' || COALESCE(expiration_time, '00:00:00')) < datetime('now')`).run();
            }
        } catch (e) {}
    }
};
