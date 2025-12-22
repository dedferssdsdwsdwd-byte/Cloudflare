// @ts-nocheck
/**
 * ==============================================================================
 * 🚀 VLESS PROXY MANAGER - ROBUST EDITION (SINGLE-FILE WORKER)
 * ==============================================================================
 * 
 * A complete, professional, and secure VLESS implementation for Cloudflare Workers.
 * Refactored for maximum stability, error handling, and ease of deployment.
 * 
 * @version 3.2.0 (Error-Proof)
 * @author AI Assistant
 */

import { connect } from 'cloudflare:sockets';

// ==============================================================================
// 1. TOP-LEVEL UTILITIES (HOISTED FOR SAFETY)
// ==============================================================================

/**
 * Safely closes a WebSocket connection.
 */
function safeCloseWebSocket(socket) {
    try {
        if (socket && (socket.readyState === 1 || socket.readyState === 0)) {
            socket.close();
        }
    } catch (e) {
        console.error('Error closing WebSocket:', e);
    }
}

/**
 * Validates a UUID string.
 */
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

/**
 * Converts ArrayBuffer to UUID string.
 */
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

/**
 * Decodes a Base64 string to ArrayBuffer.
 */
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

/**
 * Generates a random nonce for CSP headers.
 */
function generateNonce() {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 16; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

// ==============================================================================
// 2. CONFIGURATION & CONSTANTS
// ==============================================================================

const CONST = {
    VERSION: '3.2.0',
    HEALTH_CHECK_TIMEOUT: 2000,
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
            // D1 binding is accessed directly via env.DB
        };
    }
};

// ==============================================================================
// 3. DATABASE LAYER (ROBUST)
// ==============================================================================

const Database = {
    async init(env) {
        // Guard: Check if DB is bound
        if (!env.DB) {
            console.warn('⚠️ D1 Database (env.DB) is missing. Skipping DB operations.');
            return;
        }

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

            // Seed default user if empty
            const check = await env.DB.prepare("SELECT count(*) as count FROM users").first();
            if (check && check.count === 0) {
                const cfg = Config.fromEnv(env);
                await env.DB.prepare("INSERT INTO users (uuid, notes, traffic_limit) VALUES (?, ?, ?)")
                    .bind(cfg.uuid, 'Admin User', 0).run();
                console.log('Database seeded with default user.');
            }
        } catch (e) {
            // Log but don't crash the worker. Tables might already exist or D1 is busy.
            console.warn('Database initialization warning (non-fatal):', e.message);
        }
    },

    async getUser(env, uuid) {
        if (!env.DB) {
            // Fallback: If no DB, allow the UUID from env variable as a "superuser"
            const cfg = Config.fromEnv(env);
            if (uuid === cfg.uuid) {
                return { uuid: cfg.uuid, notes: 'Env Superuser', traffic_limit: 0, traffic_used: 0, active: 1 };
            }
            return null;
        }
        try {
            return await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
        } catch (e) {
            console.error('DB getUser error:', e);
            // Fallback to env UUID on DB error
            const cfg = Config.fromEnv(env);
            if (uuid === cfg.uuid) return { uuid: cfg.uuid, notes: 'Fallback User', active: 1 };
            return null;
        }
    },

    async getAllUsers(env) {
        if (!env.DB) return [];
        try {
            const res = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
            return res.results || [];
        } catch (e) {
            console.error('DB getAllUsers error:', e);
            return [];
        }
    },

    async updateUserTraffic(env, uuid, bytes) {
        if (!env.DB) return;
        try {
            await env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?").bind(bytes, uuid).run();
        } catch (e) { /* ignore traffic update errors to prevent lag */ }
    },

    async saveProxyHealth(env, address, latency, isHealthy) {
        if (!env.DB) return;
        try {
            await env.DB.prepare("INSERT OR REPLACE INTO proxy_health (address, latency, is_healthy, last_check) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
                .bind(address, latency, isHealthy ? 1 : 0).run();
        } catch (e) { console.error('DB saveProxyHealth error:', e); }
    }
};

// ==============================================================================
// 4. VLESS CORE LOGIC (SOCKET HANDLERS)
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
    // Connect to remote server
    const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
    remoteSocket.value = tcpSocket;
    
    // Write initial data
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawData);
    writer.releaseLock();

    // Pipe remote -> client
    tcpSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (uuid && env.DB && ctx) {
                // Non-blocking traffic log
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
        close() {
            safeCloseWebSocket(webSocket);
        },
        abort(reason) {
            console.error('Remote TCP Aborted:', reason);
            safeCloseWebSocket(webSocket);
        }
    })).catch((err) => {
        console.error('Remote TCP Pipe Error:', err);
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
                console.error('WebSocket Error:', err);
                controller.error(err);
            });
            
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel(reason) {
            safeCloseWebSocket(webSocket);
        }
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
                console.warn('VLESS Header Error:', message);
                safeCloseWebSocket(webSocket);
                return;
            }

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp" : "tcp"}`;

            // Check User Authorization
            const user = await Database.getUser(env, uuid);
            if (!user) {
                console.warn(`Unauthorized Access Attempt: ${uuid}`);
                // Close gracefully
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
                    console.warn('UDP blocked: Only DNS (53) allowed');
                    safeCloseWebSocket(webSocket);
                    return;
                }
            }

            // Handle TCP
            await handleTCPOutbound(remoteSocketWapper, addressRemote, portRemote, chunk.slice(rawDataIndex), webSocket, new Uint8Array([vlessVersion[0], 0]), log, env, uuid, ctx);
        },
        abort(reason) {
            safeCloseWebSocket(webSocket);
        }
    })).catch((err) => {
        console.error('Readable WebSocket Pipe Error:', err);
        safeCloseWebSocket(webSocket);
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ==============================================================================
// 5. HELPER OBJECTS (UI & SUBSCRIPTION)
// ==============================================================================

const ASSETS = {
    CSS: `:root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --primary: #3b82f6; }
          body { font-family: sans-serif; background: var(--bg); color: var(--text); padding: 20px; }
          .card { background: var(--card); padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 600px; margin: 0 auto; }
          .btn { background: var(--primary); color: white; padding: 10px 20px; border-radius: 8px; text-decoration: none; display: inline-block; margin-top: 10px; border:none; cursor:pointer;}
          input, button { width: 100%; padding: 10px; margin-bottom: 10px; border-radius: 5px; border: 1px solid #333; background: #334155; color: white; }
          table { width: 100%; border-collapse: collapse; margin-top: 20px; }
          th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }`,
};

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

// ==============================================================================
// 6. MAIN WORKER ENTRY POINT
// ==============================================================================

export default {
    /**
     * Main request handler
     */
    async fetch(request, env, ctx) {
        // GLOBAL ERROR TRAP - Prevents 1101/500 crashes
        try {
            // 1. Guardrails: Check Environment
            if (!env.UUID) {
                return new Response(`
                    <html><body style="background:#111;color:#eee;font-family:sans-serif;text-align:center;padding:50px;">
                    <h1>Setup Required</h1>
                    <p>Please add <code>UUID</code> to your Cloudflare Worker "Environment Variables".</p>
                    </body></html>`, 
                    { status: 503, headers: { 'Content-Type': 'text/html' } }
                );
            }

            const config = Config.fromEnv(env);
            await Database.init(env);
            const url = new URL(request.url);

            // 2. VLESS WebSocket Handler
            if (request.headers.get('Upgrade') === 'websocket') {
                return await vlessOverWSHandler(request, env, ctx);
            }

            // 3. Static Routes
            if (url.pathname === '/robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200 });

            // 4. Admin Panel & API
            if (url.pathname.startsWith('/' + config.adminPath)) {
                // Login
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
                    return new Response('Invalid Password', { status: 401 });
                }

                // Auth Check
                const cookie = request.headers.get('Cookie') || '';
                if (!cookie.includes(`auth_token=${config.adminKey}`)) {
                    return new Response(`<!DOCTYPE html><html><head><style>${ASSETS.CSS}</style></head><body>
                        <div class="card" style="text-align:center">
                        <h2>Login</h2>
                        <form method="POST"><input type="password" name="password" placeholder="Key" required><button type="submit" class="btn">Enter</button></form>
                        </div></body></html>`, 
                        { headers: { 'Content-Type': 'text/html' } }
                    );
                }

                // API Handling
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
                        const newUUID = crypto.randomUUID();
                        if (env.DB) await env.DB.prepare("INSERT INTO users (uuid, notes, traffic_limit) VALUES (?, ?, ?)").bind(newUUID, body.note, 0).run();
                        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
                    }
                    if (action === 'delete_user' && request.method === 'POST') {
                        const body = await request.json();
                        if (env.DB) await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(body.uuid).run();
                        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
                    }
                }

                // Render Dashboard (Simplified for robustness)
                const nonce = generateNonce();
                return new Response(`<!DOCTYPE html><html><head><title>Admin</title><style nonce="${nonce}">${ASSETS.CSS}</style></head><body>
                    <div class="card">
                    <h2>Dashboard</h2>
                    <div style="display:flex;gap:10px;margin-bottom:20px"><button onclick="loadUsers()" class="btn">Refresh</button><button onclick="createUser()" class="btn" style="background:#10b981">New User</button></div>
                    <div id="stats">Loading...</div>
                    <div id="list"></div>
                    </div>
                    <script nonce="${nonce}">
                    async function loadUsers() {
                        const res = await fetch('?action=get_users');
                        const users = await res.json();
                        const statsRes = await fetch('?action=get_stats');
                        const stats = await statsRes.json();
                        document.getElementById('stats').innerText = 'Users: ' + stats.total + ' | Traffic: ' + (stats.traffic/1e9).toFixed(2) + ' GB';
                        document.getElementById('list').innerHTML = '<table><tr><th>User</th><th>UUID</th><th>Traffic</th><th>Action</th></tr>' + 
                        users.map(u => '<tr><td>' + (u.notes||'-') + '</td><td style="font-family:monospace;font-size:12px">' + u.uuid + '</td><td>' + (u.traffic_used/1e9).toFixed(2) + ' GB</td><td><button onclick="del(\\'npm'+u.uuid+'\\')" style="background:#ef4444;padding:5px;width:auto">Del</button></td></tr>').join('') + '</table>';
                    }
                    async function createUser() {
                        const note = prompt("User Note:");
                        if(note) { await fetch('?action=create_user', {method:'POST', body:JSON.stringify({note})}); loadUsers(); }
                    }
                    async function del(uuid) {
                         if(confirm("Delete?")) { await fetch('?action=delete_user', {method:'POST', body:JSON.stringify({uuid: uuid.substring(3)})}); loadUsers(); }
                    }
                    loadUsers();
                    </script></body></html>`,
                    { headers: { 'Content-Type': 'text/html' } }
                );
            }

            // 5. User Portal & Subscription
            if (url.pathname.startsWith('/sub/')) {
                const uuid = url.pathname.split('/')[2];
                if (!uuid || !isValidUUID(uuid)) return new Response('Invalid UUID', { status: 400 });

                const user = await Database.getUser(env, uuid);
                if (!user) return new Response('User Not Found', { status: 404 });

                // Update activity
                if (env.DB && ctx) ctx.waitUntil(env.DB.prepare("UPDATE users SET active = 1 WHERE uuid = ?").bind(uuid).run());

                const format = url.searchParams.get('format');
                const host = url.hostname;

                if (format === 'clash') {
                    return new Response(Subscriptions.toClash(user, host), { 
                        headers: { 'Content-Type': 'text/yaml', 'Content-Disposition': `attachment; filename="${host}.yaml"` } 
                    });
                }
                if (format === 'singbox') {
                    return new Response(Subscriptions.toSingbox(user, host), { 
                        headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="${host}.json"` } 
                    });
                }

                // User Web UI
                return new Response(`<!DOCTYPE html><html><head><title>Subscription</title><style>${ASSETS.CSS}</style>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script></head><body>
                <div class="card">
                    <h2>Hi, ${user.notes || 'User'}</h2>
                    <p>Usage: ${(user.traffic_used/1073741824).toFixed(2)} GB</p>
                    <div id="qrcode" style="background:white;padding:10px;margin:20px auto;width:fit-content"></div>
                    <button onclick="copyClash()" class="btn">Copy Clash Config</button>
                    <button onclick="copyLink()" class="btn" style="background:#8b5cf6">Copy VLESS Link</button>
                </div>
                <script>
                    const host = "${host}";
                    const uuid = "${user.uuid}";
                    const link = "vless://" + uuid + "@" + host + ":443?encryption=none&security=tls&type=ws&host=" + host + "&path=%2F#" + host;
                    new QRCode(document.getElementById("qrcode"), { text: link, width: 200, height: 200 });
                    function copyLink() { navigator.clipboard.writeText(link); alert("Copied!"); }
                    function copyClash() { window.location.href = location.href + "?format=clash"; }
                </script></body></html>`, { headers: { 'Content-Type': 'text/html' } });
            }

            // 6. Reverse Proxy Fallback
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
                    const newHeaders = new Headers(res.headers);
                    // Remove security headers that break iframe/proxying
                    ['content-security-policy', 'x-frame-options', 'x-xss-protection'].forEach(h => newHeaders.delete(h));
                    
                    return new Response(res.body, { status: res.status, headers: newHeaders });
                } catch (e) {
                    console.error('Landing proxy failed', e);
                }
            }

            // 7. Default 404
            return new Response('404 Not Found', { status: 404 });

        } catch (err) {
            // CATCH-ALL: Prevents Error 1101
            return new Response(`Internal Worker Error:\n${err.message}\n${err.stack}`, { status: 500 });
        }
    },

    /**
     * Cron Triggers
     */
    async scheduled(event, env, ctx) {
        try {
            await Database.init(env);
            if (env.DB) {
                // Cleanup expired users
                await env.DB.prepare(`UPDATE users SET active = 0 WHERE active = 1 AND expiration_date IS NOT NULL AND datetime(expiration_date || ' ' || COALESCE(expiration_time, '00:00:00')) < datetime('now')`).run();
            }
        } catch (e) {
            console.error('Scheduled Task Error:', e);
        }
    }
};
