import { connect } from 'cloudflare:sockets';

const Config = {
    userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
    proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
    scamalytics: {
        username: 'victoriacrossn',
        apiKey: 'ed89b4fef21aba43c15cdd15cff2138dd8d3bbde5aaaa4690ad8e94990448516',
        baseUrl: 'https://api12.scamalytics.com/v3/',
    },
    socks5: {
        enabled: false,
        relayMode: false,
        address: '',
    },

    async fromEnv(env) {
        let selectedProxyIP = null;

        if (env.DB) {
            try {
                const { results } = await env.DB.prepare(
                    "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
                ).all();
                selectedProxyIP = results[0]?.ip_port || null;
            } catch (e) {
                console.error(e.message);
            }
        }

        if (!selectedProxyIP) {
            selectedProxyIP = env.PROXYIP;
        }

        if (!selectedProxyIP) {
            selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
        }

        if (!selectedProxyIP) {
            console.error('CRITICAL ERROR: No VLESS proxy IP available. Service will be severely degraded.');
            selectedProxyIP = this.proxyIPs[0] || '127.0.0.1:443';
        }

        const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
        const socks5Address = env.SOCKS5 || this.socks5.address;
        let socks5Enabled = !!env.SOCKS5 || this.socks5.enabled;
        let parsedSocks5Address = null;

        if (socks5Enabled && socks5Address) {
            try {
                parsedSocks5Address = socks5AddressParser(socks5Address);
            } catch (e) {
                console.error(e.message);
                socks5Enabled = false;
            }
        }

        return {
            userID: env.UUID || this.userID,
            proxyIP: proxyHost,
            proxyPort: parseInt(proxyPort, 10),
            proxyAddress: selectedProxyIP,
            scamalytics: {
                username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
                apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
                baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
            },
            socks5: {
                enabled: socks5Enabled,
                relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
                address: socks5Address,
            },
            parsedSocks5Address: parsedSocks5Address,
        };
    },
};

const CONST = {
    ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
    VLESS_PROTOCOL: 'vless',
    WS_READY_STATE_OPEN: 1,
    WS_READY_STATE_CLOSING: 2,

    ADMIN_LOGIN_FAIL_LIMIT: 5,
    ADMIN_LOGIN_LOCK_TTL: 600,
    ADMIN_SESSION_TTL: 86400,

    SCAMALYTICS_THRESHOLD: 50,
    USER_PATH_RATE_LIMIT: 20,
    USER_PATH_RATE_TTL: 60,

    IP_BLACKLIST_TTL: 3600,
    BRUTE_FORCE_LOGIN_ATTEMPTS: 10,
    BRUTE_FORCE_LOGIN_TTL: 300,
    INVALID_UUID_ATTEMPTS: 50,
    INVALID_UUID_TTL: 60,
    PORT_SCAN_THRESHOLD: 10,
    PORT_SCAN_TTL: 30,

    ADMIN_AUTO_REFRESH_INTERVAL: 60000,
    IP_CLEANUP_AGE_DAYS: 30,
    HEALTH_CHECK_INTERVAL: 300000,
    HEALTH_CHECK_TIMEOUT: 5000,
    DB_CACHE_TTL: 3600,
};

function generateNonce() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
    const scriptSrc = nonce
        ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com https://chart.googleapis.com`
        : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com https://chart.googleapis.com 'unsafe-inline'";
    
    const styleSrc = "style-src 'self' 'unsafe-inline' 'unsafe-hashes'"; 

    const csp = [
        "default-src 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        scriptSrc,
        styleSrc,
        `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
        `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
        "worker-src 'self' blob:",
        "child-src 'self' blob:",
        "frame-src 'none'",
        "font-src 'self' https: data:",
    ];
    headers.set('Content-Security-Policy', csp.join('; '));
    headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'SAMEORIGIN');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    headers.set('alt-svc', 'h3=":443"; ma=0');
    headers.set('Cross-Origin-Opener-Policy', 'same-origin');
    headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
    headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
    headers.set('X-XSS-Protection', '1; mode=block');
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const aLen = a.length;
    const bLen = b.length;
    let result = 0;
    if (aLen !== bLen) {
        for (let i = 0; i < aLen; i++) {
            result |= a.charCodeAt(i) ^ a.charCodeAt(i);
        }
        return false;
    }
    for (let i = 0; i < aLen; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

function escapeHTML(str) {
    if (typeof str !== 'string') return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    };
    return str.replace(/[&<>"']/g, m => map[m]);
}

function safeBase64Encode(str) {
    try {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(str);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    } catch (e) {
        console.warn(e);
        return btoa(unescape(encodeURIComponent(str)));
    }
}

function generateUUID() {
    return crypto.randomUUID();
}

function isValidUUID(uuid) {
    if (typeof uuid !== 'string') return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
    if (!expDate || !expTime) return true;

    const cleanTime = expTime.includes(':') && expTime.split(':').length === 2
        ? `${expTime}:00`
        : expTime.split('.')[0];

    const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
    
    return isNaN(expDatetimeUTC.getTime()) || expDatetimeUTC <= new Date();
}

async function formatBytes(bytes) {
    if (bytes === 0 || bytes === null || bytes === undefined) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i))).toFixed(2) + ' ' + sizes[i];
}

function base32ToBuffer(base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const str = base32.toUpperCase().replace(/=+$/, '');
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array(Math.floor(str.length * 5 / 8));

    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        const charValue = base32Chars.indexOf(char);
        if (charValue === -1) throw new Error('Invalid Base32 character');

        value = (value << 5) | charValue;
        bits += 5;

        if (bits >= 8) {
            output[index++] = (value >>> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    return output.buffer.slice(0, index);
}

async function generateHOTP(secretBuffer, counter) {
    const counterBuffer = new ArrayBuffer(8);
    new DataView(counterBuffer).setBigUint64(0, BigInt(counter), false);

    const key = await crypto.subtle.importKey(
        'raw',
        secretBuffer,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );

    const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
    const hmacBuffer = new Uint8Array(hmac);

    const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
    const binary = (
        ((hmacBuffer[offset] & 0x7F) << 24) |
        ((hmacBuffer[offset + 1] & 0xFF) << 16) |
        ((hmacBuffer[offset + 2] & 0xFF) << 8) |
        (hmacBuffer[offset + 3] & 0xFF)
    );

    const otp = binary % 1000000;
    return otp.toString().padStart(6, '0');
}

async function validateTOTP(secret, code) {
    if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
        return false;
    }

    let secretBuffer;
    try {
        secretBuffer = base32ToBuffer(secret);
    } catch (e) {
        console.error(e.message);
        return false;
    }

    const timeStep = 30;
    const epoch = Math.floor(Date.now() / 1000);
    const currentCounter = Math.floor(epoch / timeStep);

    const counters = [currentCounter, currentCounter - 1, currentCounter + 1];

    for (const counter of counters) {
        const generatedCode = await generateHOTP(secretBuffer, counter);
        if (timingSafeEqual(code, generatedCode)) {
            return true;
        }
    }
    return false;
}

async function hashSHA256(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function d1KvGet(db, key, type = 'text') {
    if (!db) {
        return null;
    }
    try {
        const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
        const res = await stmt.first();

        if (!res) return null;

        if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
            db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run().catch(e => console.error(e.message));
            return null;
        }

        if (type === 'json') {
            try {
                return JSON.parse(res.value);
            } catch (e) {
                console.error(e.message);
                return null;
            }
        }
        return res.value;
    } catch (e) {
        console.error(e.message, e.stack);
        return null;
    }
}

async function d1KvPut(db, key, value, options = {}) {
    if (!db) {
        return;
    }
    try {
        let serializedValue = value;
        if (typeof value === 'object' && value !== null) {
            serializedValue = JSON.stringify(value);
        }

        const expiration = options.expirationTtl
            ? Math.floor(Date.now() / 1000 + options.expirationTtl)
            : null;

        await db.prepare(
            "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
        ).bind(key, serializedValue, expiration).run();
    } catch (e) {
        console.error(e.message);
    }
}

async function d1KvDelete(db, key) {
    if (!db) {
        return;
    }
    try {
        await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
    } catch (e) {
        console.error(e.message);
    }
}

async function checkRateLimit(db, key, limit, ttl) {
    if (!db) {
        return false;
    }
    try {
        const countStr = await d1KvGet(db, key);
        const count = parseInt(countStr, 10) || 0;

        if (count >= limit) {
            return true;
        }

        await d1KvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
        return false;
    } catch (e) {
        console.error(e.message);
        return false;
    }
}

async function logSecurityEvent(db, ctx, ip, type, details, uuid = null) {
    if (!db) {
        return;
    }
    try {
        const timestamp = Math.floor(Date.now() / 1000);
        const stmt = db.prepare(
            "INSERT INTO security_events (timestamp, ip, type, details, uuid) VALUES (?, ?, ?, ?, ?)"
        ).bind(timestamp, ip, type, details, uuid);

        ctx.waitUntil(stmt.run().catch(e => console.error(e.message)));
    } catch (e) {
        console.error(e.message, e.stack);
    }
}

async function addIpToBlacklist(db, ctx, ip, reason, ttl = CONST.IP_BLACKLIST_TTL) {
    if (!db) {
        return;
    }
    try {
        const expiration = (ttl === 0)
            ? (Math.floor(Date.now() / 1000) + 365 * 24 * 3600 * 100)
            : (Math.floor(Date.now() / 1000 + ttl));

        const stmt = db.prepare(
            "INSERT OR REPLACE INTO ip_blacklist (ip, expiration, reason, timestamp) VALUES (?, ?, ?, ?)"
        ).bind(ip, expiration, reason, Math.floor(Date.now() / 1000));

        ctx.waitUntil(stmt.run().then(() => {
            logSecurityEvent(db, ctx, ip, 'IP_BLACKLISTED', `IP blacklisted for ${reason}. TTL: ${ttl}s.`, null);
        }).catch(e => console.error(e.message)));

    } catch (e) {
        console.error(e.message, e.stack);
    }
}

async function checkBlockedIP(db, ip) {
    if (!db) return null;
    try {
        const now = Math.floor(Date.now() / 1000);
        const stmt = db.prepare("SELECT * FROM ip_blacklist WHERE ip = ?").bind(ip);
        const entry = await stmt.first();

        if (entry && entry.expiration > now) {
            return entry;
        } else if (entry && entry.expiration <= now) {
            db.prepare("DELETE FROM ip_blacklist WHERE ip = ?").bind(ip).run()
                .catch(e => console.error(e.message));
        }
        return null;
    } catch (e) {
        console.error(e.message);
        return null;
    }
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] +
        '-' +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] +
        '-' +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] +
        '-' +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] +
        '-' +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw new TypeError('Stringified UUID is invalid or malformed: ' + uuid);
    }
    return uuid;
}

// Part 2: VLESS Protocol Logic and Connection Handling

async function getUserData(env, uuid, ctx) {
    if (!isValidUUID(uuid)) {
        console.warn(`Invalid UUID format: ${uuid}`);
        return null;
    }
    if (!env.DB) {
        console.error("D1 binding missing. Cannot retrieve user data.");
        return null;
    }

    const cacheKey = `user:${uuid}`;
    let userData = null;

    try {
        userData = await d1KvGet(env.DB, cacheKey, 'json');
        if (userData && userData.uuid) {
            return userData;
        }
    } catch (e) {
        console.error(e.message);
    }

    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();

    if (!userFromDb) {
        if (userData) {
            ctx.waitUntil(d1KvDelete(env.DB, cacheKey));
        }
        return null;
    }

    const cachePromise = d1KvPut(env.DB, cacheKey, userFromDb, { expirationTtl: CONST.DB_CACHE_TTL });
    if (ctx) {
        ctx.waitUntil(cachePromise.catch(e => console.error(e.message)));
    } else {
        await cachePromise.catch(e => console.error(e.message));
    }

    return userFromDb;
}

async function updateUsage(env, uuid, bytes, ctx) {
    if (bytes <= 0 || !uuid) return;
    if (!env.DB) {
        console.error("D1 binding missing. Cannot update user usage.");
        return;
    }

    const usageLockKey = `usage_lock:${uuid}`;
    let lockAcquired = false;
    const LOCK_TTL = 5;

    try {
        const maxAttempts = 5;
        for (let i = 0; i < maxAttempts; i++) {
            const existingLock = await d1KvGet(env.DB, usageLockKey);
            if (!existingLock) {
                await d1KvPut(env.DB, usageLockKey, 'locked', { expirationTtl: LOCK_TTL });
                lockAcquired = true;
                break;
            } else {
                await new Promise(resolve => setTimeout(resolve, 100 * (i + 1)));
            }
        }

        if (!lockAcquired) {
            console.warn(`Failed to acquire lock for ${uuid} after attempts. Skipping usage update.`);
            return;
        }

        const usage = Math.round(bytes);
        const updatePromise = env.DB.prepare(
            "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
        ).bind(usage, uuid).run();

        const deleteCachePromise = d1KvDelete(env.DB, `user:${uuid}`);

        if (ctx) {
            ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise])
                .catch(err => console.error(err)));
        } else {
            await Promise.all([updatePromise, deleteCachePromise])
                .catch(err => console.error(err));
        }

    } catch (err) {
        console.error(err.message, err.stack);
    } finally {
        if (lockAcquired) {
            try {
                ctx.waitUntil(d1KvDelete(env.DB, usageLockKey).catch(e => console.error(e.message)));
            } catch (e) {
                console.error(e.message);
            }
        }
    }
}

async function resolveProxyIP(proxyHost) {
    const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const ipv6Regex = /^\[?([0-9a-fA-F:.]+)\]?$/;
    
    if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
        return proxyHost;
    }

    const dnsAPIs = [
        {
            url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`,
            parse: data => data.Answer?.find(a => a.type === 1)?.data
        },
        {
            url: `https://dns.google/resolve?name=${encodeURIComponent(proxyHost)}&type=A`,
            parse: data => data.Answer?.find(a => a.type === 1)?.data
        },
        {
            url: `https://dns.quad9.net/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`,
            parse: data => data.Answer?.find(a => a.type === 1)?.data
        }
    ];

    for (const api of dnsAPIs) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            const response = await fetch(api.url, {
                headers: { 'accept': 'application/dns-json' },
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                const data = await response.json();
                const ip = api.parse(data);
                if (ip && ipv4Regex.test(ip)) {
                    return ip;
                }
            }
        } catch (e) {
        }
    }
    console.warn(`Failed to resolve IP for ${proxyHost} after trying all DNS providers. Using original hostname as fallback.`);
    return proxyHost;
}

async function getGeo(ip, cfHeaders = null) {
    if (cfHeaders && (cfHeaders.city || cfHeaders.country || cfHeaders.asOrganization)) {
        return {
            city: cfHeaders.city || '',
            country: cfHeaders.country || '',
            isp: cfHeaders.asOrganization || ''
        };
    }

    const geoAPIs = [
        {
            url: `https://ip-api.com/json/${ip}?fields=status,message,city,country,isp`,
            parse: async (r) => {
                const data = await r.json();
                if (data.status === 'fail') throw new Error(data.message || 'API Error');
                return { city: data.city || '', country: data.country || '', isp: data.isp || '' };
            }
        },
        {
            url: `https://ipapi.co/${ip}/json/`,
            parse: async (r) => {
                const data = await r.json();
                if (data.error) throw new Error(data.reason || 'API Error');
                return { city: data.city || '', country: data.country_name || '', isp: data.org || '' };
            }
        },
        {
            url: `https://ipwho.is/${ip}`,
            parse: async (r) => {
                const data = await r.json();
                if (!data.success) throw new Error('API Error');
                return { city: data.city || '', country: data.country || '', isp: data.connection?.isp || '' };
            }
        },
        {
            url: `https://ipinfo.io/${ip}/json`,
            parse: async (r) => {
                const data = await r.json();
                if (data.bogon) throw new Error('Bogon IP');
                return { city: data.city || '', country: data.country || '', isp: data.org || '' };
            }
        },
        {
            url: `https://freeipapi.com/api/json/${ip}`,
            parse: async (r) => {
                const data = await r.json();
                if (data.message) throw new Error(data.message);
                return { city: data.cityName || '', country: data.countryName || '', isp: '' };
            }
        }
    ];

    for (const api of geoAPIs) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            const response = await fetch(api.url, {
                signal: controller.signal,
                headers: { 'Accept': 'application/json' }
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                const geo = await api.parse(response);
                if (geo && (geo.city || geo.country || geo.isp)) {
                    return geo;
                }
            }
        } catch (e) {
        }
    }

    console.warn(`Failed to get geo-location for IP ${ip} after trying all providers.`);
    return { city: 'Unknown', country: 'Global', isp: 'Unknown' };
}

function generateRandomPath(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `/${result}`;
}

const CORE_PRESETS = {
    xray: {
        tls: {
            path: () => generateRandomPath(12),
            security: 'tls',
            fp: 'chrome',
            alpn: 'http/1.1',
            extra: { ed: '2560' },
        },
        tcp: {
            path: () => generateRandomPath(12),
            security: 'none',
            fp: 'chrome',
            extra: { ed: '2560' },
        },
    },
    sb: {
        tls: {
            path: () => generateRandomPath(18),
            security: 'tls',
            fp: 'firefox',
            alpn: 'h3',
            extra: CONST.ED_PARAMS,
        },
        tcp: {
            path: () => generateRandomPath(18),
            security: 'none',
            fp: 'firefox',
            extra: CONST.ED_PARAMS,
        },
    },
};

function makeName(tag, proto) {
    return `${tag}-${proto.toUpperCase()}`;
}

function randomizeCase(str) {
    if (!str) return str;
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
    }
    return result;
}

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
    const params = new URLSearchParams({
        encryption: 'none',
        type: 'ws',
        host: host,
        path: path,
    });

    if (security) {
        params.set('security', security);
    }
    if (sni) params.set('sni', sni);
    if (fp) params.set('fp', fp);
    if (alpn) params.set('alpn', alpn);

    for (const [k, v] of Object.entries(extra)) {
        params.set(k, v);
    }

    return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
    const p = CORE_PRESETS[core]?.[proto];
    if (!p) {
        console.error(`Invalid core or protocol preset requested: core=${core}, proto=${proto}. Falling back to default TLS config.`);
        return createVlessLink({
            userID, address, port, host: hostName, path: generateRandomPath(12),
            security: 'tls', sni: hostName, fp: 'chrome', alpn: 'http/1.1',
            name: makeName(tag, 'DEFAULT_TLS')
        });
    }

    const sniValue = p.security === 'tls' ? randomizeCase(hostName) : undefined;

    return createVlessLink({
        userID,
        address,
        port,
        host: hostName,
        path: p.path(),
        security: p.security,
        sni: sniValue,
        fp: p.fp,
        alpn: p.alpn,
        extra: p.extra,
        name: makeName(tag, proto),
    });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName, env) {
    const mainDomains = [
        hostName,
        'www.visa.com', 'www.wto.org', 'creativecommons.org', 'www.speedtest.net',
        'sky.rethinkdns.com', 'cdnjs.com', 'zula.ir', 'go.inmobi.com',
        'mail.tm', 'temp-mail.org', 'ipaddress.my', 'mdbmax.com',
        'check-host.net', 'kodambroker.com', 'iplocation.io', 'whatismyip.org',
        'www.linkedin.com', 'exir.io', 'arzex.io', 'ok-ex.io',
        'arzdigital.com', 'pouyanit.com', 'auth.grok.com', 'grok.com',
        'maxmind.com', 'whatsmyip.com', 'iplocation.net', 'ipchicken.com',
        'showmyip.com', 'router-network.com', 'whatismyipaddress.com',
        'www.apple.com', 'www.microsoft.com', 'www.amazon.com', 'www.cloudflare.com',
        'www.google.com', 'github.com', 'gitlab.com', 'wikipedia.org',
        'developer.mozilla.org', 'www.nginx.com', 'www.apache.org',
        'telegram.org', 'bale.ai', 'ir.linkedin.com', 'divar.ir', 'snapp.ir',
        'jiring.ir', 'shaparak.ir', 'pishgaman.net', 'asriran.com', 'varzesh3.com',
        'isna.ir', 'farsnews.com', 'mehrnews.com', 'tasnimnews.com'
    ].sort(() => 0.5 - Math.random());

    const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096, 4430, 4431, 4432, 4433, 4434, 4435, 4436, 4437, 4438, 4439];
    const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095, 8000, 8008, 8009, 8010, 8011, 8012, 8013, 8014, 8015];

    let links = [];
    const isPagesDeployment = hostName.endsWith('.pages.dev');

    mainDomains.slice(0, 15).forEach((domain, i) => {
        links.push(
            buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i + 1}-TLS-1` }),
            buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i + 1}-TLS-2` }),
        );
        if (!isPagesDeployment) {
            links.push(
                buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i + 1}-TCP-1` }),
                buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i + 1}-TCP-2` }),
            );
        }
    });

    let dynamicProxyIPs = [];
    if (env.DB) {
        try {
            const { results } = await env.DB.prepare(
                "SELECT ip_port, latency_ms FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 20"
            ).all();
            dynamicProxyIPs = results.map(r => r.ip_port.split(':')[0]);
        } catch (e) {
            console.error(e.message);
        }
    }
    if (dynamicProxyIPs.length === 0) {
        try {
            const r = await fetch(
                'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
            );
            if (r.ok) {
                const json = await r.json();
                dynamicProxyIPs = [...(json.ipv4 || []), ...(json.ipv6 || [])]
                                .slice(0, 30)
                                .map((x) => x.ip);
            } else {
                console.warn(`Failed to fetch Cloudflare IPs: HTTP Status ${r.status}`);
            }
        } catch (e) {
            console.error(e.message, e.stack);
        }
    }

    dynamicProxyIPs.slice(0, 20).forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(
            buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i + 1}-TLS-1` }),
            buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i + 1}-TLS-2` }),
        );
        if (!isPagesDeployment) {
            links.push(
                buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i + 1}-TCP-1` }),
                buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i + 1}-TCP-2` }),
            );
        }
    });

    const uniqueLinks = Array.from(new Set(links)).sort(() => 0.5 - Math.random());

    const headers = new Headers({
        'Content-Type': 'text/plain;charset=utf-8',
        'Profile-Update-Interval': '6',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
    });
    addSecurityHeaders(headers, null, {});

    return new Response(safeBase64Encode(uniqueLinks.join('\n')), { headers });
}

async function ProtocolOverWSHandler(request, config, env, ctx) {
    let webSocket = null;

    try {
        const clientIp = request.headers.get('CF-Connecting-IP');

        const isBlocked = await checkBlockedIP(env.DB, clientIp);
        if (isBlocked) {
            console.warn(`VLESS connection denied for blacklisted IP: ${clientIp} (Reason: ${isBlocked.reason || 'Generic'}).`);
            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'VLESS_ACCESS_DENIED', `Attempted VLESS connection from blacklisted IP: ${clientIp}.`));
            return new Response('Access Denied: Your IP address is currently blocked due to suspicious activity. Please contact support.', { status: 403 });
        }

        if (config.scamalytics.username && config.scamalytics.apiKey) {
            if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
                console.warn(`VLESS connection denied for suspicious IP: ${clientIp} (Scamalytics).`);
                ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'VLESS_ACCESS_DENIED', `Scamalytics score too high. IP: ${clientIp}.`));
                ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Scamalytics High Score', CONST.IP_BLACKLIST_TTL));
                return new Response('Access Denied: Suspicious IP detected.', { status: 403 });
            }
        }

        const webSocketPair = new WebSocketPair();
        const [client, ws_server] = Object.values(webSocketPair);
        webSocket = ws_server;

        webSocket.accept();

        let addressRemote = '';
        let portRemote = 0;
        let sessionUsage = 0;
        let userUUID = '';
        let udpStreamWriter = null;

        const log = (info, event = null) => {
            const id = userUUID ? userUUID.substring(0, 8) : 'unknown';
            const target = addressRemote && portRemote ? `${addressRemote}:${portRemote}` : 'unknown_target';
            console.log(`[${id}][${target}] ${info}`, event);
        };

        const deferredUsageUpdate = () => {
            if (sessionUsage > 0 && userUUID) {
                const usageToUpdate = sessionUsage;
                const uuidToUpdate = userUUID;
                sessionUsage = 0;
                ctx.waitUntil(
                    updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
                        .catch(err => console.error(err))
                );
            }
        };
        const updateInterval = setInterval(deferredUsageUpdate, 10000);

        const finalCleanup = () => {
            clearInterval(updateInterval);
            deferredUsageUpdate();
            log('WebSocket session ended. Final usage logged and resources cleaned.');
        };

        webSocket.addEventListener('close', finalCleanup, { once: true });
        webSocket.addEventListener('error', finalCleanup, { once: true });

        const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
        const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);

        let remoteSocketWrapper = { value: null };

        readableWebSocketStream
            .pipeTo(new WritableStream({
                async write(chunk, controller) {
                    sessionUsage += chunk.byteLength;

                    if (udpStreamWriter) {
                        return udpStreamWriter.write(chunk);
                    }

                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const { user, hasError, message, addressType, portRemote: parsedPort, addressRemote: parsedAddress, rawDataIndex, ProtocolVersion, isUDP } = await ProcessProtocolHeader(chunk, env, ctx);

                    if (hasError || !user) {
                        log(`Authentication/Protocol Error: ${message}`, hasError ? new Error(message) : undefined);
                        if (message?.includes('invalid UUID') || message?.includes('user not found')) {
                            const invalidUuidRateKey = `invalid_uuid_attempt:${clientIp}`;
                            const attempts = parseInt(await d1KvGet(env.DB, invalidUuidRateKey) || '0', 10) + 1;
                            ctx.waitUntil(d1KvPut(env.DB, invalidUuidRateKey, attempts.toString(), { expirationTtl: CONST.INVALID_UUID_TTL }));
                            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'INVALID_UUID_ATTEMPT', `Invalid or unknown UUID in VLESS header. UUID: ${user?.uuid || 'N/A'}.`));
                            if (attempts >= CONST.INVALID_UUID_ATTEMPTS) {
                                console.warn(`Too many invalid UUID attempts from ${clientIp}. Blacklisting.`);
                                ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Repeated invalid UUID attempts', CONST.IP_BLACKLIST_TTL));
                            }
                        }
                        controller.error(new Error(message || 'Authentication failed.'));
                        safeCloseWebSocket(webSocket);
                        return;
                    }

                    userUUID = user.uuid;
                    addressRemote = parsedAddress;
                    portRemote = parsedPort;

                    if (isExpired(user.expiration_date, user.expiration_time)) {
                        log('Account expired.');
                        ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ACCOUNT_EXPIRED', `Expired account attempting VLESS connection. UUID: ${userUUID}.`));
                        controller.error(new Error('Account expired.'));
                        safeCloseWebSocket(webSocket);
                        return;
                    }

                    if (user.traffic_limit && user.traffic_limit > 0) {
                        const totalUsage = (user.traffic_used || 0) + sessionUsage;
                        if (totalUsage >= user.traffic_limit) {
                            log('Traffic limit exceeded.');
                            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'TRAFFIC_LIMIT_EXCEEDED', `Traffic limit exceeded for VLESS connection. UUID: ${userUUID}.`));
                            controller.error(new Error('Traffic limit exceeded.'));
                            safeCloseWebSocket(webSocket);
                            return;
                        }
                    }

                    if (user.ip_limit && user.ip_limit > -1) {
                        const ipCountResult = await env.DB.prepare(
                            "SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?"
                        ).bind(userUUID).first('count');
                        const ipCount = ipCountResult?.count || 0;

                        if (ipCount >= user.ip_limit) {
                            const existingIp = await env.DB.prepare(
                                "SELECT ip FROM user_ips WHERE uuid = ? AND ip = ?"
                            ).bind(userUUID, clientIp).first();

                            if (!existingIp) {
                                log(`IP limit exceeded for user ${userUUID}. Current IP: ${clientIp}.`);
                                ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'IP_LIMIT_EXCEEDED', `IP limit exceeded for VLESS connection. UUID: ${userUUID}. IP: ${clientIp}.`));
                                controller.error(new Error('IP limit exceeded.'));
                                safeCloseWebSocket(webSocket);
                                return;
                            }
                        }
                        ctx.waitUntil(env.DB.prepare(
                            "INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)"
                        ).bind(userUUID, clientIp).run()
                        .catch(e => console.error(e.message)));
                    }
                    
                    if (parsedPort && ![80, 443, 8443, 2053, 2083, 2087, 2096, 53].includes(parsedPort)) {
                         const portScanKey = `port_scan:${clientIp}`;
                         const accessedPortsStr = await d1KvGet(env.DB, portScanKey) || '';
                         const accessedPorts = new Set(accessedPortsStr.split(',').filter(Boolean).map(Number));
                         
                         if (!accessedPorts.has(parsedPort)) {
                             accessedPorts.add(parsedPort);
                             ctx.waitUntil(d1KvPut(env.DB, portScanKey, Array.from(accessedPorts).join(','), { expirationTtl: CONST.PORT_SCAN_TTL }));
                             ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'PORT_SCAN_ATTEMPT', `Attempted to access non-standard port: ${parsedPort}. Unique ports in window: ${accessedPorts.size}.`, userUUID));
                             if (accessedPorts.size >= CONST.PORT_SCAN_THRESHOLD) {
                                 console.warn(`Port scan detected from ${clientIp}. Blacklisting.`);
                                 ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Port scanning activity detected', CONST.IP_BLACKLIST_TTL));
                                 controller.error(new Error('Port scan detected. Connection denied.'));
                                 safeCloseWebSocket(webSocket);
                                 return;
                             }
                         }
                    }

                    const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0x00]);
                    const rawClientData = chunk.slice(rawDataIndex);

                    if (isUDP) {
                        if (portRemote === 53) {
                            const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => { sessionUsage += bytes; });
                            udpStreamWriter = dnsPipeline.write;
                            await udpStreamWriter(rawClientData);
                        } else {
                            log(`UDP command to unsupported port ${portRemote}. Closing connection.`);
                            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'UNSUPPORTED_UDP', `Attempted UDP connection to unsupported port: ${portRemote}.`, userUUID));
                            controller.error(new Error(`UDP only supported for DNS (port 53).`));
                            safeCloseWebSocket(webSocket);
                        }
                        return;
                    }

                    await HandleTCPOutBound(
                        remoteSocketWrapper,
                        addressType,
                        parsedAddress,
                        parsedPort,
                        rawClientData,
                        webSocket,
                        vlessResponseHeader,
                        log,
                        config,
                        (bytes) => { sessionUsage += bytes; }
                    );

                },
                close() {
                    log('Readable WebSocket stream closed.');
                    finalCleanup();
                },
                abort(err) {
                    log('Readable WebSocket stream aborted.', err);
                    finalCleanup();
                },
            }))
            .catch(err => {
                console.error(err.stack || err);
                safeCloseWebSocket(webSocket);
                finalCleanup();
            });

        return new Response(null, { status: 101, webSocket: client });
    } catch (e) {
        console.error(e.message, e.stack);
        if (webSocket) {
            try {
                safeCloseWebSocket(webSocket);
            } catch (closeErr) {
                console.error(closeErr);
            }
        }
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Internal Server Error.', { status: 500, headers });
    }
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
    try {
        if (protocolBuffer.byteLength < 24) {
            return { hasError: true, message: `Invalid data length in VLESS header: ${protocolBuffer.byteLength} bytes. Too short.` };
        }

        const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);

        const version = dataView.getUint8(0);
        if (version !== 0x00) {
            return { hasError: true, message: `Unsupported VLESS protocol version: ${version}. Expected 0x00.` };
        }

        let uuid;
        try {
            uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
        } catch (e) {
            return { hasError: true, message: `Invalid UUID format in VLESS header: ${e.message}.` };
        }

        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
            return { hasError: true, message: `User ${uuid} not found or invalid.` };
        }

        const optionsLengthIndex = 17;
        const optLength = dataView.getUint8(optionsLengthIndex);

        const commandIndex = optionsLengthIndex + 1 + optLength;
        if (protocolBuffer.byteLength < commandIndex + 1) {
            return { hasError: true, message: 'Invalid data length (command field missing in VLESS header).' };
        }
        const command = dataView.getUint8(commandIndex);
        if (command !== 0x01 && command !== 0x02) {
            return { hasError: true, message: `Unsupported command type: ${command}. Only TCP (1) and UDP (2) are supported.` };
        }

        const portIndex = commandIndex + 1;
        if (protocolBuffer.byteLength < portIndex + 2) {
            return { hasError: true, message: 'Invalid data length (port field missing in VLESS header).' };
        }
        const portRemote = dataView.getUint16(portIndex, false);

        const addressTypeIndex = portIndex + 2;
        if (protocolBuffer.byteLength < addressTypeIndex + 1) {
            return { hasError: true, message: 'Invalid data length (address type field missing in VLESS header).' };
        }
        const addressType = dataView.getUint8(addressTypeIndex);

        let addressValue, addressLength, addressValueIndex;

        switch (addressType) {
            case 0x01:
                addressLength = 4;
                addressValueIndex = addressTypeIndex + 1;
                if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
                    return { hasError: true, message: 'Invalid data length (IPv4 address bytes missing in VLESS header).' };
                }
                addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
                break;
            case 0x02:
                if (protocolBuffer.byteLength < addressTypeIndex + 2) {
                    return { hasError: true, message: 'Invalid data length (domain name length byte missing in VLESS header).' };
                }
                addressLength = dataView.getUint8(addressTypeIndex + 1);
                addressValueIndex = addressTypeIndex + 2;
                if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
                    return { hasError: true, message: 'Invalid data length (domain name bytes missing in VLESS header).' };
                }
                addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
                break;
            case 0x03:
                addressLength = 16;
                addressValueIndex = addressTypeIndex + 1;
                if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
                    return { hasError: true, message: 'Invalid data length (IPv6 address bytes missing in VLESS header).' };
                }
                addressValue = Array.from({ length: 8 }, (_, i) =>
                    dataView.getUint16(addressValueIndex + i * 2, false).toString(16)
                ).join(':');
                break;
            default:
                return { hasError: true, message: `Unsupported address type: ${addressType}. Expected 0x01 (IPv4), 0x02 (Domain), or 0x03 (IPv6).` };
        }

        const rawDataIndex = addressValueIndex + addressLength;

        if (protocolBuffer.byteLength < rawDataIndex) {
            return { hasError: true, message: 'Invalid data length (raw data missing after VLESS header).' };
        }

        return {
            user: userData,
            hasError: false,
            addressRemote: addressValue,
            addressType,
            portRemote,
            rawDataIndex,
            ProtocolVersion: new Uint8Array([version]),
            isUDP: command === 0x02,
        };
    } catch (e) {
        console.error(e.message, e.stack);
        return { hasError: true, message: `Protocol header processing error: ${e.message}.` };
    }
}

async function HandleTCPOutBound(
    remoteSocketWrapper,
    addressType,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    protocolResponseHeader,
    log,
    config,
    trafficCallback
) {
    async function connectAndWrite(address, port, useSocks = false) {
        let tcpSocket;
        if (useSocks && config.socks5.enabled && config.parsedSocks5Address) {
            tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
        } else {
            tcpSocket = connect({ hostname: address, port: port, secureTransport: 'on' });
        }
        remoteSocketWrapper.value = tcpSocket;
        log(`Connected to remote TCP: ${address}:${port}${useSocks ? ' (via SOCKS5)' : ''}.`);

        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retryConnection() {
        log('Attempting to retry TCP connection (e.g., due to proxy health switch or initial failure).');
        try {
            const newConfig = await Config.fromEnv(env);
            
            const tcpSocket = newConfig.socks5.enabled
                ? await connectAndWrite(addressRemote, portRemote, true)
                : await connectAndWrite(newConfig.proxyIP || addressRemote, newConfig.proxyPort || portRemote, false);

            tcpSocket.closed
                .catch(error => { console.log('Retry: new remote TCP socket closed with error:', error); })
                .finally(() => { safeCloseWebSocket(webSocket); });

            RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
        } catch (retryError) {
            log(`Retry connection failed: ${retryError.message}. Closing WebSocket.`, retryError);
            safeCloseWebSocket(webSocket);
        }
    }

    try {
        const tcpSocket = config.socks5.enabled
            ? await connectAndWrite(addressRemote, portRemote, true)
            : await connectAndWrite(config.proxyIP || addressRemote, config.proxyPort || portRemote, false);

        tcpSocket.closed
            .catch(error => { log('Remote TCP socket closed with error:', error); })
            .finally(() => { safeCloseWebSocket(webSocket); });

        await RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retryConnection, log, trafficCallback);

    } catch (connectionError) {
        log(`Failed to establish initial TCP connection: ${connectionError.message}. Closing WebSocket.`, connectionError);
        safeCloseWebSocket(webSocket);
    }
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (event.data instanceof ArrayBuffer) {
                    controller.enqueue(event.data);
                } else if (event.data instanceof Blob) {
                    event.data.arrayBuffer().then(buffer => controller.enqueue(buffer))
                        .catch(e => { console.error(e); controller.error(e); });
                } else {
                    console.error('Received unexpected WebSocket data type:', typeof event.data);
                    controller.error(new Error('Unsupported WebSocket data type received.'));
                }
            });
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
                log('WebSocket server stream closed.');
            });
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket server stream encountered error:', err);
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                console.error(error);
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
                log(`Enqueued ${earlyData.byteLength} bytes of early data.`);
            }
        },
        pull(_controller) {
        },
        cancel(reason) {
            log(`ReadableStream canceled: ${reason}`);
            safeCloseWebSocket(webSocketServer);
        },
    });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
    let hasIncomingData = false;
    try {
        await remoteSocket.readable
            .pipeTo(new WritableStream({
                async write(chunk, controller) {
                    if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
                        controller.error(new Error('WebSocket is not open, cannot write remote data.'));
                        return;
                    }
                    hasIncomingData = true;
                    if (protocolResponseHeader) {
                        await webSocket.send(await new Blob([protocolResponseHeader, chunk]).arrayBuffer());
                        protocolResponseHeader = null;
                    } else {
                        await webSocket.send(chunk);
                    }
                    if (trafficCallback) {
                        trafficCallback(chunk.byteLength);
                    }
                },
                close() {
                    log(`Remote socket readable stream closed. Has incoming data: ${hasIncomingData}`);
                    safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                    log(`Remote socket readable stream aborted: ${reason}`);
                    safeCloseWebSocket(webSocket);
                },
            }))
            .catch((error) => {
                console.error(error);
                safeCloseWebSocket(webSocket);
            });
    } catch (pipeError) {
        console.error(pipeError);
        safeCloseWebSocket(webSocket);
    }

    if (!hasIncomingData && retry && webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
        log('No incoming data received from remote socket, attempting retry.');
        await retry();
    } else if (!hasIncomingData && !retry) {
        log('No incoming data received and no retry mechanism. Closing WebSocket.');
        safeCloseWebSocket(webSocket);
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const buffer = new ArrayBuffer(binaryStr.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binaryStr.length; i++) {
            view[i] = binaryStr.charCodeAt(i);
        }
        return { earlyData: buffer, error: null };
    } catch (error) {
        return { earlyData: null, error: new Error(`Failed to decode base64 early data: ${error.message}`) };
    }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket && (socket.readyState === CONST.WS_READY_STATE_OPEN || socket.readyState === CONST.WS_READY_STATE_CLOSING)) {
            socket.close(1000, 'Normal Closure');
        }
    } catch (error) {
        console.error(error);
    }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
    let isHeaderSent = false;

    const transformStream = new TransformStream({
        transform(chunk, controller) {
            let index = 0;
            while (index + 2 <= chunk.byteLength) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer.buffer, lengthBuffer.byteOffset, lengthBuffer.byteLength).getUint16(0, false);

                if (index + 2 + udpPacketLength > chunk.byteLength) {
                    log(`Warning: Partial UDP packet received. Dropping. Current index: ${index}, Expected packet length: ${udpPacketLength}, Remaining chunk: ${chunk.byteLength - index}.`);
                    break;
                }

                const udpData = chunk.slice(index + 2, index + 2 + udpPacketLength);
                controller.enqueue(udpData);
                index += 2 + udpPacketLength;
            }
        },
    });

    transformStream.readable
        .pipeTo(new WritableStream({
            async write(udpChunk) {
                try {
                    const resp = await fetch('https://1.1.1.1/dns-query', {
                        method: 'POST',
                        headers: {
                            'content-type': 'application/dns-message',
                            'accept': 'application/dns-message',
                        },
                        body: udpChunk,
                    });

                    if (!resp.ok) {
                        throw new Error(`DNS-over-HTTPS request failed with status: ${resp.status}`);
                    }

                    const dnsQueryResult = await resp.arrayBuffer();
                    const udpSize = dnsQueryResult.byteLength;

                    const udpSizeBuffer = new Uint8Array(2);
                    new DataView(udpSizeBuffer.buffer).setUint16(0, udpSize, false);

                    if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
                        log(`DNS query success, response length: ${udpSize}`);
                        let responseChunk;
                        if (!isHeaderSent) {
                            responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                            isHeaderSent = true;
                        } else {
                            responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                        }
                        if (trafficCallback) {
                            trafficCallback(responseChunk.byteLength);
                        }
                        webSocket.send(responseChunk);
                    }
                } catch (error) {
                    log('DNS query error: ' + error.message, error);
                    safeCloseWebSocket(webSocket);
                }
            },
            close() {
                log('DNS WritableStream closed.');
            },
            abort(reason) {
                log('DNS WritableStream aborted: ' + reason);
                safeCloseWebSocket(webSocket);
            },
        }))
        .catch(e => {
            log('DNS stream pipeline error: ' + e.message, e);
            safeCloseWebSocket(webSocket);
        });

    const writer = transformStream.writable.getWriter();
    return {
        write: (chunk) => writer.write(chunk),
    };
}

function parseIPv6(ipv6) {
    const buffer = new ArrayBuffer(16);
    const view = new DataView(buffer);
    const parts = ipv6.split('::');

    let left = parts[0] ? parts[0].split(':') : [];
    let right = parts[1] ? parts[1].split(':') : [];

    if (left.length === 1 && left[0] === '') left = [];
    if (right.length === 1 && right[0] === '') right = [];

    const missing = 8 - (left.length + right.length);
    const expansion = [];
    if (missing > 0) {
        for (let i = 0; i < missing; i++) {
            expansion.push('0000');
        }
    }

    const hextets = [...left, ...expansion, ...right];

    if (hextets.length !== 8) {
        throw new Error(`Invalid IPv6 address format: ${ipv6}. Expected 8 hextets after expansion.`);
    }

    for (let i = 0; i < 8; i++) {
        const val = parseInt(hextets[i] || '0', 16);
        if (isNaN(val)) {
            throw new Error(`Invalid IPv6 hextet: '${hextets[i]}' in address ${ipv6}.`);
        }
        view.setUint16(i * 2, val, false);
    }
    return new Uint8Array(buffer);
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
    const { username, password, hostname, port } = parsedSocks5Address;
    let socket = null;
    let reader = null;
    let writer = null;
    let success = false;

    try {
        socket = connect({ hostname, port, secureTransport: 'on' });
        reader = socket.readable.getReader();
        writer = socket.writable.getWriter();
        const encoder = new TextEncoder();

        await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
        let res = (await reader.read()).value;

        if (!res || res[0] !== 0x05 || (res[1] !== 0x00 && res[1] !== 0x02)) {
            throw new Error(`SOCKS5 handshake failed: Proxy selected unsupported authentication method (0x${res?.[1]?.toString(16) || '??'}).`);
        }

        if (res[1] === 0x02) {
            if (!username || !password) {
                throw new Error('SOCKS5 proxy requires username/password, but none provided in configuration.');
            }
            const authRequest = new Uint8Array([
                0x01,
                username.length,
                ...encoder.encode(username),
                password.length,
                ...encoder.encode(password)
            ]);
            await writer.write(authRequest);
            res = (await reader.read()).value;

            if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
                throw new Error(`SOCKS5 authentication failed with proxy (Reply Code: 0x${res?.[1]?.toString(16) || '??'}).`);
            }
            log('SOCKS5 proxy authenticated with username/password.');
        } else if (res[1] === 0x00) {
            log('SOCKS5 proxy selected No Authentication.');
        }

        let dstAddr;
        switch (addressType) {
            case 0x01:
                dstAddr = new Uint8Array([0x01, ...addressRemote.split('.').map(Number)]);
                break;
            case 0x02:
                dstAddr = new Uint8Array([0x03, addressRemote.length, ...encoder.encode(addressRemote)]);
                break;
            case 0x03:
                const ipv6Bytes = parseIPv6(addressRemote);
                dstAddr = new Uint8Array(1 + 16);
                dstAddr[0] = 0x04;
                dstAddr.set(ipv6Bytes, 1);
                break;
            default:
                throw new Error(`Unsupported SOCKS5 destination address type: ${addressType}.`);
        }

        const socksRequest = new Uint8Array([
            0x05,
            0x01,
            0x00,
            ...dstAddr,
            (portRemote >> 8) & 0xff,
            portRemote & 0xff
        ]);
        await writer.write(socksRequest);
        res = (await reader.read()).value;

        if (!res || res[0] !== 0x05 || res[1] !== 0x00) {
            throw new Error(`SOCKS5 connection to ${addressRemote}:${portRemote} failed (Reply Code: 0x${res?.[1]?.toString(16) || '??'}).`);
        }

        log(`SOCKS5 tunnel to ${addressRemote}:${portRemote} established successfully.`);
        success = true;
        return socket;

    } catch (err) {
        log(`SOCKS5 connection error: ${err.message}`, err);
        throw err;
    } finally {
        if (writer) writer.releaseLock();
        if (reader) reader.releaseLock();
        if (!success && socket) {
            try {
                socket.abort();
            } catch (e) {
                log('Error aborting SOCKS5 socket in finally block:', e);
            }
        }
    }
}

function socks5AddressParser(address) {
    if (!address || typeof address !== 'string') {
        throw new Error('Invalid SOCKS5 address format: Must be a non-empty string.');
    }

    let username, password;
    let hostPart = address;

    const authSeparatorIndex = address.indexOf('@');
    if (authSeparatorIndex !== -1) {
        const authPart = address.substring(0, authSeparatorIndex);
        hostPart = address.substring(authSeparatorIndex + 1);
        const creds = authPart.split(':');
        if (creds.length === 2) {
            username = creds[0];
            password = creds[1];
        } else {
            throw new Error('Invalid SOCKS5 address: Malformed username/password credentials.');
        }
    }

    const lastColonIndex = hostPart.lastIndexOf(':');
    if (lastColonIndex === -1) {
        throw new Error('Invalid SOCKS5 address: Missing port in hostname:port format.');
    }

    let hostname;
    if (hostPart.startsWith('[') && hostPart.indexOf(']') < lastColonIndex) {
        const closingBracketIndex = hostPart.indexOf(']');
        if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
            throw new Error('Invalid SOCKS5 address: Malformed IPv6 address with brackets.');
        }
        hostname = hostPart.substring(1, closingBracketIndex);
    } else {
        hostname = hostPart.substring(0, lastColonIndex);
    }

    const portStr = hostPart.substring(lastColonIndex + 1);
    const port = parseInt(portStr, 10);

    if (!hostname || hostname.length === 0 || isNaN(port) || port <= 0 || port > 65535) {
        throw new Error(`Invalid SOCKS5 address: Malformed hostname or port value '${portStr}'.`);
    }

    return { username, password, hostname, port };
}

D1 Persistence Logic, API Endpoints, & Final Integration async function ensureTablesExist(env, ctx) { if (!env.DB) { console.warn('D1 binding not available. Skipping table creation.'); return; } try { const createTables = [ `CREATE TABLE IF NOT EXISTS users ( uuid TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expiration_date TEXT NOT NULL, expiration_time TEXT NOT NULL, notes TEXT, traffic_limit INTEGER, traffic_used INTEGER DEFAULT 0, ip_limit INTEGER DEFAULT -1 )`, `CREATE TABLE IF NOT EXISTS user_ips ( uuid TEXT, ip TEXT, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (uuid, ip), FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE )`, `CREATE TABLE IF NOT EXISTS key_value ( key TEXT PRIMARY KEY, value TEXT NOT NULL, expiration INTEGER )`, `CREATE TABLE IF NOT EXISTS proxy_health ( ip_port TEXT PRIMARY KEY, is_healthy INTEGER NOT NULL, latency_ms INTEGER, last_check INTEGER DEFAULT (strftime('%s', 'now')) )`, `CREATE TABLE IF NOT EXISTS security_events ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, ip TEXT NOT NULL, type TEXT NOT NULL, details TEXT, uuid TEXT )`, `CREATE TABLE IF NOT EXISTS ip_blacklist ( ip TEXT PRIMARY KEY, expiration INTEGER NOT NULL, reason TEXT, timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')) )` ]; const stmts = createTables.map(sql => env.DB.prepare(sql)); await env.DB.batch(stmts); const testUUID = env.UUID || Config.userID; const futureDate = new Date(); futureDate.setMonth(futureDate.getMonth() + 1); const expDate = futureDate.toISOString().split('T')[0]; const expTime = '23:59:59'; const insertTestUser = env.DB.prepare( "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)" ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1); await insertTestUser.run(); console.log('D1 tables initialized successfully and test user ensured.'); } catch (e) { console.error(e.message, e.stack); throw new Error('Database initialization failed. Critical error: ' + e.message); } } async function performHealthCheck(env, ctx) { if (!env.DB) { console.warn('D1 binding not available. Skipping health checks.'); return; } const proxyIps = env.PROXYIPS ? env.PROXYIPS.split(',').map(ip => ip.trim()) : Config.proxyIPs; const healthStmts = []; const results = await Promise.allSettled(proxyIps.map(async (ipPort) => { const [host, port = '443'] = ipPort.split(':'); let latency = null; let isHealthy = 0; const start = Date.now(); try { const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT); const response = await fetch(`https://${host}:${port}`, { method: 'HEAD', signal: controller.signal, redirect: 'manual', }); clearTimeout(timeoutId); if (response.ok || (response.status >= 400 && response.status < 500)) { latency = Date.now() - start; isHealthy = 1; } else { console.warn(`Health check for ${ipPort} failed: HTTP Status ${response.status}.`); } } catch (e) { if (e.name === 'AbortError') { console.error(`Health check for ${ipPort} timed out after ${CONST.HEALTH_CHECK_TIMEOUT}ms.`); } else { console.error(`Health check failed for ${ipPort}: ${e.message}.`); } } finally { healthStmts.push( env.DB.prepare( "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)" ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000)) ); } })); results.filter(r => r.status === 'rejected').forEach(r => console.error(r.reason)); try { await env.DB.batch(healthStmts); console.log('Proxy health check and database update completed.'); } catch (e) { console.error(e.message, e.stack); throw new Error('Failed to batch update proxy health status in D1: ' + e.message); } } async function cleanupOldIps(env, ctx) { if (!env.DB) { console.warn('D1 binding not available. Skipping data cleanup.'); return; } try { const cleanupPromises = []; cleanupPromises.push(env.DB.prepare( "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)" ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run()); cleanupPromises.push(env.DB.prepare( "DELETE FROM ip_blacklist WHERE expiration <= ?" ).bind(Math.floor(Date.now() / 1000)).run()); cleanupPromises.push(env.DB.prepare( "DELETE FROM key_value WHERE expiration <= ?" ).bind(Math.floor(Date.now() / 1000)).run()); await Promise.all(cleanupPromises.map(p => p.catch(e => console.error(e.message)))); console.log(`Cleaned up user_ips records older than ${CONST.IP_CLEANUP_AGE_DAYS} days and expired blacklist/key_value entries.`); } catch (e) { console.error(e.message, e.stack); throw new Error('Failed to perform scheduled database cleanup: ' + e.message); } } async function handleAdminRequest(request, env, ctx, adminPrefix) { try { await ensureTablesExist(env, ctx); const url = new URL(request.url); const jsonHeader = { 'Content-Type': 'application/json' }; const htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' }); const clientIp = request.headers.get('CF-Connecting-IP'); if (!env.ADMIN_KEY) { addSecurityHeaders(htmlHeaders, null, {}); return new Response('Admin panel not configured: ADMIN_KEY is missing.', { status: 503, headers: htmlHeaders }); } const isBlocked = await checkBlockedIP(env.DB, clientIp); if (isBlocked) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_ACCESS_DENIED', `Attempted admin panel access from blacklisted IP: ${clientIp}.`)); addSecurityHeaders(htmlHeaders, null, {}); return new Response('Access Denied: Your IP address is currently blocked due to suspicious activity. Please contact support.', { status: 403, headers: htmlHeaders }); } if (env.ADMIN_IP_WHITELIST) { const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim()); if (!allowedIps.includes(clientIp)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_ACCESS_DENIED', `IP not in ADMIN_IP_WHITELIST. IP: ${clientIp}.`)); addSecurityHeaders(htmlHeaders, null, {}); return new Response('Access denied: Your IP is not authorized.', { status: 403, headers: htmlHeaders }); } } else { const scamalyticsConfig = { username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username, apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey, baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl, }; if (scamalyticsConfig.username && scamalyticsConfig.apiKey) { if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_ACCESS_DENIED', `Scamalytics score too high. IP: ${clientIp}.`)); ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Scamalytics High Score', CONST.IP_BLACKLIST_TTL)); addSecurityHeaders(htmlHeaders, null, {}); return new Response('Access denied: Your IP has been flagged as suspicious.', { status: 403, headers: htmlHeaders }); } } } if (env.ADMIN_HEADER_KEY) { const headerValue = request.headers.get('X-Admin-Auth'); if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_ACCESS_DENIED', `Invalid custom auth header. IP: ${clientIp}.`)); addSecurityHeaders(htmlHeaders, null, {}); return new Response('Access denied: Invalid authentication header.', { status: 403, headers: htmlHeaders }); } } const adminBasePath = `/${adminPrefix}/${env.ADMIN_KEY}`; if (!url.pathname.startsWith(adminBasePath)) { const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Not Found', { status: 404, headers }); } const adminSubPath = url.pathname.substring(adminBasePath.length) || '/'; if (adminSubPath.startsWith('/api/')) { if (!env.DB) { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); return new Response(JSON.stringify({ error: 'Database not configured for API operations.' }), { status: 503, headers }); } if (!(await isAdmin(request, env))) { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); return new Response(JSON.stringify({ error: 'Unauthorized: Admin session expired or not logged in.' }), { status: 401, headers }); } const apiRateKey = `admin_api_rate:${clientIp}`; if (await checkRateLimit(env.DB, apiRateKey, 100, 60)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_API_RATE_LIMIT', `API rate limit exceeded. IP: ${clientIp}.`)); const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); return new Response(JSON.stringify({ error: 'API rate limit exceeded. Please try again later.' }), { status: 429, headers }); } if (request.method !== 'GET') { const origin = request.headers.get('Origin'); const secFetchSite = request.headers.get('Sec-Fetch-Site'); const currentHost = url.hostname; if (!origin || new URL(origin).hostname !== currentHost || secFetchSite !== 'same-origin') { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'CSRF_ATTEMPT', `Invalid request origin or Sec-Fetch-Site header. IP: ${clientIp}.`)); const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); return new Response(JSON.stringify({ error: 'Invalid request origin or Sec-Fetch-Site header (CSRF defense).' }), { status: 403, headers }); } const csrfToken = request.headers.get('X-CSRF-Token'); const cookieCsrfMatch = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/); const cookieCsrf = cookieCsrfMatch ? cookieCsrfMatch[1] : null; if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'CSRF_ATTEMPT', `Invalid or missing CSRF token. IP: ${clientIp}.`)); const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); return new Response(JSON.stringify({ error: 'CSRF validation failed: Invalid or missing CSRF token.' }), { status: 403, headers }); } } if (adminSubPath === '/api/stats' && request.method === 'GET') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count'); const expiredQuery = await env.DB.prepare( "SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')" ).first(); const expiredUsers = expiredQuery?.count || 0; const activeUsers = totalUsers - expiredUsers; const totalTrafficQuery = await env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first(); const totalTraffic = totalTrafficQuery?.sum || 0; const blockedIPsCount = await env.DB.prepare("SELECT COUNT(*) as count FROM ip_blacklist WHERE expiration > ?").bind(Math.floor(Date.now() / 1000)).first('count'); let proxyHealth = { is_healthy: 0, latency_ms: null }; try { const healthResult = await env.DB.prepare( "SELECT is_healthy, latency_ms FROM proxy_health ORDER BY is_healthy DESC, latency_ms ASC LIMIT 1" ).first(); if (healthResult) { proxyHealth = { is_healthy: !!healthResult.is_healthy, latency_ms: healthResult.latency_ms }; } } catch (healthErr) { console.error(healthErr.message); } return new Response(JSON.stringify({ total_users: totalUsers, active_users: activeUsers, expired_users: expiredUsers, total_traffic: totalTraffic, proxy_health: proxyHealth, blocked_ips_count: blockedIPsCount }), { status: 200, headers }); } catch (e) { return new Response(JSON.stringify({ error: `Failed to fetch stats: ${e.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/users' && request.method === 'GET') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const { results } = await env.DB.prepare( "SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC" ).all(); return new Response(JSON.stringify(results ?? []), { status: 200, headers }); } catch (e) { return new Response(JSON.stringify({ error: `Failed to fetch users: ${e.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/users' && request.method === 'POST') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const { uuid, exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit } = await request.json(); if (!uuid || !expDate || !expTime || !isValidUUID(uuid) || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) { throw new Error('Invalid or missing UUID, expiration date, or expiration time format.'); } await env.DB.prepare( "INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)" ).bind(uuid, expDate, expTime, notes || null, traffic_limit, ip_limit || -1).run(); ctx.waitUntil(d1KvDelete(env.DB, `user:${uuid}`)); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'USER_CREATED', `User ${uuid} created by admin.`, uuid)); return new Response(JSON.stringify({ success: true, uuid }), { status: 201, headers }); } catch (error) { if (error.message?.includes('UNIQUE constraint failed')) { return new Response(JSON.stringify({ error: 'User with this UUID already exists.' }), { status: 409, headers }); } return new Response(JSON.stringify({ error: `Failed to create user: ${error.message}` }), { status: 400, headers }); } } if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const { uuids } = await request.json(); if (!Array.isArray(uuids) || uuids.length === 0) { throw new Error('Invalid request: Expected an array of UUIDs.'); } const deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?"); const stmts = uuids.map(uuid => deleteUserStmt.bind(uuid)); await env.DB.batch(stmts); ctx.waitUntil(Promise.all(uuids.map(uuid => d1KvDelete(env.DB, `user:${uuid}`))) .catch(e => console.error(e.message))); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'USER_BULK_DELETED', `Bulk deleted ${uuids.length} users by admin.`, null)); return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers }); } catch (error) { return new Response(JSON.stringify({ error: `Failed to bulk delete users: ${error.message}` }), { status: 400, headers }); } } const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/i); if (userRouteMatch && request.method === 'PUT') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); const uuid = userRouteMatch[1]; try { const { exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit, reset_traffic } = await request.json(); if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) { throw new Error('Invalid expiration date or time format.'); } if (!isValidUUID(uuid)) { throw new Error('Invalid UUID for update operation.'); } let query = "UPDATE users SET expiration_date = ?, expiration_time = ?, notes = ?, traffic_limit = ?, ip_limit = ?"; let binds = [expDate, expTime, notes || null, traffic_limit, ip_limit || -1]; if (reset_traffic) { query += ", traffic_used = 0"; } query += " WHERE uuid = ?"; binds.push(uuid); const { changes } = await env.DB.prepare(query).bind(...binds).run(); if (changes === 0) { return new Response(JSON.stringify({ success: false, message: 'User not found or no changes made.' }), { status: 404, headers }); } ctx.waitUntil(d1KvDelete(env.DB, `user:${uuid}`)); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'USER_UPDATED', `User ${uuid} updated by admin (reset_traffic: ${reset_traffic}).`, uuid)); return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers }); } catch (error) { return new Response(JSON.stringify({ error: `Failed to update user: ${error.message}` }), { status: 400, headers }); } } if (userRouteMatch && request.method === 'DELETE') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); const uuid = userRouteMatch[1]; if (!isValidUUID(uuid)) { return new Response(JSON.stringify({ error: 'Invalid UUID for delete operation.' }), { status: 400, headers }); } try { const { changes } = await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run(); if (changes === 0) { return new Response(JSON.stringify({ success: false, message: 'User not found.' }), { status: 404, headers }); } ctx.waitUntil(d1KvDelete(env.DB, `user:${uuid}`)); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'USER_DELETED', `User ${uuid} deleted by admin.`, uuid)); return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers }); } catch (error) { return new Response(JSON.stringify({ error: `Failed to delete user: ${error.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/logout' && request.method === 'POST') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { await d1KvDelete(env.DB, 'admin_session_token_hash'); const responseHeaders = new Headers(); responseHeaders.append('Set-Cookie', `auth_token=; Max-Age=0; Path=${adminBasePath}; Secure; HttpOnly; SameSite=Strict`); responseHeaders.append('Set-Cookie', `csrf_token=; Max-Age=0; Path=${adminBasePath}; Secure; SameSite=Strict`); addSecurityHeaders(responseHeaders, null, {}); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_LOGOUT', 'Admin logged out.')); return new Response(JSON.stringify({ success: true, message: 'Logged out successfully.' }), { status: 200, headers: responseHeaders }); } catch (error) { return new Response(JSON.stringify({ error: `Logout failed: ${error.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/health-check' && request.method === 'POST') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { await performHealthCheck(env, ctx); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'HEALTH_CHECK_TRIGGERED', 'Admin manually triggered proxy health check.')); return new Response(JSON.stringify({ success: true, message: 'Proxy health check initiated.' }), { status: 200, headers }); } catch (error) { return new Response(JSON.stringify({ error: `Health check failed to initiate: ${error.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/security/events' && request.method === 'GET') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const queryParams = new URL(request.url).searchParams; const eventType = queryParams.get('type') || ''; const timeFilter = queryParams.get('time') || ''; const searchTerm = queryParams.get('search') || ''; let whereClauses = []; let bindParams = []; if (eventType) { whereClauses.push("type = ?"); bindParams.push(eventType); } if (searchTerm) { whereClauses.push("(ip LIKE ? OR details LIKE ? OR uuid LIKE ?)"); bindParams.push(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`); } let timeThreshold = 0; const now = Math.floor(Date.now() / 1000); if (timeFilter === '24h') timeThreshold = now - (24 * 3600); else if (timeFilter === '7d') timeThreshold = now - (7 * 24 * 3600); else if (timeFilter === '30d') timeThreshold = now - (30 * 24 * 3600); if (timeThreshold > 0) { whereClauses.push("timestamp >= ?"); bindParams.push(timeThreshold); } const whereSql = whereClauses.length > 0 ? " WHERE " + whereClauses.join(" AND ") : ""; const query = `SELECT * FROM security_events ${whereSql} ORDER BY timestamp DESC LIMIT 200`; const { results } = await env.DB.prepare(query).bind(...bindParams).all(); return new Response(JSON.stringify(results ?? []), { status: 200, headers }); } catch (e) { return new Response(JSON.stringify({ error: `Failed to fetch security events: ${e.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/security/blacklist' && request.method === 'GET') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const now = Math.floor(Date.now() / 1000); const queryParams = new URL(request.url).searchParams; const searchTerm = queryParams.get('search') || ''; let whereClauses = ["expiration > ?"]; let bindParams = [now]; if (searchTerm) { whereClauses.push("(ip LIKE ? OR reason LIKE ?)"); bindParams.push(`%${searchTerm}%`, `%${searchTerm}%`); } const whereSql = whereClauses.length > 0 ? " WHERE " + whereClauses.join(" AND ") : ""; const query = `SELECT ip, expiration, reason, timestamp FROM ip_blacklist ${whereSql} ORDER BY timestamp DESC`; const { results } = await env.DB.prepare(query).bind(...bindParams).all(); return new Response(JSON.stringify(results ?? []), { status: 200, headers }); } catch (e) { return new Response(JSON.stringify({ error: `Failed to fetch IP blacklist: ${e.message}` }), { status: 500, headers }); } } if (adminSubPath === '/api/security/blacklist' && request.method === 'POST') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); try { const { ip, reason, duration } = await request.json(); if (!ip || !reason) { throw new Error('IP address and reason are required for blacklisting.'); } const ttl = duration === 0 ? (365 * 24 * 3600 * 100) : duration; await addIpToBlacklist(env.DB, ctx, ip, reason, ttl); return new Response(JSON.stringify({ success: true, ip, reason, duration }), { status: 201, headers }); } catch (e) { return new Response(JSON.stringify({ error: `Failed to add IP to blacklist: ${e.message}` }), { status: 400, headers }); } } const blacklistRemoveMatch = adminSubPath.match(/^\/api\/security\/blacklist\/([^/]+)$/i); if (blacklistRemoveMatch && request.method === 'DELETE') { const headers = new Headers(jsonHeader); addSecurityHeaders(headers, null, {}); const ipToRemove = decodeURIComponent(blacklistRemoveMatch[1]); try { const { changes } = await env.DB.prepare("DELETE FROM ip_blacklist WHERE ip = ?").bind(ipToRemove).run(); if (changes === 0) { return new Response(JSON.stringify({ success: false, message: 'IP not found in blacklist.' }), { status: 404, headers }); } ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'IP_WHITELISTED', `IP ${ipToRemove} whitelisted by admin.`)); return new Response(JSON.stringify({ success: true, ip: ipToRemove, message: 'IP removed from blacklist.' }), { status: 200, headers }); } catch (e) { return new Response(JSON.stringify({ error: `Failed to remove IP from blacklist: ${e.message}` }), { status: 500, headers }); } } if (adminSubPath === '/') { if (request.method === 'POST') { const rateLimitKey = `admin_login_fail_ip:${clientIp}`; try { const failCountStr = await d1KvGet(env.DB, rateLimitKey); const failCount = parseInt(failCountStr, 10) || 0; if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'BRUTE_FORCE_LOGIN', `Too many failed login attempts (${failCount + 1}). IP blacklisted. IP: ${clientIp}.`)); ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Brute-force login attempts', CONST.BRUTE_FORCE_LOGIN_TTL)); addSecurityHeaders(htmlHeaders, null, {}); return new Response('Too many failed attempts. Your IP has been temporarily blocked.', { status: 429, headers: htmlHeaders }); } const formData = await request.formData(); const passwordAttempt = formData.get('password'); const totpAttempt = formData.get('totp'); if (timingSafeEqual(passwordAttempt, env.ADMIN_KEY)) { if (env.ADMIN_TOTP_SECRET) { if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpAttempt))) { const nonce = generateNonce(); addSecurityHeaders(htmlHeaders, nonce, {}); let html = adminLoginHTML.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`); html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce); html = html.replace('</form>', `</form><p class="error">Invalid 2FA code. Attempt ${failCount + 1}/${CONST.ADMIN_LOGIN_FAIL_LIMIT}.</p>`); ctx.waitUntil(d1KvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL })); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'BRUTE_FORCE_LOGIN', `Invalid 2FA code. IP: ${clientIp}.`)); return new Response(html, { status: 401, headers: htmlHeaders }); } } const authToken = crypto.randomUUID(); const csrfToken = crypto.randomUUID(); const hashedAuthToken = await hashSHA256(authToken); ctx.waitUntil(Promise.all([ d1KvPut(env.DB, 'admin_session_token_hash', hashedAuthToken, { expirationTtl: CONST.ADMIN_SESSION_TTL }), d1KvDelete(env.DB, rateLimitKey) ]).catch(e => console.error(e.message))); const responseHeaders = new Headers({ 'Location': adminBasePath }); responseHeaders.append('Set-Cookie', `auth_token=${authToken}; HttpOnly; Secure; Path=${adminBasePath}; Max-Age=${CONST.ADMIN_SESSION_TTL}; SameSite=Strict`); responseHeaders.append('Set-Cookie', `csrf_token=${csrfToken}; Secure; Path=${adminBasePath}; Max-Age=${CONST.ADMIN_SESSION_TTL}; SameSite=Strict`); addSecurityHeaders(responseHeaders, null, {}); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_LOGIN_SUCCESS', `Admin logged in successfully. IP: ${clientIp}.`)); return new Response(null, { status: 302, headers: responseHeaders }); } else { ctx.waitUntil(d1KvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL })); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'BRUTE_FORCE_LOGIN', `Invalid password attempt. IP: ${clientIp}.`)); const nonce = generateNonce(); addSecurityHeaders(htmlHeaders, nonce, {}); let html = adminLoginHTML.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`); html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce); html = html.replace('</form>', `</form><p class="error">Invalid password. Attempt ${failCount + 1}/${CONST.ADMIN_LOGIN_FAIL_LIMIT}.</p>`); return new Response(html, { status: 401, headers: htmlHeaders }); } } catch (e) { console.error(e.message, e.stack); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_LOGIN_ERROR', `Internal server error during login: ${e.message}. IP: ${clientIp}.`)); addSecurityHeaders(htmlHeaders, null, {}); return new Response('Internal server error during login. Please try again.', { status: 500, headers: htmlHeaders }); } } if (request.method === 'GET') { const nonce = generateNonce(); addSecurityHeaders(htmlHeaders, nonce, {}); let htmlContent; if (await isAdmin(request, env)) { htmlContent = adminPanelHTML; htmlContent = htmlContent.replace('ADMIN_API_BASE_PATH_PLACEHOLDER', adminBasePath + '/api'); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ADMIN_DASHBOARD_ACCESS', `Admin dashboard accessed. IP: ${clientIp}.`)); } else { htmlContent = adminLoginHTML; htmlContent = htmlContent.replace('ADMIN_PATH_PLACEHOLDER', adminBasePath); } htmlContent = htmlContent.replace(/CSP_NONCE_PLACEHOLDER/g, nonce); return new Response(htmlContent, { headers: htmlHeaders }); } const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Method Not Allowed', { status: 405, headers }); } const custom404Html = `<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>404 - Not Found</title> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"> <style nonce="CSP_NONCE_PLACEHOLDER"> :root { --bg-main: #0a0e17; --text-primary: #F9FAFB; --text-secondary: #9CA3AF; --accent: #3B82F6; --border-light: rgba(255,255,255,0.06); --shadow-light: 0 8px 32px rgba(0,0,0,0.3); --radius-lg: 16px; } * { box-sizing: border-box; margin: 0; padding: 0; } body { font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: linear-gradient(135deg, #030712 0%, #0f172a 25%, #1e1b4b 50%, #0f172a 75%, #030712 100%); background-size: 400% 400%; animation: gradient-shift 15s ease infinite; color: var(--text-primary); min-height: 100vh; display: flex; justify-content: center; align-items: center; text-align: center; padding: 20px; position: relative; overflow: hidden; } body::before { content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%); pointer-events: none; z-index: -1; } @keyframes gradient-shift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } } .container-404 { background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7)); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-radius: var(--radius-lg); padding: 40px; border: 1px solid var(--border-light); box-shadow: var(--shadow-light), inset 0 1px 0 rgba(255,255,255,0.05); max-width: 600px; width: 100%; position: relative; z-index: 1; animation: fadeIn 0.8s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } } h1 { font-size: 72px; color: var(--accent); margin-bottom: 20px; font-weight: 800; text-shadow: 0 0 20px rgba(59, 130, 246, 0.5); animation: bounceIn 1s ease-out forwards; } @keyframes bounceIn { 0% { transform: scale(0.3); opacity: 0; } 50% { transform: scale(1.1); opacity: 1; } 70% { transform: scale(0.9); } 100% { transform: scale(1); } } p { font-size: 18px; color: var(--text-secondary); margin-bottom: 30px; line-height: 1.6; } .home-link { display: inline-block; background: linear-gradient(135deg, var(--accent) 0%, #6366f1 100%); color: white; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3); position: relative; overflow: hidden; } .home-link::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s ease; } .home-link:hover::before { left: 100%; } .home-link:hover { transform: translateY(-3px) scale(1.02); box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5); } .home-link:active { transform: translateY(0); box-shadow: 0 2px 10px rgba(59, 130, 246, 0.3); } @media (max-width: 600px) { h1 { font-size: 56px; } p { font-size: 16px; } .container-404 { padding: 30px 20px; } } </style> </head> <body> <div class="container-404"> <h1>404</h1> <p>Oops! The page you're looking for couldn't be found.</p> <p>It might have been moved, deleted, or never existed.</p> <a href="/" class="home-link">Go to Homepage</a> </div> </body> </html>`; const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' }); addSecurityHeaders(headers, generateNonce(), {}); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'PAGE_NOT_FOUND', `404 hit for path: ${url.pathname}. IP: ${clientIp}.`)); return new Response(custom404Html.replace(/CSP_NONCE_PLACEHOLDER/g, generateNonce()), { status: 404, headers }); } catch (e) { console.error('Fetch handler top-level error (unhandled route):', e.message, e.stack); ctx.waitUntil(logSecurityEvent(env.DB, ctx, request.headers.get('CF-Connecting-IP') || 'unknown', 'CRITICAL_ERROR', `Unhandled fetch error in main handler: ${e.message}. Path: ${new URL(request.url).pathname}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Internal Server Error. Please try again later.', { status: 500, headers }); } }, async scheduled(event, env, ctx) { console.log(`[Scheduled Task] Event received at ${new Date().toISOString()}`); try { await ensureTablesExist(env, ctx); console.log('Running scheduled proxy health check...'); await performHealthCheck(env, ctx); console.log('Scheduled proxy health check completed.'); console.log('Running scheduled old data cleanup...'); await cleanupOldIps(env, ctx); console.log('Scheduled old data cleanup completed.'); console.log('All scheduled tasks completed successfully.'); } catch (e) { console.error('[Scheduled Task] Execution error:', e.message, e.stack); ctx.waitUntil(logSecurityEvent(env.DB, ctx, 'system', 'SCHEDULED_TASK_ERROR', `Scheduled task failed: ${e.message}.`)); } }, };
