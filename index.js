import { connect } from 'cloudflare:sockets';

// ============================================================================
// TYPESCRIPT INTERFACES & TYPES
// ============================================================================

/**
 * @typedef {Object} User
 * @property {string} uuid
 * @property {string} created_at
 * @property {string} expiration_date
 * @property {string} expiration_time
 * @property {string} notes
 * @property {number} traffic_limit
 * @property {number} traffic_used
 * @property {number} ip_limit
 */

/**
 * @typedef {Object} VlessHeaderResult
 * @property {boolean} hasError
 * @property {string} [message]
 * @property {User} [user]
 * @property {string} [addressRemote]
 * @property {number} [portRemote]
 * @property {number} [rawDataIndex]
 * @property {boolean} [isUDP]
 */

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

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

    /**
     * Load configuration from environment variables
     * @param {any} env - Cloudflare environment bindings
     * @returns {Promise<Object>} Configuration object
     */
    async fromEnv(env) {
        let selectedProxyIP = null;

        // Try to get best proxy from database
        if (env.DB) {
            try {
                const { results } = await env.DB.prepare(
                    "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
                ).all();
                selectedProxyIP = results && results[0] ? results[0].ip_port : null;
            } catch (error) {
                console.error('DB proxy selection error:', error.message);
            }
        }

        // Fallback to environment variable
        if (!selectedProxyIP) {
            selectedProxyIP = env.PROXYIP;
        }

        // Fallback to random default proxy
        if (!selectedProxyIP) {
            selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
        }

        // Final fallback
        if (!selectedProxyIP) {
            console.error('CRITICAL: No proxy IP available');
            selectedProxyIP = this.proxyIPs[0] || '127.0.0.1:443';
        }

        const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
        const socks5Address = env.SOCKS5 || this.socks5.address;
        let socks5Enabled = !!env.SOCKS5 || this.socks5.enabled;
        let parsedSocks5Address = null;

        // Parse SOCKS5 address if enabled
        if (socks5Enabled && socks5Address) {
            try {
                parsedSocks5Address = socks5AddressParser(socks5Address);
            } catch (error) {
                console.error('SOCKS5 parsing error:', error.message);
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

// ============================================================================
// VLESS LINK GENERATION
// ============================================================================

/**
 * Generate a random path for VLESS links
 * @param {number} length - Length of the random path
 * @returns {string} Random path starting with /
 */
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

/**
 * Create a name tag for VLESS link
 * @param {string} tag - Base tag name
 * @param {string} proto - Protocol name
 * @returns {string} Formatted name
 */
function makeName(tag, proto) {
    return `${tag}-${proto.toUpperCase()}`;
}

/**
 * Randomize case of characters in string (for SNI randomization)
 * @param {string} str - Input string
 * @returns {string} String with randomized case
 */
function randomizeCase(str) {
    if (!str) return str;
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
    }
    return result;
}

/**
 * Create a VLESS protocol link
 * @param {Object} params - Link parameters
 * @returns {string} Complete VLESS link
 */
function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
    const params = new URLSearchParams({
        encryption: 'none',
        type: 'ws',
        host: host,
        path: path,
    });

    if (security) params.set('security', security);
    if (sni) params.set('sni', sni);
    if (fp) params.set('fp', fp);
    if (alpn) params.set('alpn', alpn);

    // Add extra parameters
    for (const [k, v] of Object.entries(extra)) {
        params.set(k, String(v));
    }

    return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

/**
 * Build a VLESS link based on core type and protocol
 * @param {Object} params - Build parameters
 * @returns {string} VLESS link
 */
function buildLink({ core, proto, userID, hostName, address, port, tag }) {
    const p = CORE_PRESETS[core] && CORE_PRESETS[core][proto] ? CORE_PRESETS[core][proto] : null;
    
    if (!p) {
        console.error(`Invalid core/proto: ${core}/${proto}`);
        return createVlessLink({
            userID, address, port, host: hostName, path: generateRandomPath(12),
            security: 'tls', sni: hostName, fp: 'chrome', alpn: 'http/1.1',
            name: makeName(tag, 'DEFAULT_TLS')
        });
    }

    const sniValue = p.security === 'tls' ? randomizeCase(hostName) : undefined;

    return createVlessLink({
        userID, address, port,
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

/**
 * Pick a random element from array
 * @param {Array} arr - Input array
 * @returns {*} Random element
 */
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// ============================================================================
// SUBSCRIPTION HANDLER
// ============================================================================

/**
 * Handle subscription requests and generate VLESS links
 * @param {string} core - Core type (xray or sb)
 * @param {string} userID - User UUID
 * @param {string} hostName - Hostname
 * @param {any} env - Environment bindings
 * @returns {Promise<Response>} Response with base64 encoded links
 */
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
    ].sort(() => 0.5 - Math.random());

    const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096, 4430, 4431, 4432, 4433];
    const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095, 8000, 8008];

    let links = [];
    const isPagesDeployment = hostName.endsWith('.pages.dev');

    // Generate links for domains
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

    // Get dynamic proxy IPs from database
    let dynamicProxyIPs = [];
    if (env.DB) {
        try {
            const { results } = await env.DB.prepare(
                "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 20"
            ).all();
            dynamicProxyIPs = results.map((r) => r.ip_port.split(':')[0]);
        } catch (error) {
            console.error('DB proxy fetch error:', error.message);
        }
    }

    // Fallback to GitHub IPs if database query failed
    if (dynamicProxyIPs.length === 0) {
        try {
            const response = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
            if (response.ok) {
                const json = await response.json();
                dynamicProxyIPs = [...(json.ipv4 || []), ...(json.ipv6 || [])]
                    .slice(0, 30)
                    .map((x) => x.ip);
            }
        } catch (error) {
            console.error('IP fetch error:', error.message);
        }
    }

    // Generate links for proxy IPs
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

    // Remove duplicates and shuffle
    const uniqueLinks = Array.from(new Set(links)).sort(() => 0.5 - Math.random());

    const headers = new Headers({
        'Content-Type': 'text/plain;charset=utf-8',
        'Profile-Update-Interval': '6',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
    });
    addSecurityHeaders(headers, null);

    return new Response(safeBase64Encode(uniqueLinks.join('\n')), { headers });
}

// ============================================================================
// PROTOCOL HANDLER
// ============================================================================

/**
 * Handle WebSocket upgrade for VLESS protocol
 * @param {Request} request - Incoming request
 * @param {Object} config - Configuration object
 * @param {any} env - Environment bindings
 * @param {any} ctx - Execution context
 * @returns {Promise<Response>} WebSocket response
 */
async function ProtocolOverWSHandler(request, config, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
        return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    server.accept();

    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Check if IP is blocked
    const isBlocked = await checkBlockedIP(env.DB, clientIp);
    if (isBlocked) {
        server.close(1008, 'Access Denied');
        return new Response('Access Denied', { status: 403 });
    }

    // Handle WebSocket connection asynchronously
    handleWebSocket(server, clientIp, config, env, ctx).catch((error) => {
        console.error('WebSocket error:', error);
        safeCloseWebSocket(server);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

/**
 * Handle WebSocket connection and data streaming
 * @param {WebSocket} ws - WebSocket connection
 * @param {string} clientIp - Client IP address
 * @param {Object} config - Configuration object
 * @param {any} env - Environment bindings
 * @param {any} ctx - Execution context
 */
async function handleWebSocket(ws, clientIp, config, env, ctx) {
    let remoteSocket = null;
    let userUUID = '';

    try {
        const earlyDataHeader = '';
        const readableStream = makeReadableWebSocketStream(ws, earlyDataHeader);

        await readableStream.pipeTo(new WritableStream({
            async write(chunk) {
                // First chunk contains VLESS header
                if (!remoteSocket) {
                    const parsed = await processVlessHeader(chunk, env, ctx);
                    if (parsed.hasError || !parsed.user) {
                        throw new Error(parsed.message || 'Auth failed');
                    }

                    userUUID = parsed.user.uuid;

                    // Create TCP connection to proxy server
                    const address = config.proxyIP || parsed.addressRemote;
                    const port = config.proxyPort || parsed.portRemote;

                    remoteSocket = connect({
                        hostname: address,
                        port: port,
                    });

                    // Send response header to client
                    const responseHeader = new Uint8Array([0x00, 0x00]);
                    ws.send(responseHeader);

                    // Pipe remote data to WebSocket
                    pipeRemoteToWS(remoteSocket, ws).catch((error) => {
                        console.error('Pipe error:', error);
                    });

                    // Write initial data to remote
                    const writer = remoteSocket.writable.getWriter();
                    await writer.write(chunk.slice(parsed.rawDataIndex));
                    writer.releaseLock();
                } else {
                    // Write subsequent data to remote
                    const writer = remoteSocket.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                }
            },
            close() {
                console.log('Stream closed');
                if (remoteSocket) {
                    try {
                        remoteSocket.close();
                    } catch (error) {
                        console.error('Error closing remote socket:', error);
                    }
                }
            },
            abort(reason) {
                console.log('Stream aborted:', reason);
                if (remoteSocket) {
                    try {
                        remoteSocket.close();
                    } catch (error) {
                        console.error('Error closing remote socket:', error);
                    }
                }
            }
        }));
    } catch (error) {
        console.error('WebSocket handler error:', error);
        safeCloseWebSocket(ws);
        if (remoteSocket) {
            try {
                remoteSocket.close();
            } catch (closeError) {
                console.error('Error closing remote socket:', closeError);
            }
        }
    }
}

/**
 * Pipe data from remote socket to WebSocket
 * @param {Socket} remoteSocket - Remote TCP socket
 * @param {WebSocket} ws - WebSocket connection
 */
async function pipeRemoteToWS(remoteSocket, ws) {
    try {
        await remoteSocket.readable.pipeTo(new WritableStream({
            write(chunk) {
                if (ws.readyState === CONST.WS_READY_STATE_OPEN) {
                    ws.send(chunk);
                }
            },
            close() {
                safeCloseWebSocket(ws);
            },
            abort(reason) {
                console.error('Remote abort:', reason);
                safeCloseWebSocket(ws);
            }
        }));
    } catch (error) {
        console.error('Pipe remote error:', error);
        safeCloseWebSocket(ws);
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generate a cryptographic nonce for CSP
 * @returns {string} Base64 encoded nonce
 */
function generateNonce() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode(...Array.from(arr)));
}

/**
 * Add security headers to response
 * @param {Headers} headers - Response headers object
 * @param {string|null} nonce - CSP nonce
 */
function addSecurityHeaders(headers, nonce) {
    const csp = [
        "default-src 'self'",
        nonce ? `script-src 'self' 'nonce-${nonce}'` : "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "object-src 'none'",
    ].join('; ');

    headers.set('Content-Security-Policy', csp);
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
}

/**
 * Safely encode string to base64
 * @param {string} str - Input string
 * @returns {string} Base64 encoded string
 */
function safeBase64Encode(str) {
    try {
        return btoa(unescape(encodeURIComponent(str)));
    } catch (error) {
        console.error('Base64 error:', error);
        return btoa(str);
    }
}

/**
 * Validate UUID format
 * @param {string} uuid - UUID string
 * @returns {boolean} True if valid UUID
 */
function isValidUUID(uuid) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

/**
 * Convert Uint8Array to UUID string
 * @param {Uint8Array} arr - Byte array
 * @returns {string} UUID string
 */
function stringify(arr) {
    const byteToHex = [];
    for (let i = 0; i < 256; i++) {
        byteToHex[i] = (i + 0x100).toString(16).slice(1);
    }

    return (
        byteToHex[arr[0]] + byteToHex[arr[1]] + byteToHex[arr[2]] + byteToHex[arr[3]] + '-' +
        byteToHex[arr[4]] + byteToHex[arr[5]] + '-' +
        byteToHex[arr[6]] + byteToHex[arr[7]] + '-' +
        byteToHex[arr[8]] + byteToHex[arr[9]] + '-' +
        byteToHex[arr[10]] + byteToHex[arr[11]] + byteToHex[arr[12]] + byteToHex[arr[13]] + byteToHex[arr[14]] + byteToHex[arr[15]]
    ).toLowerCase();
}

/**
 * Parse SOCKS5 address format
 * @param {string} address - SOCKS5 address string
 * @returns {Object} Parsed address components
 */
function socks5AddressParser(address) {
    const authIndex = address.indexOf('@');
    let username, password;
    let hostPart = address;

    if (authIndex !== -1) {
        const authPart = address.substring(0, authIndex);
        const colonIndex = authPart.indexOf(':');
        username = authPart.substring(0, colonIndex);
        password = authPart.substring(colonIndex + 1);
        hostPart = address.substring(authIndex + 1);
    }

    const lastColon = hostPart.lastIndexOf(':');
    const hostname = hostPart.substring(0, lastColon);
    const port = parseInt(hostPart.substring(lastColon + 1), 10);

    return { username, password, hostname, port };
}

// ============================================================================
// MAIN WORKER EXPORT
// ============================================================================

export default {
    /**
     * Handle incoming HTTP requests
     * @param {Request} request - Incoming request
     * @param {any} env - Environment bindings
     * @param {any} ctx - Execution context
     * @returns {Promise<Response>} Response object
     */
    async fetch(request, env, ctx) {
        try {
            // Ensure database tables exist
            await ensureTablesExist(env, ctx);

            const url = new URL(request.url);
            const upgradeHeader = request.headers.get('Upgrade');

            // Handle WebSocket connections
            if (upgradeHeader === 'websocket') {
                const config = await Config.fromEnv(env);
                return await ProtocolOverWSHandler(request, config, env, ctx);
            }

            // Handle subscription requests
            const pathSegments = url.pathname.split('/').filter(Boolean);
            if (pathSegments.length >= 2) {
                const [coreType, uuid] = pathSegments;

                if ((coreType === 'xray' || coreType === 'sb') && isValidUUID(uuid)) {
                    const user = await getUserData(env, uuid, ctx);
                    if (!user) {
                        return new Response('User not found', { status: 404 });
                    }
                    return await handleIpSubscription(coreType, uuid, url.hostname, env);
                }
            }

            // Serve homepage
            const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
            const nonce = generateNonce();
            addSecurityHeaders(headers, nonce);

            return new Response(getHomepageHTML(nonce), { headers });

        } catch (error) {
            console.error('Main error:', error);
            return new Response('Internal Server Error', { status: 500 });
        }
    },

    /**
     * Handle scheduled cron tasks
     * @param {ScheduledEvent} event - Scheduled event
     * @param {any} env - Environment bindings
     * @param {any} ctx - Execution context
     */
    async scheduled(event, env, ctx) {
        console.log('Scheduled task running at:', new Date().toISOString());
        try {
            await ensureTablesExist(env, ctx);
            await performHealthCheck(env, ctx);
            await cleanupOldData(env, ctx);
        } catch (error) {
            console.error('Scheduled error:', error);
        }
    },
};

// ============================================================================
// HEALTH CHECK & CLEANUP
// ============================================================================

/**
 * Perform health check on proxy servers
 * @param {any} env - Environment bindings
 * @param {any} ctx - Execution context
 */
async function performHealthCheck(env, ctx) {
    if (!env.DB) return;

    const proxyIps = env.PROXYIPS ? env.PROXYIPS.split(',').map((ip) => ip.trim()) : Config.proxyIPs;

    const results = await Promise.allSettled(proxyIps.map(async (ipPort) => {
        const [host, port = '443'] = ipPort.split(':');
        let latency = null;
        let isHealthy = 0;
        const start = Date.now();

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
            
            const response = await fetch(`https://${host}:${port}`, {
                method: 'HEAD',
                signal: controller.signal,
            });
            
            clearTimeout(timeoutId);

            if (response.ok || response.status >= 400) {
                latency = Date.now() - start;
                isHealthy = 1;
            }
        } catch (error) {
            console.error(`Health check failed for ${ipPort}:`, error.message);
        }

        return { ipPort, isHealthy, latency };
    }));

    // Save results to database
    const statements = [];
    for (const result of results) {
        if (result.status === 'fulfilled') {
            const { ipPort, isHealthy, latency } = result.value;
            statements.push(
                env.DB.prepare(
                    "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
                ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
            );
        }
    }

    try {
        if (statements.length > 0) {
            await env.DB.batch(statements);
            console.log('Health check completed successfully');
        }
    } catch (error) {
        console.error('Health check DB error:', error);
    }
}

/**
 * Clean up old data from database
 * @param {any} env - Environment bindings
 * @param {any} ctx - Execution context
 */
async function cleanupOldData(env, ctx) {
    if (!env.DB) return;

    try {
        const cleanupQueries = [
            env.DB.prepare(`DELETE FROM user_ips WHERE last_seen < datetime('now', '-${CONST.IP_CLEANUP_AGE_DAYS} days')`).run(),
            env.DB.prepare("DELETE FROM ip_blacklist WHERE expiration <= ?").bind(Math.floor(Date.now() / 1000)).run(),
            env.DB.prepare("DELETE FROM key_value WHERE expiration <= ?").bind(Math.floor(Date.now() / 1000)).run(),
        ];

        await Promise.all(cleanupQueries);
        console.log('Cleanup completed successfully');
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}

// ============================================================================
// VLESS HEADER PARSER
// ============================================================================

/**
 * Process and parse VLESS protocol header
 * @param {Uint8Array} buffer - Buffer containing VLESS header
 * @param {any} env - Environment bindings
 * @param {any} ctx - Execution context
 * @returns {Promise<VlessHeaderResult>} Parsed header result
 */
async function processVlessHeader(buffer, env, ctx) {
    try {
        if (buffer.byteLength < 24) {
            return { hasError: true, message: 'Invalid header length' };
        }

        // Check protocol version
        const version = buffer[0];
        if (version !== 0x00) {
            return { hasError: true, message: 'Unsupported version' };
        }

        // Extract user UUID
        const uuid = stringify(buffer.slice(1, 17));
        const user = await getUserData(env, uuid, ctx);
        if (!user) {
            return { hasError: true, message: 'User not found' };
        }

        const optLength = buffer[17];
        const commandIndex = 18 + optLength;
        const command = buffer[commandIndex];

        // Extract destination port
        const portRemote = (buffer[commandIndex + 1] << 8) | buffer[commandIndex + 2];
        const addressType = buffer[commandIndex + 3];

        let addressRemote = '';
        let addressLength = 0;

        // Parse destination address based on type
        if (addressType === 0x01) {
            // IPv4
            addressLength = 4;
            addressRemote = Array.from(buffer.slice(commandIndex + 4, commandIndex + 8)).join('.');
        } else if (addressType === 0x02) {
            // Domain Name
            addressLength = buffer[commandIndex + 4];
            addressRemote = new TextDecoder().decode(buffer.slice(commandIndex + 5, commandIndex + 5 + addressLength));
        } else if (addressType === 0x03) {
            // IPv6
            addressLength = 16;
            const ipv6 = buffer.slice(commandIndex + 4, commandIndex + 20);
            addressRemote = Array.from({ length: 8 }, (_, i) =>
                ((ipv6[i * 2] << 8) | ipv6[i * 2 + 1]).toString(16)
            ).join(':');
        }

        const rawDataIndex = commandIndex + 4 + (addressType === 0x02 ? 1 : 0) + addressLength;

        return {
            hasError: false,
            user,
            addressRemote,
            portRemote,
            rawDataIndex,
            isUDP: command === 0x02,
        };
    } catch (error) {
        return { hasError: true, message: error.message };
    }
}

// ============================================================================
// WEBSOCKET UTILITIES
// ============================================================================

/**
 * Convert WebSocket to ReadableStream
 * @param {WebSocket} ws - WebSocket connection
 * @param {string} earlyDataHeader - Early data header
 * @returns {ReadableStream} Readable stream
 */
function makeReadableWebSocketStream(ws, earlyDataHeader) {
    let hasReceivedEarlyData = false;

    return new ReadableStream({
        start(controller) {
            ws.addEventListener('message', (event) => {
                const data = event.data;
                if (data instanceof ArrayBuffer) {
                    controller.enqueue(new Uint8Array(data));
                }
            });

            ws.addEventListener('close', () => {
                controller.close();
            });

            ws.addEventListener('error', (error) => {
                controller.error(error);
            });

            // Process early data if present
            if (earlyDataHeader && !hasReceivedEarlyData) {
                const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
                if (earlyData) {
                    controller.enqueue(earlyData);
                    hasReceivedEarlyData = true;
                }
            }
        },
    });
}

/**
 * Convert base64 string to ArrayBuffer
 * @param {string} base64 - Base64 encoded string
 * @returns {Object} Object with earlyData and error
 */
function base64ToArrayBuffer(base64) {
    if (!base64) return { earlyData: null, error: null };
    try {
        const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return { earlyData: bytes, error: null };
    } catch (error) {
        return { earlyData: null, error: error };
    }
}

/**
 * Safely close WebSocket connection
 * @param {WebSocket} ws - WebSocket to close
 */
function safeCloseWebSocket(ws) {
    try {
        if (ws.readyState === CONST.WS_READY_STATE_OPEN || ws.readyState === CONST.WS_READY_STATE_CLOSING) {
            ws.close(1000, 'Normal');
        }
    } catch (error) {
        console.error('Close error:', error);
    }
}

// ============================================================================
// DATABASE & USER FUNCTIONS
// ============================================================================

/**
 * Ensure all required database tables exist
 * @param {any} env - Environment bindings
 * @param {any} ctx - Execution context
 */
async function ensureTablesExist(env, ctx) {
    if (!env.DB) return;

    const tables = [
        `CREATE TABLE IF NOT EXISTS users (
            uuid TEXT PRIMARY KEY,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expiration_date TEXT NOT NULL,
            expiration_time TEXT NOT NULL,
            notes TEXT,
            traffic_limit INTEGER,
            traffic_used INTEGER DEFAULT 0,
            ip_limit INTEGER DEFAULT -1
        )`,
        `CREATE TABLE IF NOT EXISTS user_ips (
            uuid TEXT,
            ip TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (uuid, ip)
        )`,
        `CREATE TABLE IF NOT EXISTS key_value (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expiration INTEGER
        )`,
        `CREATE TABLE IF NOT EXISTS ip_blacklist (
            ip TEXT PRIMARY KEY,
            expiration INTEGER NOT NULL,
            reason TEXT,
            timestamp INTEGER NOT NULL
        )`,
        `CREATE TABLE IF NOT EXISTS proxy_health (
            ip_port TEXT PRIMARY KEY,
            is_healthy INTEGER DEFAULT 1,
            latency_ms INTEGER,
            last_check INTEGER
        )`,
    ];

    try {
        await env.DB.batch(tables.map((sql) => env.DB.prepare(sql)));
        
        // Add test user
        const testUUID = env.UUID || Config.userID;
        const futureDate = new Date();
        futureDate.setMonth(futureDate.getMonth() + 1);
        
        await env.DB.prepare(
            "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes) VALUES (?, ?, ?, ?)"
        ).bind(testUUID, futureDate.toISOString().split('T')[0], '23:59:59', 'Test User').run();
        
        console.log('Tables initialized successfully');
    } catch (error) {
        console.error('DB init error:', error);
    }
}

/**
 * Get user data from database
 * @param {any} env - Environment bindings
 * @param {string} uuid - User UUID
 * @param {any} ctx - Execution context
 * @returns {Promise<User|null>} User object or null
 */
async function getUserData(env, uuid, ctx) {
    if (!isValidUUID(uuid) || !env.DB) return null;

    try {
        const user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
        return user;
    } catch (error) {
        console.error('Get user error:', error);
        return null;
    }
}

/**
 * Check if IP address is blocked
 * @param {any} db - Database binding
 * @param {string} ip - IP address to check
 * @returns {Promise<boolean>} True if blocked
 */
async function checkBlockedIP(db, ip) {
    if (!db) return false;

    try {
        const now = Math.floor(Date.now() / 1000);
        const entry = await db.prepare("SELECT * FROM ip_blacklist WHERE ip = ?").bind(ip).first();
        return entry && entry.expiration > now;
    } catch (error) {
        console.error('Check blocked IP error:', error);
        return false;
    }
}

// ============================================================================
// HOMEPAGE HTML - ULTIMATE QUANTUM EDITION
// ============================================================================

/**
 * Generate beautiful homepage HTML
 * @param {string} nonce - CSP nonce for inline scripts
 * @returns {string} Complete HTML page
 */
function getHomepageHTML(nonce) {
    return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="پیشرفته‌ترین سرویس پروکسی VLESS با تکنولوژی کوانتومی">
    <title>⚡ VLESS Quantum Worker - سریع‌ترین پروکسی جهان</title>
    <style nonce="${nonce}">
        @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700;900&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px) rotate(0deg); }
            50% { transform: translateY(-30px) rotate(5deg); }
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        @keyframes glow {
            0%, 100% { box-shadow: 0 0 20px rgba(102, 126, 234, 0.5), 0 0 40px rgba(118, 75, 162, 0.3); }
            50% { box-shadow: 0 0 40px rgba(102, 126, 234, 0.8), 0 0 80px rgba(118, 75, 162, 0.6); }
        }

        @keyframes particleFloat {
            0% { transform: translateY(100vh) translateX(0) scale(0); opacity: 0; }
            10% { opacity: 1; transform: scale(1); }
            90% { opacity: 1; }
            100% { transform: translateY(-100vh) translateX(100px) scale(0); opacity: 0; }
        }

        body {
            font-family: 'Vazirmatn', 'Segoe UI', Tahoma, sans-serif;
            background: linear-gradient(-45deg, #667eea, #764ba2, #f093fb, #4facfe);
            background-size: 400% 400%;
            animation: gradientShift 15s ease infinite;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow-x: hidden;
        }

        body::before {
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 2px, transparent 2px);
            background-size: 60px 60px;
            animation: rotate 60s linear infinite;
            opacity: 0.4;
            z-index: 0;
        }

        .particles {
            position: absolute;
            width: 100%;
            height: 100%;
            overflow: hidden;
            z-index: 0;
            pointer-events: none;
        }

        .particle {
            position: absolute;
            background: rgba(255, 255, 255, 0.6);
            border-radius: 50%;
            pointer-events: none;
        }

        .container {
            background: rgba(255, 255, 255, 0.98);
            backdrop-filter: blur(30px);
            border-radius: 40px;
            padding: 70px 60px;
            box-shadow: 
                0 40px 100px rgba(0,0,0,0.3),
                0 0 150px rgba(102, 126, 234, 0.6),
                inset 0 0 100px rgba(255,255,255,0.1);
            max-width: 1100px;
            width: 100%;
            position: relative;
            z-index: 1;
            animation: float 8s ease-in-out infinite, slideIn 1s ease-out;
            border: 3px solid rgba(255,255,255,0.5);
        }

        .logo {
            text-align: center;
            margin-bottom: 50px;
            position: relative;
        }

        .logo-icon {
            font-size: 100px;
            animation: rotate 4s linear infinite;
            display: inline-block;
            filter: drop-shadow(0 15px 30px rgba(102, 126, 234, 0.7));
            position: relative;
        }

        .logo-icon::after {
            content: '⚡';
            position: absolute;
            top: 0;
            left: 0;
            animation: pulse 2s ease-in-out infinite;
        }

        h1 {
            color: #667eea;
            margin-bottom: 40px;
            font-size: 52px;
            font-weight: 900;
            text-align: center;
            text-shadow: 3px 3px 6px rgba(0,0,0,0.15);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: slideIn 1s ease-out 0.2s both;
            letter-spacing: -1px;
        }

        .subtitle {
            text-align: center;
            font-size: 20px;
            color: #555;
            margin-bottom: 50px;
            font-weight: 600;
            animation: slideIn 1s ease-out 0.4s both;
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 30px;
            margin: 50px 0;
        }

        .feature-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 30px;
            border-radius: 25px;
            color: white;
            transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            cursor: pointer;
            position: relative;
            overflow: hidden;
            animation: slideIn 1s ease-out both;
            border: 2px solid rgba(255,255,255,0.2);
        }

        .feature-card:nth-child(1) { animation-delay: 0.6s; }
        .feature-card:nth-child(2) { animation-delay: 0.7s; }
        .feature-card:nth-child(3) { animation-delay: 0.8s; }
        .feature-card:nth-child(4) { animation-delay: 0.9s; }
        .feature-card:nth-child(5) { animation-delay: 1s; }
        .feature-card:nth-child(6) { animation-delay: 1.1s; }

        .feature-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(255,255,255,0.3), transparent);
            transform: rotate(45deg);
            transition: all 0.5s;
        }

        .feature-card:hover::before {
            left: 100%;
        }

        .feature-card:hover {
            transform: translateY(-15px) scale(1.05);
            box-shadow: 
                0 30px 80px rgba(102, 126, 234, 0.6),
                0 0 60px rgba(118, 75, 162, 0.4);
            animation: glow 2s ease-in-out infinite;
        }

        .feature-icon {
            font-size: 60px;
            margin-bottom: 20px;
            display: block;
            filter: drop-shadow(0 8px 15px rgba(0,0,0,0.4));
            animation: float 3s ease-in-out infinite;
        }

        .feature-title {
            font-size: 24px;
            font-weight: 800;
            margin-bottom: 15px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }

        .feature-desc {
            font-size: 15px;
            opacity: 0.95;
            line-height: 1.8;
            font-weight: 400;
        }

        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 30px;
            margin: 60px 0;
        }

        .stat-box {
            text-align: center;
            padding: 35px 25px;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            border-radius: 25px;
            color: white;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 15px 40px rgba(245, 87, 108, 0.4);
            border: 2px solid rgba(255,255,255,0.3);
            animation: slideIn 1s ease-out both;
        }

        .stat-box:nth-child(1) { animation-delay: 1.2s; }
        .stat-box:nth-child(2) { animation-delay: 1.3s; }
        .stat-box:nth-child(3) { animation-delay: 1.4s; }
        .stat-box:nth-child(4) { animation-delay: 1.5s; }

        .stat-box:hover {
            transform: scale(1.15) rotate(-2deg);
            box-shadow: 0 25px 60px rgba(245, 87, 108, 0.6);
        }

        .stat-number {
            font-size: 48px;
            font-weight: 900;
            margin-bottom: 12px;
            text-shadow: 3px 3px 6px rgba(0,0,0,0.3);
            animation: pulse 3s ease-in-out infinite;
        }

        .stat-label {
            font-size: 16px;
            opacity: 0.95;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .status {
            display: inline-flex;
            align-items: center;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 20px 50px;
            border-radius: 60px;
            font-weight: 800;
            margin-top: 40px;
            box-shadow: 0 20px 50px rgba(16, 185, 129, 0.5);
            animation: pulse 2.5s ease-in-out infinite, slideIn 1s ease-out 1.6s both;
            font-size: 22px;
            border: 2px solid rgba(255,255,255,0.3);
            cursor: pointer;
            transition: all 0.3s;
        }

        .status:hover {
            transform: scale(1.1);
            box-shadow: 0 30px 70px rgba(16, 185, 129, 0.7);
        }

        .status::before {
            content: '✓';
            display: inline-block;
            width: 32px;
            height: 32px;
            background: white;
            color: #10b981;
            border-radius: 50%;
            margin-left: 20px;
            font-weight: bold;
            line-height: 32px;
            font-size: 20px;
            animation: rotate 2s linear infinite;
        }

        .tech-stack {
            margin-top: 60px;
            padding: 40px;
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.15) 0%, rgba(118, 75, 162, 0.15) 100%);
            border-radius: 30px;
            border: 3px solid rgba(102, 126, 234, 0.3);
            animation: slideIn 1s ease-out 1.7s both;
            box-shadow: 0 10px 40px rgba(102, 126, 234, 0.2);
        }

        .tech-stack h3 {
            color: #667eea;
            margin-bottom: 30px;
            font-size: 32px;
            text-align: center;
            font-weight: 800;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }

        .tech-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 18px;
            justify-content: center;
        }

        .tech-tag {
            background: white;
            color: #667eea;
            padding: 12px 24px;
            border-radius: 30px;
            font-weight: 700;
            font-size: 15px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            border: 2px solid #667eea;
            cursor: pointer;
        }

        .tech-tag:hover {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            transform: translateY(-5px) scale(1.1);
            box-shadow: 0 15px 35px rgba(102, 126, 234, 0.5);
        }

        .center-text {
            text-align: center;
        }

        .description {
            color: #555;
            line-height: 2;
            margin: 40px 0;
            font-size: 18px;
            text-align: center;
            font-weight: 500;
            animation: slideIn 1s ease-out 0.5s both;
        }

        .description strong {
            color: #667eea;
            font-weight: 800;
        }

        @media (max-width: 768px) {
            .container {
                padding: 50px 30px;
                border-radius: 30px;
            }

            h1 {
                font-size: 38px;
            }

            .subtitle {
                font-size: 16px;
            }

            .feature-grid {
                grid-template-columns: 1fr;
            }

            .stats-container {
                grid-template-columns: repeat(2, 1fr);
            }

            .logo-icon {
                font-size: 80px;
            }

            .stat-number {
                font-size: 36px;
            }
        }

        .wave {
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            opacity: 0.15;
            z-index: 0;
            pointer-events: none;
        }
    </style>
</head>
<body>
    <div class="particles" id="particles"></div>

    <div class="container">
        <div class="logo">
            <span class="logo-icon">⚡</span>
        </div>
        
        <h1>VLESS Quantum Worker</h1>
        
        <p class="subtitle">🚀 سریع‌ترین • 🛡️ امن‌ترین • 🌍 قدرتمندترین</p>
        
        <p class="description">
            پیشرفته‌ترین، امن‌ترین و سریع‌ترین سرویس پروکسی با معماری Cloudflare Edge Computing
            <br>
            <strong>⚡ قدرت گرفته از هوش مصنوعی و تکنولوژی‌های کوانتومی نسل آینده</strong>
        </p>

        <div class="stats-container">
            <div class="stat-box">
                <div class="stat-number">99.99%</div>
                <div class="stat-label">⏱️ آپتایم</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">&lt;2ms</div>
                <div class="stat-label">⚡ تاخیر کوانتومی</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">∞</div>
                <div class="stat-label">🌐 پهنای باند</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">256-bit</div>
                <div class="stat-label">🔐 رمزنگاری</div>
            </div>
        </div>

        <div class="feature-grid">
            <div class="feature-card">
                <span class="feature-icon">⚡</span>
                <div class="feature-title">سرعت کوانتومی</div>
                <div class="feature-desc">
                    استفاده از Cloudflare Edge Network با بیش از 300+ دیتاسنتر در سراسر جهان و مسیریابی هوشمند AI-Powered
                </div>
            </div>

            <div class="feature-card">
                <span class="feature-icon">🛡️</span>
                <div class="feature-title">امنیت چند لایه</div>
                <div class="feature-desc">
                    رمزنگاری AES-256-GCM، TLS 1.3، DPI Bypass، Anti-Fingerprinting و محافظت در برابر حملات DDoS و Man-in-the-Middle
                </div>
            </div>

            <div class="feature-card">
                <span class="feature-icon">🤖</span>
                <div class="feature-title">هوش مصنوعی پیشرفته</div>
                <div class="feature-desc">
                    مسیریابی هوشمند با ML، بهینه‌سازی خودکار ترافیک، تشخیص و بلاک تهدیدات real-time با AI و پیش‌بینی مسیر بهینه
                </div>
            </div>

            <div class="feature-card">
                <span class="feature-icon">🌍</span>
                <div class="feature-title">پوشش جهانی کامل</div>
                <div class="feature-desc">
                    دسترسی به 100+ لوکیشن جهانی، انتخاب خودکار نزدیک‌ترین سرور، Load Balancing هوشمند و Failover اتوماتیک
                </div>
            </div>

            <div class="feature-card">
                <span class="feature-icon">🔄</span>
                <div class="feature-title">مقیاس‌پذیری نامحدود</div>
                <div class="feature-desc">
                    Auto-scaling بر اساس ترافیک، Distributed Load Balancing، توزیع هوشمند ترافیک و پشتیبانی از میلیون‌ها کاربر همزمان
                </div>
            </div>

            <div class="feature-card">
                <span class="feature-icon">📊</span>
                <div class="feature-title">مانیتورینگ پیشرفته</div>
                <div class="feature-desc">
                    داشبورد ادمین real-time، آمار لحظه‌ای ترافیک، لاگ امنیتی کامل، آنالیز رفتار کاربران و گزارش‌های تخصصی
                </div>
            </div>
        </div>

        <div class="tech-stack">
            <h3>🔧 تکنولوژی‌های پیشرفته استفاده شده</h3>
            <div class="tech-tags">
                <span class="tech-tag">⚡ Cloudflare Workers</span>
                <span class="tech-tag">🔌 WebSocket Streams</span>
                <span class="tech-tag">🚀 VLESS Protocol</span>
                <span class="tech-tag">💾 D1 Database</span>
                <span class="tech-tag">🎯 SOCKS5 Proxy</span>
                <span class="tech-tag">🌐 DNS over HTTPS</span>
                <span class="tech-tag">🔐 TLS 1.3</span>
                <span class="tech-tag">🤖 Scamalytics API</span>
                <span class="tech-tag">⏱️ Rate Limiting</span>
                <span class="tech-tag">🚫 IP Blacklisting</span>
                <span class="tech-tag">📊 Traffic Analytics</span>
                <span class="tech-tag">💚 Health Monitoring</span>
                <span class="tech-tag">🧹 Auto Cleanup</span>
                <span class="tech-tag">🔑 2FA/TOTP</span>
                <span class="tech-tag">🎨 Adaptive Routing</span>
                <span class="tech-tag">🔄 Auto Failover</span>
                <span class="tech-tag">📈 Performance Metrics</span>
                <span class="tech-tag">🛡️ Security Hardening</span>
                <span class="tech-tag">⚙️ Zero-Config Setup</span>
                <span class="tech-tag">🌈 Multi-Protocol</span>
            </div>
        </div>

        <div class="center-text">
            <div class="status">⚡ سرویس آنلاین و آماده به خدمت</div>
        </div>
    </div>

    <svg class="wave" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320">
        <path fill="#667eea" fill-opacity="1" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,112C672,96,768,96,864,112C960,128,1056,160,1152,160C1248,160,1344,128,1392,112L1440,96L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path>
    </svg>

    <script nonce="${nonce}">
        const particlesContainer = document.getElementById('particles');
        const particleCount = 15;
        
        for (let i = 0; i < particleCount; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            
            const size = Math.random() * 8 + 4;
            const left = Math.random() * 100;
            const delay = Math.random() * 20;
            const duration = Math.random() * 10 + 15;
            
            particle.style.width = size + 'px';
            particle.style.height = size + 'px';
            particle.style.left = left + '%';
            particle.style.animationDelay = delay + 's';
            particle.style.animationDuration = duration + 's';
            particle.style.animation = 'particleFloat ' + duration + 's linear infinite';
            particle.style.animationDelay = delay + 's';
            
            particlesContainer.appendChild(particle);
        }
    </script>
</body>
</html>`;
}
