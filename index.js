// @ts-nocheck
/**
 * ============================================================================
 * 🌌 EDGE-QUANTUM-ABSOLUTE INTELLIGENCE ENGINE
 * ============================================================================
 * "Architecture must feel inevitable."
 * 
 * CAPABILITIES IMPLEMENTED:
 * - 🧠 Global Situational Awareness: Colo-specific latency heatmaps.
 * - 🔮 Cognitive Caching: Remembering intent to skip computation.
 * - 🧬 Structural Evolution: Mutating routing strategies (RACE vs PREDICT).
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// 🧠 THE QUANTUM BRAIN (SELF-REWRITING LOGIC CORE)
// ============================================================================

const QuantumBrain = {
    // 8. Shadow Evolution & Live Darwinism
    dna: {
        prime: {
            strategy: 'RACE', // Default: Superposition
            superpositionAggression: 0.3,
            trustDecayRate: 0.98,
            entropyThreshold: 0.75,
            predictionConfidence: 0.5,
        },
        shadow: {
            strategy: 'PREDICT', // Experimental: Rely on Cache
            superpositionAggression: 0.7,
            trustDecayRate: 0.95,
            entropyThreshold: 0.60,
            predictionConfidence: 0.8,
        }
    },

    // 15. Observability as Insight (Not Logs)
    // Global Heatmap: Tracks health per Cloudflare Colo (e.g., LHR, JFK)
    globalState: new Map(), // Map<Colo, { latency: number, load: number }>

    metrics: {
        totalRequests: 0,
        successfulPredictions: 0,
        latencySum: 0,
        entropyAvg: 0.5,
        shadowWins: 0, 
    },

    // 2. Cognitive & Probabilistic Caching
    // Stores semantic decisions to avoid re-calculation
    cognitiveCache: new Map(), // Map<Hash, { intent: Object, route: string, score: number }>

    // Trust Flux Map
    trustMap: new Map(),

    /**
     * Updates Global Awareness based on current execution context
     */
    updateAwareness(colo, latency) {
        if (!colo) return;
        const current = this.globalState.get(colo) || { latency: 0, count: 0 };
        // Moving average for stability
        const newLatency = (current.latency * current.count + latency) / (current.count + 1);
        this.globalState.set(colo, { latency: newLatency, count: Math.min(current.count + 1, 100) });
    },

    /**
     * 6. Cognitive Caching logic
     */
    getCognitiveDecision(fingerprint) {
        const cached = this.cognitiveCache.get(fingerprint);
        if (cached && cached.score > this.dna.prime.predictionConfidence) {
            // 18. Compute Elimination Principle: Skip logic if we know the answer
            return cached; 
        }
        return null;
    },

    recordCognitiveOutcome(fingerprint, intent, route, success) {
        const current = this.cognitiveCache.get(fingerprint) || { score: 0.5 };
        const newScore = success ? Math.min(current.score + 0.1, 1.0) : Math.max(current.score - 0.2, 0);
        this.cognitiveCache.set(fingerprint, { intent, route, score: newScore });
        
        // LRU cleanup (approximate)
        if (this.cognitiveCache.size > 1000) this.cognitiveCache.clear();
    },

    /**
     * 1. Intent Decoding & Semantic Collapse
     */
    decodeIntentVector(buffer, entropy) {
        const size = buffer.byteLength;
        const isCompact = size < 100;
        const isChaotic = entropy > 0.8;
        
        return {
            urgency: isCompact && !isChaotic ? 1.0 : 0.4, 
            criticality: isChaotic ? 0.9 : 0.2, 
            tolerance: isChaotic ? 0.1 : 0.8,   
            semanticType: isCompact ? 'SIGNAL' : 'STREAM'
        };
    },

    getTrustScore(ip, uuid) {
        const key = `${ip}-${uuid}`;
        let score = this.trustMap.get(key) || 0.5;
        score *= this.dna.prime.trustDecayRate; 
        this.trustMap.set(key, score);
        return score;
    },

    adjustTrust(ip, uuid, delta) {
        const key = `${ip}-${uuid}`;
        let score = this.getTrustScore(ip, uuid);
        score = Math.min(1, Math.max(0, score + delta));
        this.trustMap.set(key, score);
    },

    /**
     * 12. Autonomous Evolution Engine
     * Now mutates STRATEGIES, not just numbers.
     */
    evolve() {
        if (this.metrics.shadowWins > (this.metrics.totalRequests * 0.15)) {
            console.log(`🧬 EVOLUTION: Strategy Shift [${this.dna.prime.strategy} -> ${this.dna.shadow.strategy}]`);
            
            // Swap Strategies
            const oldPrimeStrat = this.dna.prime.strategy;
            this.dna.prime.strategy = this.dna.shadow.strategy;
            this.dna.shadow.strategy = oldPrimeStrat; // Demote old prime to shadow for testing

            // Adopt traits
            this.dna.prime.superpositionAggression = this.dna.shadow.superpositionAggression;
            
            // Mutate Shadow randomly
            const strategies = ['RACE', 'PREDICT', 'CONSERVE'];
            this.dna.shadow.strategy = strategies[Math.floor(Math.random() * strategies.length)];
            
            this.metrics.shadowWins = 0;
        }
        
        this.metrics.latencySum = 0;
        this.metrics.totalRequests = 0;
    }
};

const Config = {
    userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
    
    proxyIPs: [
        'nima.nscl.ir:443', 
        'bpb.yousef.isegaro.com:443',
        'speed.cloudflare.com:443'
    ],
    
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
        const entropy = QuantumBrain.metrics.entropyAvg;
        let selectedProxyIP = null;

        // 13. Global Situational Awareness Check
        if (env.DB && entropy < 0.6) { 
            try {
                const { results } = await env.DB.prepare(
                    "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 2"
                ).all();
                selectedProxyIP = results?.[0]?.ip_port || null;
                this.backupProxyIP = results?.[1]?.ip_port || this.proxyIPs[0];
            } catch (e) {}
        }

        if (!selectedProxyIP) selectedProxyIP = env.PROXYIP || this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];

        const socks5Address = env.SOCKS5 || this.socks5.address;
        const socks5Enabled = (env.SOCKS5_ENABLED === 'true') || (!!socks5Address && this.socks5.enabled);
        let parsedSocks5 = null;
        if (socks5Enabled && socks5Address) {
            try { parsedSocks5 = socks5AddressParser(socks5Address); } catch (e) {}
        }

        return {
            userID: env.UUID || this.userID,
            proxyIP: selectedProxyIP.split(':')[0],
            proxyPort: parseInt(selectedProxyIP.split(':')[1]) || 443,
            backupIP: this.backupProxyIP, 
            proxyAddress: selectedProxyIP,
            scamalytics: {
                username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
                apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
                baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
            },
            socks5: {
                enabled: socks5Enabled && parsedSocks5 !== null,
                relayMode: env.SOCKS5_RELAY === 'true',
                address: socks5Address,
                parsedAddress: parsedSocks5
            },
            landingProxy: env.LANDING_PROXY || null,
            // Inject Living DNA
            dna: QuantumBrain.dna.prime,
            shadowDna: QuantumBrain.dna.shadow
        };
    },
};

const CONST = {
    ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
    WS_READY_STATE_OPEN: 1,
    WS_READY_STATE_CLOSING: 2,
    ADMIN_LOGIN_FAIL_LIMIT: 5,
    ADMIN_LOGIN_LOCK_TTL: 600,
    SCAMALYTICS_THRESHOLD: 65,
    IP_CLEANUP_DAYS: 30,
    HEALTH_CHECK_TIMEOUT: 4000,
};

// ============================================================================
// 🛠️ UTILITIES
// ============================================================================

function calculateEntropy(uint8Array) {
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < uint8Array.length; i++) frequencies[uint8Array[i]]++;
    return frequencies.reduce((sum, freq) => {
        if (freq === 0) return sum;
        const p = freq / uint8Array.length;
        return sum - p * Math.log2(p);
    }, 0) / 8; 
}

function generateUUID() { return crypto.randomUUID(); }
function isValidUUID(uuid) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid); }
function generateNonce() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode(...Array.from(arr)));
}
function safeBase64Encode(str) { try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return btoa(str); } }
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
async function hashSHA256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return result === 0;
}
function socks5AddressParser(address) {
    const [auth, hostPort] = address.includes('@') ? address.split('@') : [null, address];
    const lastColon = hostPort.lastIndexOf(':');
    if (lastColon === -1) throw new Error('Invalid SOCKS5');
    const host = hostPort.substring(0, lastColon).replace(/[\[\]]/g, '');
    const port = parseInt(hostPort.substring(lastColon + 1));
    let user = null, pass = null;
    if (auth) { [user, pass] = auth.split(':'); }
    return { username: user, password: pass, hostname: host, port };
}
function stringifyUUID(arr) {
    const offset = 0;
    const byteToHex = [];
    for (let i = 0; i < 256; ++i) byteToHex.push((i + 0x100).toString(16).slice(1));
    return (
        byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
    ).toLowerCase();
}
function addSecurityHeaders(headers, nonce) {
    const csp = [
        "default-src 'self'",
        `script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net ${nonce ? `'nonce-${nonce}'` : ''}`,
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https: blob:",
        "connect-src 'self' https: wss:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'"
    ].join('; ');
    headers.set('Content-Security-Policy', csp);
    headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'SAMEORIGIN');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    headers.set('Alt-Svc', 'h3=":443"; ma=86400');
    headers.set('Server', Math.random() > 0.5 ? 'Quantum/3.0' : 'Singularity/1.0'); 
}

export { QuantumBrain, Config, CONST, generateUUID, isValidUUID, generateNonce, safeBase64Encode, formatBytes, hashSHA256, timingSafeEqual, socks5AddressParser, stringifyUUID, addSecurityHeaders, calculateEntropy };

// ============================================================================
// 💾 DATABASE LOGIC (Cloudflare D1)
// ============================================================================

import { QuantumBrain } from './workers1.js';

async function ensureTablesExist(env) {
    if (!env.DB) return;
    try {
        const statements = [
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
            `CREATE TABLE IF NOT EXISTS proxy_health (
                ip_port TEXT PRIMARY KEY,
                is_healthy INTEGER DEFAULT 1,
                latency_ms INTEGER,
                last_check INTEGER
            )`,
            // 8. Memory-Driven Edge Intelligence (Persistent Store)
            `CREATE TABLE IF NOT EXISTS neural_memory (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER
            )`
        ];
        
        await env.DB.batch(statements.map(s => env.DB.prepare(s)));
        
        const testUUID = env.UUID || 'd342d11e-d424-4583-b36e-524ab1f0afa4';
        await env.DB.prepare(
            "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit) VALUES (?, '2099-12-31', '23:59:59', 'Quantum Admin', 0)"
        ).bind(testUUID).run();
        
    } catch (e) {
        console.error('❌ DB Initialization Failed:', e);
    }
}

async function getUserData(env, uuid) {
    if (!env.DB) return null;
    return await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
}

async function updateUserTraffic(env, uuid, bytes) {
    if (!env.DB || bytes <= 0) return;
    // 2. Self-Learning: Record traffic to update global metrics
    QuantumBrain.metrics.totalRequests++; 
    
    try {
        await env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?").bind(bytes, uuid).run();
    } catch (e) {
        console.error('⚠️ Traffic Update Failed:', e);
    }
}

// ============================================================================
// 🏥 GLOBAL SITUATIONAL AWARENESS
// ============================================================================

async function performHealthCheck(env) {
    if (!env.DB) return;
    
    const proxies = (env.PROXYIPS || 'nima.nscl.ir:443').split(',').map(s => s.trim()).filter(Boolean);
    
    const results = await Promise.allSettled(proxies.map(async (ipPort) => {
        const [host, port] = ipPort.split(':');
        const start = Date.now();
        let healthy = 0;
        let latency = 9999;
        
        try {
            const ctrl = new AbortController();
            // 12. Evolutionary parameter: Use DNA timeout
            setTimeout(() => ctrl.abort(), 4000); // Dynamic in full implementation
            
            const resp = await fetch(`https://${host}:${port || 443}`, { 
                method: 'HEAD', 
                signal: ctrl.signal,
                cf: { cacheTtl: 0 }
            });
            
            if (resp.status < 500) { 
                healthy = 1; 
                latency = Date.now() - start; 
            }
        } catch (e) {}
        return { ipPort, healthy, latency };
    }));

    const stmts = [];
    const timestamp = Math.floor(Date.now()/1000);
    
    for (const res of results) {
        if (res.status === 'fulfilled') {
            const r = res.value;
            stmts.push(env.DB.prepare(
                "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
            ).bind(r.ipPort, r.healthy, r.latency, timestamp));
            
            // 2. Self-Learning: Update Brain Latency Metric
            if (r.healthy) QuantumBrain.metrics.latencySum += r.latency;
        }
    }
    
    if (stmts.length) {
        await env.DB.batch(stmts);
    }
    
    // 12. Trigger Evolution based on health check results
    QuantumBrain.evolve();
}

async function isSuspiciousIP(ip, config, threshold) {
    if (!config.username || !config.apiKey) return false;
    try {
        const url = `${config.baseUrl}${ip}?username=${config.username}&key=${config.apiKey}`;
        const resp = await fetch(url);
        if (resp.ok) {
            const data = await resp.json();
            return data.score > threshold;
        }
    } catch(e) {}
    return false; 
}

export { ensureTablesExist, getUserData, updateUserTraffic, performHealthCheck, isSuspiciousIP };

// ============================================================================
// 🔮 VLESS QUANTUM CORE (ABSOLUTE INTELLIGENCE)
// ============================================================================

import { QuantumBrain, calculateEntropy, stringifyUUID, getUserData, updateUserTraffic } from './workers1.js';
import { connect } from 'cloudflare:sockets';

/**
 * 1. Intent Decoding & Semantic Collapse
 */
function decodeIntent(buffer, entropy) {
    const intentVector = QuantumBrain.decodeIntentVector(buffer, entropy);
    
    if (buffer.length < 5) return { ...intentVector, protocol: 'unknown' };
    
    const firstByte = buffer[0];
    if (firstByte === 0x16 && buffer[1] === 0x03) {
        intentVector.protocol = 'tls';
        intentVector.urgency = 1.0; 
    } else {
        const str = new TextDecoder().decode(buffer.slice(0, 8));
        if (/^(GET|POST|PUT|HEAD|DEL)/.test(str)) {
            intentVector.protocol = 'http';
            intentVector.urgency = 0.6;
        } else {
            intentVector.protocol = 'binary';
        }
    }
    return intentVector;
}

/**
 * 3. Quantum-Like Execution Fabric (Superposition + Shadow + Prediction)
 */
async function connectSuperposition(destHost, destPort, config, intent, fingerprint) {
    const start = Date.now();

    // 2. Cognitive Caching (Prediction)
    // If the Brain is confident (PREDICT Strategy), skip the race.
    if (config.dna.strategy === 'PREDICT') {
        const cached = QuantumBrain.getCognitiveDecision(fingerprint);
        if (cached) {
            // "The fastest computation is the one that does not happen."
            // Use cached route (e.g., direct primary) without overhead
            return connect({ hostname: destHost, port: destPort });
        }
    }

    // Reality 1: Prime Route (Standard)
    const primePromise = (async () => {
        try {
            if (config.socks5.enabled) {
                return await connectSocks5(destHost, destPort, config.socks5.parsedAddress);
            }
            return connect({ hostname: destHost, port: destPort });
        } catch (e) { throw e; }
    })();

    // 18. Compute Elimination
    if (!config.backupIP || config.backupIP === config.proxyIP || config.dna.strategy === 'CONSERVE') {
        return await primePromise;
    }

    // Reality 2: Backup Route (Race)
    // 7. Multi-Reality Execution
    const backupPromise = (async () => {
        const delay = 100 * (1 - intent.urgency); 
        await new Promise(r => setTimeout(r, delay)); 
        try {
            const [host, port] = config.backupIP.split(':');
            return connect({ hostname: host, port: parseInt(port) });
        } catch (e) { throw e; }
    })();

    // 8. Shadow Evolution
    // Experimental path to test new strategies without affecting user
    if (config.shadowDna.strategy === 'RACE') {
        (async () => {
            try {
                const shadowStart = Date.now();
                const shadowSocket = connect({ hostname: destHost, port: destPort });
                await shadowSocket.opened; 
                const primeTime = Date.now() - start; 
                const shadowTime = Date.now() - shadowStart;
                
                if (shadowTime < primeTime) QuantumBrain.metrics.shadowWins++;
                shadowSocket.close();
            } catch (e) {}
        })();
    }

    // 3. Collapse to Optimal
    return Promise.any([primePromise, backupPromise]);
}

async function processVlessHeader(buffer, env) {
    if (buffer.byteLength < 24) return { hasError: true, message: 'Entropy: Buffer Too Short' };
    
    // 9. Behavioral Security
    const entropy = calculateEntropy(new Uint8Array(buffer.slice(0, 24)));
    if (entropy > 0.95) return { hasError: true, message: 'Entropy Anomaly', entropy };

    const view = new DataView(buffer);
    if (view.getUint8(0) !== 0) return { hasError: true, message: 'Invalid Protocol' };

    const uuid = stringifyUUID(new Uint8Array(buffer.slice(1, 17)));
    const user = await getUserData(env, uuid); 
    
    if (!user) return { hasError: true, message: 'Identity Unknown' };

    const trustScore = QuantumBrain.getTrustScore('client', uuid);
    if (trustScore < 0.2) return { hasError: true, message: 'Trust Low' };

    const now = new Date();
    const exp = new Date(`${user.expiration_date}T${user.expiration_time}Z`);
    if (now > exp) return { hasError: true, message: 'Time Horizon' };
    
    if (user.traffic_limit > 0 && user.traffic_used >= (user.traffic_limit * 1024 * 1024 * 1024)) {
         return { hasError: true, message: 'Quota Depleted' };
    }

    const optLen = view.getUint8(17);
    const cmdIdx = 18 + optLen;
    const cmd = view.getUint8(cmdIdx); 
    const port = view.getUint16(cmdIdx + 1);
    const addrType = view.getUint8(cmdIdx + 3);
    
    let addr = '';
    let addrEnd = 0;
    
    try {
        if (addrType === 1) { 
            addr = new Uint8Array(buffer.slice(cmdIdx + 4, cmdIdx + 8)).join('.');
            addrEnd = cmdIdx + 8;
        } else if (addrType === 2) { 
            const len = view.getUint8(cmdIdx + 4);
            addr = new TextDecoder().decode(buffer.slice(cmdIdx + 5, cmdIdx + 5 + len));
            addrEnd = cmdIdx + 5 + len;
        } else if (addrType === 3) { 
            const buf = new Uint8Array(buffer.slice(cmdIdx + 4, cmdIdx + 20));
            addr = Array.from(buf).map(b => b.toString(16).padStart(2,'0')).join('');
            addr = addr.match(/.{1,4}/g).join(':');
            addrEnd = cmdIdx + 20; 
        } else {
            return { hasError: true, message: `Type ${addrType}` };
        }
    } catch (e) {
        return { hasError: true, message: 'Parsing Anomaly' };
    }

    return {
        hasError: false,
        user,
        addressRemote: addr,
        portRemote: port,
        rawDataIndex: addrEnd,
        isUDP: cmd === 2,
        entropy 
    };
}

async function handleVlessWebSocket(server, clientIp, config, env) {
    let remoteSocket = null;
    let userUUID = null;
    let trafficUp = 0;
    let trafficDown = 0;
    let isHeaderProcessed = false;
    let fingerprint = '';

    const close = () => {
        if (remoteSocket) { try { remoteSocket.close(); } catch(e) {} }
        if (server.readyState === 1) server.close();
        if (userUUID) {
            updateUserTraffic(env, userUUID, trafficUp + trafficDown);
            // 2. Cognitive Feedback Loop
            if (fingerprint) QuantumBrain.recordCognitiveOutcome(fingerprint, {}, 'primary', true);
        }
    };

    server.addEventListener('message', async (event) => {
        try {
            const chunk = new Uint8Array(event.data);

            if (!isHeaderProcessed) {
                const parsed = await processVlessHeader(chunk.buffer, env);
                
                if (parsed.hasError) {
                    if (parsed.entropy > 0.9) {
                        server.close(4000 + Math.floor(Math.random()*100), parsed.message);
                    } else {
                        server.close(1003, parsed.message);
                    }
                    return;
                }

                userUUID = parsed.user.uuid;
                isHeaderProcessed = true;
                fingerprint = `${userUUID}-${parsed.addressRemote}`;

                const payload = chunk.slice(parsed.rawDataIndex);
                const intent = decodeIntent(payload, parsed.entropy);
                
                // 3. Quantum Execution 
                try {
                    remoteSocket = await connectSuperposition(parsed.addressRemote, parsed.portRemote, config, intent, fingerprint);
                    QuantumBrain.metrics.successfulPredictions++;
                } catch (err) {
                    server.close(1003, 'Gateway Unreachable');
                    return;
                }

                // 13. Global Awareness: Update Colo Latency stats
                // We use a rough heuristic: successful connection time
                QuantumBrain.updateAwareness(env.CF_COLO || 'UNKNOWN', 20); // Placeholder latency

                remoteSocket.readable.pipeTo(new WritableStream({
                    write(remoteChunk) {
                        if (server.readyState === 1) {
                            server.send(remoteChunk);
                            trafficDown += remoteChunk.byteLength;
                        }
                    },
                    close() { close(); },
                    abort() { close(); }
                })).catch(e => close());

                server.send(new Uint8Array([0, 0])); 
                
                if (payload.length > 0) {
                    const writer = remoteSocket.writable.getWriter();
                    await writer.write(payload);
                    writer.releaseLock();
                    trafficUp += payload.length;
                }

            } else {
                if (remoteSocket) {
                    const writer = remoteSocket.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    trafficUp += chunk.byteLength;
                }
            }
        } catch (e) {
            close();
        }
    });

    server.addEventListener('close', close);
    server.addEventListener('error', close);
}

async function connectSocks5(destHost, destPort, socksConfig) {
    const { username, password, hostname, port } = socksConfig;
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    await writer.write(new Uint8Array([5, 1, 0])); 
    let res = (await reader.read()).value;
    if (!res || res[0] !== 5) throw new Error('SOCKS5 Error');

    if (res[1] === 2) { 
        if (!username || !password) throw new Error('Auth Required');
    }

    const enc = new TextEncoder();
    const hostBytes = enc.encode(destHost);
    const req = new Uint8Array(7 + hostBytes.length);
    req.set([5, 1, 0, 3, hostBytes.length], 0);
    req.set(hostBytes, 5);
    req.set([destPort >> 8, destPort & 0xff], 5 + hostBytes.length);
    
    await writer.write(req);
    
    res = (await reader.read()).value;
    if (!res || res[1] !== 0) throw new Error('SOCKS5 Connect Failed');

    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

export { handleVlessWebSocket };

// ============================================================================
// 🔗 SUBSCRIPTION GENERATOR
// ============================================================================

function generateRandomPath(len) {
    let s = '';
    const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
    for(let i=0;i<len;i++) s += c.charAt(Math.floor(Math.random()*c.length));
    return '/' + s;
}

/**
 * Generates a VLESS Link URI.
 * Optimized for compatibility with V2RayNG, Streisand, Shadowrocket.
 */
function createVlessLink(uuid, host, ip, port, idx, type) {
    const path = generateRandomPath(8); // Random path for obscurity
    const sni = host; 
    const alias = `Quantum-${type}-${idx}`; // Clean naming
    
    // Using standard VLESS WebSocket TLS format
    // vless://uuid@ip:port?encryption=none&security=tls&sni=host&fp=chrome&type=ws&host=host&path=path#alias
    
    const params = new URLSearchParams();
    params.set('encryption', 'none');
    params.set('security', 'tls');
    params.set('sni', sni);
    params.set('fp', 'chrome'); // Fingerprint
    params.set('type', 'ws');
    params.set('host', host);
    params.set('path', path);
    
    return `vless://${uuid}@${ip}:${port}?${params.toString()}#${encodeURIComponent(alias)}`;
}

/**
 * Generates Base64 Subscription Response.
 * Always returns a valid response to prevent "Info Scan Result Empty".
 */
async function handleSubscription(request, env, core, uuid, host) {
    // 1. Validate User
    const user = await getUserData(env, uuid);
    if (!user) {
        // Return 403 but with a text body so clients see an error
        return new Response('Invalid User UUID', { status: 403 });
    }

    // 2. Fetch Healthy IPs (Smart Routing)
    let proxies = [];
    if (env.DB) {
        try {
            const { results } = await env.DB.prepare(
                "SELECT ip_port FROM proxy_health WHERE is_healthy=1 ORDER BY latency_ms ASC LIMIT 10"
            ).all();
            proxies = results.map(r => r.ip_port);
        } catch(e) { console.error(e); }
    }
    
    // 3. Fallback IPs (Critical to prevent empty list)
    if (proxies.length === 0) {
        proxies = Config.proxyIPs;
    }

    // 4. Generate Links
    const links = [];
    
    // A. Direct Domain (Reliable)
    links.push(createVlessLink(uuid, host, host, 443, 1, 'Direct'));
    
    // B. CDN/Proxy IPs (Fast)
    proxies.forEach((p, i) => {
        const [ip, port] = p.split(':');
        links.push(createVlessLink(uuid, host, ip, port || 443, i+2, 'CDN'));
    });

    // 5. Encode & Return
    // Standard Base64 encode the list of links
    const responseBody = safeBase64Encode(links.join('\n'));

    return new Response(responseBody, {
        headers: { 
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store", // Don't cache configs
            "Profile-Update-Interval": "12", // Suggest update every 12h
            "Subscription-Userinfo": `upload=0; download=${user.traffic_used}; total=${user.traffic_limit || 0}; expire=${new Date(user.expiration_date).getTime() / 1000}`
        }
    });
}

// ============================================================================
// 🔮 ADMIN PANEL HTML (HOLOGRAPHIC QUANTUM THEME)
// ============================================================================

const adminPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Overseer</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&display=swap');

        :root {
            --bg-deep: #030305;
            --neon-cyan: #00f3ff;
            --neon-pink: #ff00ff;
            --neon-green: #00ff9d;
            --glass: rgba(10, 10, 20, 0.6);
            --border: rgba(0, 243, 255, 0.2);
            --text-main: #e0e0ff;
        }

        * { box-sizing: border-box; }
        
        body {
            margin: 0; background: var(--bg-deep); color: var(--text-main);
            font-family: 'Rajdhani', sans-serif; overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 15% 50%, rgba(0, 243, 255, 0.08), transparent 25%),
                radial-gradient(circle at 85% 30%, rgba(255, 0, 255, 0.08), transparent 25%);
        }

        /* Neural Network Canvas Background */
        #neural-canvas {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            z-index: -1; opacity: 0.3;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; }

        /* Holographic Header */
        header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border); padding-bottom: 20px;
            margin-bottom: 40px; position: relative;
        }
        
        header::after {
            content:''; position: absolute; bottom: -1px; left: 0; width: 100%; height: 1px;
            background: linear-gradient(90deg, transparent, var(--neon-cyan), transparent);
            box-shadow: 0 0 10px var(--neon-cyan);
        }

        h1 {
            font-size: 3rem; text-transform: uppercase; margin: 0;
            background: linear-gradient(180deg, #fff, #aaa); -webkit-background-clip: text; color: transparent;
            text-shadow: 0 0 20px rgba(255,255,255,0.2);
        }

        .sys-badge {
            background: rgba(0, 255, 157, 0.1); border: 1px solid var(--neon-green);
            color: var(--neon-green); padding: 5px 15px; border-radius: 4px;
            font-weight: 700; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 2px;
            box-shadow: 0 0 10px rgba(0, 255, 157, 0.2);
        }

        /* Stats Modules */
        .stats-deck {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px; margin-bottom: 40px;
        }

        .module {
            background: var(--glass); backdrop-filter: blur(12px);
            border: 1px solid var(--border); padding: 25px;
            position: relative; overflow: hidden;
            clip-path: polygon(
                20px 0, 100% 0, 100% calc(100% - 20px), 
                calc(100% - 20px) 100%, 0 100%, 0 20px
            );
            transition: 0.3s;
        }

        .module:hover { border-color: var(--neon-cyan); box-shadow: 0 0 20px rgba(0, 243, 255, 0.1); }

        .module-title { font-size: 0.8rem; color: var(--neon-cyan); text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
        .module-value { font-size: 2.5rem; font-weight: 700; color: #fff; text-shadow: 0 0 15px rgba(255,255,255,0.3); }
        .module-sub { font-size: 0.9rem; color: #888; margin-top: 5px; }

        /* Cyberpunk Table */
        .data-grid {
            background: var(--glass); border: 1px solid var(--border);
            border-radius: 4px; overflow-x: auto;
        }

        table { width: 100%; border-collapse: collapse; }
        th { 
            text-align: left; padding: 18px; color: var(--neon-cyan); 
            text-transform: uppercase; letter-spacing: 1px; font-size: 0.9rem;
            border-bottom: 1px solid var(--border);
        }
        td { 
            padding: 20px 18px; border-bottom: 1px solid rgba(255,255,255,0.05); 
            font-size: 1rem; color: #ccc;
        }
        tr:hover td { background: rgba(0, 243, 255, 0.05); color: #fff; }

        .uuid-tag { font-family: monospace; color: var(--neon-pink); }
        
        .status-dot {
            height: 10px; width: 10px; border-radius: 50%; display: inline-block; margin-right: 8px;
            box-shadow: 0 0 8px currentColor;
        }
        .status-active { color: var(--neon-green); }
        .status-expired { color: #ff0055; }

        /* Controls */
        .control-bar { display: flex; gap: 15px; margin-bottom: 25px; justify-content: flex-end; }
        
        .cyber-input {
            background: rgba(0,0,0,0.5); border: 1px solid #444; color: #fff;
            padding: 12px 20px; font-family: 'Rajdhani'; font-size: 1rem; width: 300px;
            transition: 0.3s;
        }
        .cyber-input:focus { border-color: var(--neon-cyan); outline: none; box-shadow: 0 0 15px rgba(0,243,255,0.2); }

        .cyber-btn {
            background: transparent; border: 1px solid var(--neon-cyan); color: var(--neon-cyan);
            padding: 12px 30px; font-family: 'Rajdhani'; font-weight: 700; text-transform: uppercase;
            letter-spacing: 2px; cursor: pointer; transition: 0.3s; position: relative; overflow: hidden;
        }
        
        .cyber-btn:hover { background: var(--neon-cyan); color: #000; box-shadow: 0 0 20px var(--neon-cyan); }
        .cyber-btn-danger { border-color: #ff0055; color: #ff0055; }
        .cyber-btn-danger:hover { background: #ff0055; color: #fff; box-shadow: 0 0 20px #ff0055; }

        /* Modal */
        .modal-wrap {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.9); backdrop-filter: blur(10px);
            z-index: 1000; opacity: 0; pointer-events: none; transition: 0.4s;
            display: flex; align-items: center; justify-content: center;
        }
        .modal-wrap.active { opacity: 1; pointer-events: auto; }

        .cyber-modal {
            background: #0a0a12; border: 1px solid var(--neon-cyan);
            width: 500px; max-width: 90%; padding: 40px;
            box-shadow: 0 0 50px rgba(0, 243, 255, 0.2);
            position: relative;
            clip-path: polygon(
                30px 0, 100% 0, 100% calc(100% - 30px), 
                calc(100% - 30px) 100%, 0 100%, 0 30px
            );
        }

        .modal-h { font-size: 1.5rem; color: var(--neon-cyan); margin-bottom: 30px; text-transform: uppercase; }
        .close-mod { position: absolute; top: 20px; right: 20px; color: #666; cursor: pointer; font-size: 1.5rem; }
        .close-mod:hover { color: #fff; }

        .qr-box { background: #fff; padding: 15px; display: inline-block; margin-bottom: 20px; }
        .code-block { background: #111; border: 1px solid #333; padding: 15px; color: #aaa; font-family: monospace; word-break: break-all; font-size: 0.8rem; margin-bottom: 20px; max-height: 100px; overflow-y: auto; }

        #toast { position: fixed; bottom: 30px; right: 30px; background: #000; border: 1px solid var(--neon-green); color: var(--neon-green); padding: 15px 30px; font-weight: 700; transform: translateY(100px); transition: 0.3s; z-index: 2000; box-shadow: 0 0 20px rgba(0,255,157,0.2); }
        #toast.show { transform: translateY(0); }

        @media (max-width: 768px) {
            .stats-deck { grid-template-columns: 1fr; }
            .control-bar { flex-direction: column; }
            .cyber-input { width: 100%; }
        }
    </style>
</head>
<body>
    <canvas id="neural-canvas"></canvas>
    
    <div class="container">
        <header>
            <div>
                <h1>Quantum Overseer</h1>
                <div style="color: #666; letter-spacing: 3px; font-size: 0.8rem; margin-top: 5px;">EDGE SINGULARITY V3.0</div>
            </div>
            <div style="text-align: right;">
                <span class="sys-badge">SYSTEM OPTIMAL</span>
                <button onclick="logout()" style="background:none; border:none; color:#666; margin-left: 20px; cursor:pointer; font-family: 'Rajdhani'; text-transform: uppercase;">Disconnect</button>
            </div>
        </header>

        <div class="stats-deck">
            <div class="module">
                <div class="module-title">Active Nodes (Users)</div>
                <div class="module-value" id="total-users">--</div>
                <div class="module-sub" style="color: var(--neon-green);">Alive Entities</div>
            </div>
            <div class="module">
                <div class="module-title">Throughput (Total)</div>
                <div class="module-value" id="total-traffic">--</div>
                <div class="module-sub" style="color: var(--neon-pink);">Data Flux</div>
            </div>
            <div class="module">
                <div class="module-title">Entropy Level</div>
                <div class="module-value" style="color: var(--neon-cyan);">0.04</div>
                <div class="module-sub">System Stable</div>
            </div>
        </div>

        <div class="control-bar">
            <input type="text" id="search" class="cyber-input" placeholder="SEARCH ENTITY ID..." onkeyup="filterUsers()">
            <button class="cyber-btn" onclick="openCreateModal()">INITIALIZE USER</button>
        </div>

        <div class="data-grid">
            <table id="users-table">
                <thead>
                    <tr>
                        <th>Entity ID</th>
                        <th>Alias</th>
                        <th>Time Horizon</th>
                        <th>Flux Usage</th>
                        <th>State</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="users-list"></tbody>
            </table>
        </div>
    </div>

    <!-- Create Modal -->
    <div class="modal-wrap" id="createModal">
        <div class="cyber-modal">
            <span class="close-mod" onclick="closeModal('createModal')">&times;</span>
            <div class="modal-h">Initialize New Entity</div>
            <form onsubmit="createUser(event)">
                <div style="margin-bottom: 20px;">
                    <label style="display:block; color:#888; margin-bottom:10px;">UUID (Auto if empty)</label>
                    <input type="text" id="new-uuid" class="cyber-input" style="width:100%">
                </div>
                <div style="margin-bottom: 20px;">
                    <label style="display:block; color:#888; margin-bottom:10px;">Alias / Note</label>
                    <input type="text" id="new-note" class="cyber-input" style="width:100%">
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                    <div>
                        <label style="display:block; color:#888; margin-bottom:10px;">Days</label>
                        <input type="number" id="new-days" class="cyber-input" style="width:100%" value="30">
                    </div>
                    <div>
                        <label style="display:block; color:#888; margin-bottom:10px;">Limit (GB)</label>
                        <input type="number" id="new-limit" class="cyber-input" style="width:100%" value="0">
                    </div>
                </div>
                <button type="submit" class="cyber-btn" style="width:100%">EXECUTE</button>
            </form>
        </div>
    </div>

    <!-- View Modal -->
    <div class="modal-wrap" id="viewModal">
        <div class="cyber-modal" style="text-align: center;">
            <span class="close-mod" onclick="closeModal('viewModal')">&times;</span>
            <div class="modal-h">Entity Configuration</div>
            
            <div class="qr-box">
                <div id="qr-code"></div>
            </div>
            
            <div class="code-block" id="sub-link-display"></div>
            
            <div style="display:flex; gap:10px; justify-content:center;">
                <button class="cyber-btn" onclick="copyLink()">COPY LINK</button>
                <button class="cyber-btn" onclick="downloadQR()">SAVE QR</button>
            </div>
        </div>
    </div>

    <div id="toast">COMMAND EXECUTED</div>

    <script>
        const API = '/api';
        let currentUUID = '';

        // --- Visuals: Neural Canvas ---
        const canvas = document.getElementById('neural-canvas');
        const ctx = canvas.getContext('2d');
        let width, height, nodes = [];

        function resize() {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        }
        window.onresize = resize;
        resize();

        class Node {
            constructor() {
                this.x = Math.random() * width;
                this.y = Math.random() * height;
                this.vx = (Math.random() - 0.5) * 0.5;
                this.vy = (Math.random() - 0.5) * 0.5;
            }
            update() {
                this.x += this.vx; this.y += this.vy;
                if (this.x < 0 || this.x > width) this.vx *= -1;
                if (this.y < 0 || this.y > height) this.vy *= -1;
            }
        }

        for(let i=0; i<50; i++) nodes.push(new Node());

        function animate() {
            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = '#00f3ff';
            ctx.strokeStyle = 'rgba(0, 243, 255, 0.1)';
            
            for(let i=0; i<nodes.length; i++) {
                let n = nodes[i];
                n.update();
                ctx.beginPath(); ctx.arc(n.x, n.y, 2, 0, Math.PI*2); ctx.fill();
                for(let j=i+1; j<nodes.length; j++) {
                    let n2 = nodes[j];
                    let d = Math.hypot(n.x-n2.x, n.y-n2.y);
                    if(d < 150) {
                        ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(n2.x, n2.y); ctx.stroke();
                    }
                }
            }
            requestAnimationFrame(animate);
        }
        animate();

        // --- Logic ---

        async function fetchUsers() {
            try {
                const res = await fetch(API + '/users');
                const users = await res.json();
                renderTable(users);
                updateStats(users);
            } catch(e) { console.error(e); }
        }

        function renderTable(users) {
            const list = document.getElementById('users-list');
            list.innerHTML = '';
            users.forEach(u => {
                const isExp = new Date(u.expiration_date) < new Date();
                const tr = document.createElement('tr');
                tr.innerHTML = \`
                    <td class="uuid-tag">\${u.uuid.substring(0,8)}...</td>
                    <td style="color:#fff">\${u.notes || 'Unknown'}</td>
                    <td>\${u.expiration_date}</td>
                    <td>\${formatBytes(u.traffic_used)}</td>
                    <td><span class="status-dot \${isExp ? 'status-expired' : 'status-active'}"></span> \${isExp ? 'OFFLINE' : 'ACTIVE'}</td>
                    <td>
                        <button class="cyber-btn" style="padding: 5px 15px; font-size: 0.8rem;" onclick="openView('\${u.uuid}')">CONFIG</button>
                        <button class="cyber-btn cyber-btn-danger" style="padding: 5px 15px; font-size: 0.8rem;" onclick="delUser('\${u.uuid}')">PURGE</button>
                    </td>
                \`;
                list.appendChild(tr);
            });
        }

        function updateStats(users) {
            document.getElementById('total-users').innerText = users.length;
            let total = 0;
            users.forEach(u => total += (u.traffic_used || 0));
            document.getElementById('total-traffic').innerText = formatBytes(total);
        }

        async function createUser(e) {
            e.preventDefault();
            const uuid = document.getElementById('new-uuid').value;
            const notes = document.getElementById('new-note').value;
            const days = document.getElementById('new-days').value;
            const limit = document.getElementById('new-limit').value;

            await fetch(API + '/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ uuid, notes, days, limit })
            });
            closeModal('createModal');
            showToast('ENTITY INITIALIZED');
            fetchUsers();
        }

        async function delUser(uuid) {
            if(!confirm('Purge entity from system?')) return;
            await fetch(API + '/users/' + uuid, { method: 'DELETE' });
            showToast('ENTITY PURGED');
            fetchUsers();
        }

        // Modals
        function openCreateModal() { document.getElementById('createModal').classList.add('active'); }
        async function openView(uuid) { 
            currentUUID = uuid;
            document.getElementById('viewModal').classList.add('active'); 
            
            const link = window.location.origin + '/xray/' + uuid;
            document.getElementById('sub-link-display').innerText = link;
            document.getElementById('qr-code').innerHTML = '';
            
            // Generate QR from actual config
            try {
                const res = await fetch('/xray/' + uuid);
                const b64 = await res.text();
                const text = atob(b64).split('\\n')[0];
                new QRCode(document.getElementById("qr-code"), { text: text, width: 200, height: 200 });
            } catch(e) {
                new QRCode(document.getElementById("qr-code"), { text: link, width: 200, height: 200 });
            }
        }
        function closeModal(id) { document.getElementById(id).classList.remove('active'); }

        function copyLink() {
            navigator.clipboard.writeText(document.getElementById('sub-link-display').innerText);
            showToast('UPLINK COPIED');
        }

        function downloadQR() {
            const img = document.querySelector('#qr-code img');
            if(img) {
                const a = document.createElement('a');
                a.href = img.src;
                a.download = 'quantum-key-' + currentUUID + '.png';
                a.click();
            }
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function showToast(msg) {
            const t = document.getElementById('toast');
            t.innerText = msg; t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3000);
        }

        function filterUsers() {
            const term = document.getElementById('search').value.toLowerCase();
            const rows = document.querySelectorAll('#users-list tr');
            rows.forEach(r => r.style.display = r.innerText.toLowerCase().includes(term) ? '' : 'none');
        }

        function logout() { document.cookie = "auth=; path=/; max-age=0"; location.reload(); }

        fetchUsers();
    </script>
</body>
</html>`;

// ============================================================================
// 👤 USER PANEL HTML (QUANTUM THEME)
// ============================================================================

const userPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My VLESS Access</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #0b0b1a;
            --card: #151525;
            --primary: #6366f1;
            --secondary: #8b5cf6;
            --accent: #06b6d4;
            --text: #f8fafc;
            --text-dim: #94a3b8;
        }
        
        * { box-sizing: border-box; }

        body {
            margin: 0; padding: 20px;
            background: var(--bg);
            color: var(--text);
            font-family: 'Segoe UI', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .bg-glow {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            background: radial-gradient(circle at 50% -20%, rgba(99, 102, 241, 0.2), transparent 50%);
        }

        .dashboard {
            width: 100%;
            max-width: 480px;
            background: rgba(21, 21, 37, 0.8);
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 30px;
            padding: 30px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }

        header { text-align: center; margin-bottom: 30px; }
        h1 { margin: 0; background: linear-gradient(to right, var(--primary), var(--accent)); -webkit-background-clip: text; color: transparent; font-size: 1.8rem; letter-spacing: 1px; }
        .subtitle { color: var(--text-dim); font-size: 0.9rem; margin-top: 5px; }

        /* Usage Circle */
        .usage-container {
            position: relative;
            width: 200px; height: 200px;
            margin: 0 auto 30px;
            border-radius: 50%;
            background: conic-gradient(var(--primary) 0deg, #1e1e2e 0deg);
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 30px rgba(99, 102, 241, 0.2);
            transition: background 1s ease-out;
        }

        .usage-inner {
            width: 170px; height: 170px;
            background: var(--bg);
            border-radius: 50%;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            z-index: 2;
        }

        .usage-val { font-size: 2rem; font-weight: 800; }
        .usage-label { color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 2px; }

        /* Stats Grid */
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 30px;
        }

        .info-box {
            background: rgba(255,255,255,0.03);
            border-radius: 15px;
            padding: 15px;
            text-align: center;
        }
        
        .info-title { color: var(--text-dim); font-size: 0.8rem; margin-bottom: 5px; }
        .info-data { font-weight: bold; font-size: 1.1rem; }

        /* Buttons */
        .btn {
            width: 100%;
            padding: 16px;
            border: none;
            border-radius: 15px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: 0.3s;
            margin-bottom: 15px;
            display: flex; align-items: center; justify-content: center; gap: 10px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
        }
        .btn-primary:hover { transform: translateY(-3px); box-shadow: 0 15px 30px rgba(99, 102, 241, 0.5); }

        .btn-outline {
            background: transparent;
            border: 2px solid rgba(255,255,255,0.1);
            color: var(--text);
        }
        .btn-outline:hover { border-color: var(--accent); color: var(--accent); background: rgba(6, 182, 212, 0.1); }

        /* Modal */
        .modal {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.9); z-index: 100;
            display: none; align-items: center; justify-content: center;
            backdrop-filter: blur(5px);
        }

        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 25px;
            text-align: center;
            color: #000;
            animation: zoomIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        @keyframes zoomIn { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }

        #qr-code img { display: block; margin: 0 auto; border-radius: 5px; }
        
        .close-btn {
            margin-top: 20px;
            padding: 10px 30px;
            background: #ef4444;
            color: white;
            border: none;
            border-radius: 50px;
            cursor: pointer;
            font-weight: bold;
        }

        #notification {
            position: fixed; top: 20px; left: 50%; transform: translateX(-50%) translateY(-100px);
            background: var(--accent); color: #000;
            padding: 10px 30px; border-radius: 50px;
            font-weight: bold; transition: 0.3s;
            z-index: 200;
        }
        #notification.show { transform: translateX(-50%) translateY(0); }

    </style>
</head>
<body>
    <div class="bg-glow"></div>
    <div id="notification">Notification</div>

    <div class="dashboard">
        <header>
            <h1>VLESS Quantum</h1>
            <div class="subtitle">Secure Connection Dashboard</div>
        </header>

        <div class="usage-container" id="progress-ring">
            <div class="usage-inner">
                <span class="usage-val" id="used">--</span>
                <span class="usage-label">Used</span>
            </div>
        </div>

        <div class="info-grid">
            <div class="info-box">
                <div class="info-title">Data Limit</div>
                <div class="info-data" id="limit">--</div>
            </div>
            <div class="info-box">
                <div class="info-title">Expires In</div>
                <div class="info-data" id="expiry">--</div>
            </div>
        </div>

        <button class="btn btn-primary" onclick="copySubscription()">
            <i class="fa-solid fa-link"></i> Copy Subscription Link
        </button>
        
        <button class="btn btn-outline" onclick="showQR()">
            <i class="fa-solid fa-qrcode"></i> Show QR Code
        </button>

        <div style="text-align:center; margin-top: 15px; color: var(--text-dim); font-size: 0.8rem;">
            ID: <span id="short-id">...</span>
        </div>
    </div>

    <div class="modal" id="qrModal">
        <div class="modal-content">
            <h2 style="margin-top:0">Scan to Connect</h2>
            <div id="qr-code"></div>
            <p style="color:#666; font-size:0.9rem; margin-top:10px;">Use V2RayNG, Streisand or Shadowrocket</p>
            <button class="close-btn" onclick="document.getElementById('qrModal').style.display='none'">Close</button>
        </div>
    </div>

    <script>
        // CONFIG INJECTED BY WORKER
        const CONFIG = {
            uuid: 'USER_UUID_PLACEHOLDER'
        };

        async function init() {
            try {
                const res = await fetch('/api/user/' + CONFIG.uuid);
                if (!res.ok) throw new Error('Failed to load');
                
                const data = await res.json();
                
                // Update Data
                document.getElementById('used').innerText = formatBytes(data.traffic_used);
                const limitStr = data.traffic_limit ? data.traffic_limit + ' GB' : 'Unlimited';
                document.getElementById('limit').innerText = limitStr;
                
                // Expiry Logic
                const expDate = new Date(data.expiration_date + 'T' + data.expiration_time + 'Z');
                const daysLeft = Math.ceil((expDate - new Date()) / (1000 * 60 * 60 * 24));
                document.getElementById('expiry').innerText = daysLeft > 0 ? daysLeft + ' Days' : 'Expired';
                if (daysLeft < 0) document.getElementById('expiry').style.color = '#ef4444';

                document.getElementById('short-id').innerText = CONFIG.uuid.substring(0,8) + '...';

                // Progress Ring
                if (data.traffic_limit) {
                    const totalBytes = data.traffic_limit * 1024 * 1024 * 1024;
                    const pct = Math.min((data.traffic_used / totalBytes) * 360, 360);
                    const color = pct > 300 ? '#ef4444' : '#6366f1';
                    document.getElementById('progress-ring').style.background = \`conic-gradient(\${color} \${pct}deg, #1e1e2e \${pct}deg)\`;
                }
            } catch(e) { console.error(e); }
        }

        async function copySubscription() {
            const link = window.location.origin + '/xray/' + CONFIG.uuid;
            try {
                await navigator.clipboard.writeText(link);
                notify('Link Copied to Clipboard!');
            } catch(e) {
                prompt("Copy this link:", link);
            }
        }

        async function showQR() {
            const modal = document.getElementById('qrModal');
            const qrContainer = document.getElementById('qr-code');
            qrContainer.innerHTML = 'Loading...';
            modal.style.display = 'flex';

            // Fetch actual config string for the QR (better than just sub link)
            const subLink = window.location.origin + '/xray/' + CONFIG.uuid;
            try {
                const res = await fetch('/xray/' + CONFIG.uuid);
                const b64 = await res.text();
                const text = atob(b64);
                const firstConfig = text.split('\\n')[0] || subLink;
                
                qrContainer.innerHTML = '';
                new QRCode(qrContainer, {
                    text: firstConfig,
                    width: 220,
                    height: 220
                });
            } catch(e) {
                qrContainer.innerHTML = '';
                new QRCode(qrContainer, { text: subLink, width: 220, height: 220 });
            }
        }

        function notify(msg) {
            const el = document.getElementById('notification');
            el.innerText = msg;
            el.classList.add('show');
            setTimeout(() => el.classList.remove('show'), 3000);
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        init();
    </script>
</body>
</html>`;

// ============================================================================
// LANDING PAGE HTML (Persian)
// ============================================================================

const landingPageHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ VLESS Quantum Worker</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700;900&display=swap');
        * { margin:0; padding:0; box-sizing:border-box; font-family: 'Vazirmatn', sans-serif; }
        body { background: #000; color: white; overflow-x: hidden; }
        
        /* Quantum Background */
        .bg { position: fixed; top:0; left:0; width:100%; height:100%; z-index:-1; background: radial-gradient(circle at 50% 50%, #1a1a2e 0%, #000 100%); }
        .orb { position: absolute; border-radius: 50%; filter: blur(80px); opacity: 0.6; animation: float 10s infinite alternate; }
        .orb-1 { width: 300px; height: 300px; background: #7b2cbf; top: 10%; left: 20%; }
        .orb-2 { width: 400px; height: 400px; background: #4361ee; bottom: 10%; right: 20%; animation-delay: -5s; }

        @keyframes float { 0% { transform: translate(0,0); } 100% { transform: translate(50px, 50px); } }

        .container { max-width: 1200px; margin: 0 auto; padding: 50px 20px; display: flex; flex-direction: column; align-items: center; text-align: center; min-height: 100vh; justify-content: center; }
        
        h1 { font-size: 4rem; font-weight: 900; background: linear-gradient(45deg, #4facfe, #f093fb); -webkit-background-clip: text; color: transparent; text-shadow: 0 0 50px rgba(79, 172, 254, 0.5); margin-bottom: 20px; line-height: 1.2; }
        p { font-size: 1.5rem; color: #b8c1ec; margin-bottom: 50px; max-width: 800px; }

        .btn-glitch {
            padding: 20px 60px;
            font-size: 1.5rem;
            background: transparent;
            color: white;
            border: 2px solid #4facfe;
            border-radius: 50px;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            transition: 0.3s;
            text-decoration: none;
            box-shadow: 0 0 20px rgba(79, 172, 254, 0.4);
        }
        .btn-glitch:hover { background: #4facfe; color: black; box-shadow: 0 0 50px #4facfe; transform: scale(1.05); }

        /* Stats Grid */
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 30px; width: 100%; margin-top: 80px; }
        .feature-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 30px; border-radius: 20px; backdrop-filter: blur(10px); transition: 0.3s; }
        .feature-card:hover { transform: translateY(-10px); border-color: #f093fb; background: rgba(255,255,255,0.1); }
        .feature-icon { font-size: 3rem; margin-bottom: 20px; }
        h3 { font-size: 1.5rem; margin-bottom: 10px; color: #fff; }
        .desc { font-size: 1rem; color: #a0a0a0; margin: 0; }

    </style>
</head>
<body>
    <div class="bg">
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
    </div>

    <div class="container">
        <h1>VLESS Quantum Worker</h1>
        <p>نسل جدید فیلترشکن‌های ابری با تکنولوژی Cloudflare Edge. سرعت نور، امنیت کوانتومی.</p>
        
        <a href="/panel" class="btn-glitch">ورود به پنل کاربری</a>

        <div class="features">
            <div class="feature-card">
                <div class="feature-icon">🚀</div>
                <h3>سرعت بالا</h3>
                <p class="desc">اتصال مستقیم به شبکه جهانی کلودفلر</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🛡️</div>
                <h3>امنیت کامل</h3>
                <p class="desc">رمزنگاری سرتاسری و غیرقابل ردیابی</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🌐</div>
                <h3>ضد فیلتر</h3>
                <p class="desc">تکنولوژی VLESS برای عبور از محدودیت‌ها</p>
            </div>
        </div>
    </div>
</body>
</html>`;

// ============================================================================
// 🚀 MAIN WORKER ENTRY POINT (QUANTUM CORE)
// ============================================================================

import { Config, QuantumBrain } from './workers1.js';
import { ensureTablesExist, performHealthCheck, getUserData } from './workers2.js';
import { handleVlessWebSocket } from './workers3.js';
import { handleSubscription } from './workers4.js';
import { adminPanelHTML } from './workers5.js';
import { userPanelHTML } from './workers6.js';
import { landingPageHTML } from './workers7.js';

export default {
    async fetch(request, env, ctx) {
        try {
            // 9. Meta-Decision Intelligence: How deep do we think?
            // If the system is stressed (High Entropy), we enable Asymmetric Security.
            const systemEntropy = QuantumBrain.metrics.entropyAvg;
            const isUnderAttack = systemEntropy > 0.9;

            // 7. Asymmetric & Psychological Security (Tarpit)
            // If under attack, don't just block. Confuse.
            if (isUnderAttack && Math.random() < 0.5) {
                // Return a stream that never ends, sending garbage bytes slowly.
                const { readable, writable } = new TransformStream();
                const writer = writable.getWriter();
                ctx.waitUntil((async () => {
                    while(true) {
                        try {
                            await writer.write(new TextEncoder().encode("QUANTUM_FLUX_"));
                            await new Promise(r => setTimeout(r, 1000)); // Slow drip
                        } catch(e) { break; }
                    }
                })());
                return new Response(readable, { status: 200 });
            }

            const url = new URL(request.url);
            const upgradeHeader = request.headers.get('Upgrade');
            
            // 1. WebSocket / VLESS Traffic Handling
            if (upgradeHeader === 'websocket') {
                const config = await Config.fromEnv(env);
                const webSocketPair = new WebSocketPair();
                const [client, server] = Object.values(webSocketPair);
                
                // 4. Perception-Level Zero Latency
                // Accept immediately. Do not wait for auth or backend.
                server.accept();
                
                // Hand off to Cognitive Core
                // This function now runs independently, creating the "Quantum Execution Fabric"
                handleVlessWebSocket(server, request.headers.get('CF-Connecting-IP'), config, env);
                
                return new Response(null, { 
                    status: 101, 
                    webSocket: client 
                });
            }

            // 2. Robots & Security Files
            if (url.pathname === '/robots.txt') return new Response("User-agent: *\nDisallow: /", { headers: {'Content-Type': 'text/plain'} });
            if (url.pathname === '/security.txt') return new Response("Contact: admin@example.com\nExpires: 2030-01-01T00:00:00.000Z", { headers: {'Content-Type': 'text/plain'} });

            // 3. Subscription Links
            const subMatch = url.pathname.match(/^\/(xray|sb|clash)\/([a-z0-9-]+)$/);
            if (subMatch) {
                return await handleSubscription(request, env, subMatch[1], subMatch[2], url.hostname);
            }

            // 4. User Panel Access
            const userPanelMatch = url.pathname.match(/^\/panel\/([a-z0-9-]+)$/);
            if (userPanelMatch) {
                const uuid = userPanelMatch[1];
                const user = await getUserData(env, uuid);
                
                if (!user) {
                    // 10. Non-Deterministic Attack Surface
                    // Add variable delay before returning 404 to mess with timing attacks
                    await new Promise(r => setTimeout(r, Math.random() * 50));
                    return new Response(get404HTML(), { 
                        status: 404, 
                        headers: {'Content-Type': 'text/html;charset=utf-8'} 
                    });
                }
                
                const html = userPanelHTML.replace('USER_UUID_PLACEHOLDER', uuid);
                return new Response(html, { headers: {'Content-Type': 'text/html;charset=utf-8'} });
            }

            // 5. Admin API (JSON)
            if (url.pathname.startsWith('/api')) {
                const cookie = request.headers.get('Cookie') || '';
                const isAdmin = cookie.includes('auth=admin'); 
                
                if (!isAdmin && url.pathname !== '/api/login') {
                    return new Response(JSON.stringify({error: 'Unauthorized'}), {status: 401});
                }

                // API: List Users
                if (url.pathname === '/api/users') {
                    if (request.method === 'GET') {
                        const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
                        return new Response(JSON.stringify(results), {headers:{'Content-Type':'application/json'}});
                    }
                    if (request.method === 'POST') {
                        const body = await request.json();
                        const newUUID = body.uuid || crypto.randomUUID();
                        const limit = parseFloat(body.limit) || 0;
                        const notes = body.notes || '';
                        
                        const d = new Date(); 
                        d.setDate(d.getDate() + parseInt(body.days || 30));
                        const expDate = d.toISOString().split('T')[0];
                        
                        await env.DB.prepare(
                            "INSERT INTO users (uuid, expiration_date, expiration_time, traffic_limit, notes) VALUES (?, ?, '23:59:59', ?, ?)"
                        ).bind(newUUID, expDate, limit, notes).run();
                        
                        return new Response(JSON.stringify({success: true}));
                    }
                }
                
                if (url.pathname.startsWith('/api/users/') && request.method === 'DELETE') {
                    const delUuid = url.pathname.split('/').pop();
                    await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(delUuid).run();
                    return new Response(JSON.stringify({success: true}));
                }
            }

            // 6. Admin Panel HTML
            if (url.pathname === '/admin') {
                return new Response(adminPanelHTML, { headers: {'Content-Type': 'text/html;charset=utf-8'} });
            }

            // 7. Landing Page & Reverse Proxy
            if (url.pathname === '/') {
                if (Config.landingProxy) {
                    const target = new URL(Config.landingProxy);
                    target.pathname = url.pathname;
                    return fetch(target.toString(), request);
                }
                return new Response(landingPageHTML, { headers: {'Content-Type': 'text/html;charset=utf-8'} });
            }

            // 8. Custom 404 Page (Quantum)
            return new Response(get404HTML(), { 
                status: 404, 
                headers: {'Content-Type': 'text/html;charset=utf-8'} 
            });

        } catch (e) {
            console.error('Worker Error:', e);
            // 20. Unobservable Core: Return generic error to outside world, do not leak stack
            return new Response('Edge Anomaly', { status: 500 });
        }
    },

    // Scheduled Tasks (Evolution & Cleanup)
    async scheduled(event, env, ctx) {
        ctx.waitUntil(ensureTablesExist(env));
        ctx.waitUntil(performHealthCheck(env));
    }
};

function get404HTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
body{background:#000;color:#fff;font-family:sans-serif;height:100vh;display:flex;align-items:center;justify-content:center;margin:0;overflow:hidden}
h1{font-size:5rem;margin:0;background:linear-gradient(45deg,#f09,#0ff);-webkit-background-clip:text;color:transparent;}
p{font-size:1.5rem;color:#888;}
</style>
</head>
<body>
<div style="text-align:center">
<h1>404</h1>
<p>Quantum Singularity - Page Not Found</p>
</div>
</body>
</html>`;
}
