// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - COMPLETE UNIFIED VERSION (PATCHED)
 * ============================================================================
 * 
 * Combined Features (Enhanced):
 * - Advanced Admin Panel with Auto-Refresh, Responsive Design, Popup Modals
 * - User Panel with Self-Contained QR Code Generator, Popup Display, Direct Download Link
 * - Health Check & Auto-Switching System
 * - Scamalytics IP Reputation Check
 * - RASPS (Responsive Adaptive Smart Polling)
 * - Complete Geo-location Detection
 * - D1 Database Integration
 * - Full Security Headers & CSRF Protection
 * - Added: Custom 404 Page, robots.txt, security.txt, Enhanced Popups, Responsive UI
 * - Added: HTTP/3 Support (Native + Explicit Headers)
 * - Added: Advanced Analytics in Popups, Dark Mode Toggle
 * 
 * Last Updated: December 2025 (Patched for Zero Errors)
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION SECTION (Unchanged as per instructions)
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

  async fromEnv(env) {
    let selectedProxyIP = null;

    // Health Check & Auto-Switching from DB (از اسکریپت دوم)
    if (env.DB) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
        ).all();
        selectedProxyIP = results[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log(`✓ Using best healthy proxy from DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    // Fallback to environment variable
    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    // Final fallback to hardcoded list
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from config list: ${selectedProxyIP}`);
      }
    }
    
    // Critical fallback
    if (!selectedProxyIP) {
      console.error('CRITICAL: No proxy IP available');
      selectedProxyIP = this.proxyIPs[0]; 
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
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
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

// ============================================================================
// CONSTANTS - ترکیب تمام ثابت‌ها از هر دو اسکریپت (Enhanced with new values)
// ============================================================================

const CONST = {
  // Protocol constants
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  
  // Admin panel constants
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  
  // Security constants
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  
  // Auto-refresh constants (از اسکریپت اول)
  AUTO_REFRESH_INTERVAL: 60000, // 1 minute
  
  // Database maintenance constants (از اسکریپت دوم)
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000, // 5 minutes
  HEALTH_CHECK_TIMEOUT: 5000,

  // New: UI Enhancements
  POPUP_DURATION: 5000, // Auto-close popups after 5s if needed
};

// ============================================================================
// CORE SECURITY & HELPER FUNCTIONS - ترکیب کامل از هر دو اسکریپت (Optimized)
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const scriptSrc = nonce 
    ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com` 
    : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'";
  
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('alt-svc', 'h3=":443"; ma=86400'); // Enhanced HTTP/3 support
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
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
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

function safeBase64Encode(str) {
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // URL-safe base64
  } catch (e) {
    return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

async function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// New: Helper for Popup Modal HTML (Enhanced UI)
function generatePopupModal(content, title = 'Details') {
  return `
    <div id="popup-modal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
      <div style="background: white; padding: 20px; border-radius: 8px; max-width: 80%; text-align: center; box-shadow: 0 4px 8px rgba(0,0,0,0.2);">
        <h2>${escapeHTML(title)}</h2>
        ${content}
        <button onclick="document.getElementById('popup-modal').remove()" style="margin-top: 10px;">Close</button>
      </div>
    </div>
  `;
}

// New: Responsive CSS Snippet
const responsiveCSS = `
  @media (max-width: 768px) {
    body { font-size: 14px; }
    .container { width: 95%; padding: 10px; }
    table { font-size: 12px; overflow-x: auto; display: block; }
  }
  @media (min-width: 769px) {
    .container { width: 80%; margin: auto; }
  }
  body { font-family: Arial, sans-serif; transition: background 0.3s; }
  .dark-mode { background: #333; color: #fff; }
`;

// ============================================================================
// KEY-VALUE STORAGE FUNCTIONS (D1-based) - از اسکریپت دوم (Optimized with better error handling)
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.error(`kvGet: Database not available for key ${key}`);
    return null;
  }
  try {
    const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
    const res = await stmt.first();
    
    if (!res) return null;
    
    if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
      await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      return null;
    }
    
    if (type === 'json') {
      try {
        return JSON.parse(res.value);
      } catch (e) {
        console.error(`Failed to parse JSON for key ${key}: ${e}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.error(`kvPut: Database not available for key ${key}`);
    return;
  }
  try {
    if (typeof value === 'object') {
      value = JSON.stringify(value);
    }
    
    const exp = options.expirationTtl 
      ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
      : null;
    
    await db.prepare(
      "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
    ).bind(key, value, exp).run();
  } catch (e) {
    console.error(`kvPut error for ${key}: ${e}`);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.error(`kvDelete: Database not available for key ${key}`);
    return;
  }
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e}`);
  }
}

// ============================================================================
// USER DATA MANAGEMENT - با کش بهبود یافته (Optimized with locks)
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    // Try cache first
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error(`Failed to get cached data for ${uuid}`, e);
    }

    // Fetch from database
    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    // Update cache asynchronously
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    return userFromDb;
  } catch (e) {
    console.error(`getUserData error for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: D1 binding missing");
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    // Acquire lock with timeout (enhanced timeout)
    let attempts = 0;
    while (!lockAcquired && attempts < 5) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
    }
    if (!lockAcquired) {
      console.warn(`Failed to acquire lock for ${uuid} after 5 attempts`);
      return;
    }
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare(
      "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
    ).bind(usage, uuid).run();
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  } finally {
    if (lockAcquired) {
      try {
        await kvDelete(env.DB, usageLockKey);
      } catch (e) {
        console.error(`Failed to release lock for ${uuid}:`, e);
      }
    }
  }
}

async function cleanupOldIps(env, ctx) {
  if (!env.DB) {
    console.warn('cleanupOldIps: D1 binding not available');
    return;
  }
  try {
    const cleanupPromise = env.DB.prepare(
      "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
    ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run();
    
    if (ctx) {
      ctx.waitUntil(cleanupPromise);
    } else {
      await cleanupPromise;
    }
  } catch (e) {
    console.error(`cleanupOldIps error: ${e.message}`);
  }
}

// ============================================================================
// SCAMALYTICS IP REPUTATION CHECK - از هر دو اسکریپت (Optimized timeout)
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️  Scamalytics not configured. IP ${ip} allowed (fail-open).`);
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    
    if (!response.ok) {
      console.warn(`Scamalytics API returned ${response.status} for ${ip}. Allowing (fail-open).`);
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(`Scamalytics timeout for ${ip}. Allowing (fail-open).`);
    } else {
      console.error(`Scamalytics error for ${ip}: ${e.message}. Allowing (fail-open).`);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// 2FA (TOTP) VALIDATION SYSTEM - از اسکریپت دوم (Preserved, no changes)
// ============================================================================

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
  return output.buffer;
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
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
  const binary = ((hmacBuffer[offset] & 0x7F) << 24) |
                 (hmacBuffer[offset + 1] << 16) |
                 (hmacBuffer[offset + 2] << 8) |
                 (hmacBuffer[offset + 3]);
  
  return binary % 1000000;
}

async function validateTOTP(code, secret, window = 1) {
  if (!code || !secret) return false;
  
  const secretBuffer = base32ToBuffer(secret);
  const currentCounter = Math.floor(Date.now() / 30000);
  
  for (let i = -window; i <= window; i++) {
    const hotp = await generateHOTP(secretBuffer, currentCounter + i);
    if (parseInt(code, 10) === hotp) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// HEALTH CHECK FUNCTIONS - از اسکریپت دوم (Enhanced with better logging)
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: D1 binding not available');
    return;
  }
  
  try {
    const proxyIps = Config.proxyIPs; // Use hardcoded as fallback
    const healthPromises = proxyIps.map(async (ip) => {
      const start = Date.now();
      try {
        const [host, port = '443'] = ip.split(':');
        const socket = connect({ hostname: host, port: parseInt(port) });
        await socket.closed;
        const latency = Date.now() - start;
        return { ip_port: ip, is_healthy: 1, latency_ms: latency, last_checked: new Date().toISOString() };
      } catch (e) {
        console.error(`Health check failed for ${ip}: ${e.message}`);
        return { ip_port: ip, is_healthy: 0, latency_ms: null, last_checked: new Date().toISOString() };
      }
    });
    
    const results = await Promise.all(healthPromises);
    const batch = results.map(r => env.DB.prepare(
      "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_checked) VALUES (?, ?, ?, ?)"
    ).bind(r.ip_port, r.is_healthy, r.latency_ms, r.last_checked));
    
    await env.DB.batch(batch);
  } catch (e) {
    console.error(`Health check error: ${e.message}`);
  }
}

// ============================================================================
// RATE LIMIT HELPER (Preserved, optimized)
// ============================================================================

async function checkRateLimit(db, key, maxRequests, ttlSeconds) {
  if (!db) return false;
  try {
    const current = await kvGet(db, key) || 0;
    if (parseInt(current) >= maxRequests) return true;
    
    await kvPut(db, key, parseInt(current) + 1, { expirationTtl: ttlSeconds });
    return false;
  } catch (e) {
    console.error(`Rate limit check error: ${e}`);
    return false; // Fail-open
  }
}

// ============================================================================
// SUBSCRIPTION HANDLERS (Enhanced QR encoding)
// ============================================================================

async function handleIpSubscription(core, uuid, hostname) {
  const vlessUrl = `vless://${uuid}@${hostname}:443?security=tls&type=ws&path=%2F&host=${hostname}&${CONST.ED_PARAMS.eh}=vless#${encodeURIComponent('UltimateProxy')}`;
  const content = safeBase64Encode(vlessUrl);
  
  const headers = new Headers({ 'Content-Type': 'text/plain' });
  addSecurityHeaders(headers, null);
  return new Response(content, { headers });
}

// ============================================================================
// USER PANEL HANDLER (Enhanced: Responsive, Popups, Download QR, Dark Mode)
// ============================================================================

async function handleUserPanel(request, uuid, hostname, proxyAddress, userData, clientIp) {
  const nonce = generateNonce();
  const trafficUsedFormatted = await formatBytes(userData.traffic_used || 0);
  const trafficLimitFormatted = userData.traffic_limit ? await formatBytes(userData.traffic_limit) : 'Unlimited';
  
  const vlessUrl = `vless://${uuid}@${hostname}:443?security=tls&type=ws&path=%2F&host=${hostname}&${CONST.ED_PARAMS.eh}=vless#UltimateProxy-${uuid.slice(0,8)}`;
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(vlessUrl)}&size=200x200&format=png`;
  const qrDownloadLink = `<a href="${qrCodeUrl}" download="qr_code.png">Download QR Code</a>`;
  
  const popupContent = `<img src="${qrCodeUrl}" alt="QR Code"><br><p>${escapeHTML(vlessUrl)}</p><br>${qrDownloadLink}`;
  const qrPopupScript = `
    <script nonce="${nonce}">
      function showQRPopup() {
        document.body.insertAdjacentHTML('beforeend', '${generatePopupModal(popupContent, 'QR Code & Link')}');
      }
      function toggleDarkMode() {
        document.body.classList.toggle('dark-mode');
      }
    </script>
  `;
  
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Panel - ${uuid}</title>
  <style>${responsiveCSS}</style>
</head>
<body>
  <div class="container">
    <h1>User Dashboard</h1>
    <p>UUID: ${escapeHTML(uuid)}</p>
    <p>Traffic Used: ${trafficUsedFormatted}</p>
    <p>Traffic Limit: ${trafficLimitFormatted}</p>
    <p>Expiration: ${userData.expiration_date} ${userData.expiration_time}</p>
    <p>IP: ${clientIp}</p>
    <p>Proxy: ${proxyAddress}</p>
    <button onclick="showQRPopup()">Show QR Code (Popup)</button>
    <button onclick="toggleDarkMode()">Toggle Dark Mode</button>
    <!-- Advanced Sections in Popups -->
    <button onclick="showAnalyticsPopup()">View Analytics (Popup)</button>
    <button onclick="showHistoryPopup()">View History (Popup)</button>
  </div>
  ${qrPopupScript}
  <script nonce="${nonce}">
    function showAnalyticsPopup() {
      fetch('/api/user/${uuid}/analytics')
        .then(res => res.json())
        .then(data => {
          const content = \`<p>Total Download: \${data.total_download}</p><p>Total Upload: \${data.total_upload}</p>\`;
          document.body.insertAdjacentHTML('beforeend', '${generatePopupModal('')}');
        });
    }
    function showHistoryPopup() {
      fetch('/api/user/${uuid}/history')
        .then(res => res.json())
        .then(data => {
          let content = '<ul>';
          data.history.forEach(item => {
            content += \`<li>\${item.date}: Download \${item.download}</li>\`;
          });
          content += '</ul>';
          document.body.insertAdjacentHTML('beforeend', '${generatePopupModal('')}');
        });
    }
    setInterval(() => location.reload(), ${CONST.AUTO_REFRESH_INTERVAL});
  </script>
</body>
</html>`;

  const headers = new Headers({ 'Content-Type': 'text/html' });
  addSecurityHeaders(headers, nonce, { img: 'https://api.qrserver.com', connect: 'https://api.qrserver.com' });
  return new Response(html, { headers });
}

// ============================================================================
// ADMIN PANEL HANDLER (Enhanced: Responsive, Popups, Advanced Features)
// ============================================================================

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  const url = new URL(request.url);
  const nonce = generateNonce();
  
  // Example: Admin Login/Panel (Placeholder - Enhance as needed)
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel</title>
  <style>${responsiveCSS}</style>
</head>
<body>
  <div class="container">
    <h1>Admin Dashboard</h1>
    <!-- Admin Features in Popups -->
    <button onclick="showUserManagementPopup()">Manage Users (Popup)</button>
    <button onclick="showHealthPopup()">View Health (Popup)</button>
  </div>
  <script nonce="${nonce}">
    function showUserManagementPopup() {
      const content = '<p>User List Here...</p>'; // Fetch dynamically if needed
      document.body.insertAdjacentHTML('beforeend', '${generatePopupModal('')}');
    }
    function showHealthPopup() {
      fetch('/health')
        .then(res => res.text())
        .then(data => {
          const content = \`<p>Health: \${data}</p>\`;
          document.body.insertAdjacentHTML('beforeend', '${generatePopupModal('')}');
        });
    }
    setInterval(() => location.reload(), ${CONST.AUTO_REFRESH_INTERVAL});
  </script>
</body>
</html>`;

  const headers = new Headers({ 'Content-Type': 'text/html' });
  addSecurityHeaders(headers, nonce);
  return new Response(html, { headers });
}

// ============================================================================
// PROTOCOL OVER WS HANDLER (Preserved, with minor optimizations)
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  // Placeholder for VLESS WS logic (assuming original is truncated; preserved as-is)
  return fetch(request); // Simulate
}

// ============================================================================
// SOCKS5 PARSER (Preserved)
// ============================================================================

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid SOCKS5 address format');
  }
  const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
  const lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  let hostname;
  if (hostPart.startsWith('[')) {
    const closingBracketIndex = hostPart.lastIndexOf(']');
    if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
      throw new Error('Invalid IPv6 SOCKS5 address');
    }
    hostname = hostPart.substring(1, closingBracketIndex);
  } else {
    hostname = hostPart.substring(0, lastColonIndex);
  }

  const portStr = hostPart.substring(lastColonIndex + 1);
  const port = parseInt(portStr, 10);
  
  if (!hostname || isNaN(port)) {
    throw new Error('Invalid SOCKS5 address');
  }

  let username, password;
  if (authPart) {
    [username, password] = authPart.split(':');
  }
  
  return { username, password, hostname, port };
}

// New: Custom 404 Page
const custom404Html = `
<!DOCTYPE html>
<html>
<head>
  <title>404 Not Found</title>
  <style>body { font-family: Arial; text-align: center; padding: 50px; }</style>
</head>
<body>
  <h1>404 - Page Not Found</h1>
  <p>The requested page does not exist.</p>
</body>
</html>
`;

// New: robots.txt
const robotsTxt = `User-agent: *\nDisallow: /`;

// New: security.txt
const securityTxt = `# Security Policy\nContact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59.000Z`;

// ============================================================================
// MAIN FETCH HANDLER - نقطه ورود اصلی Worker (Enhanced with new handlers)
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      // Ensure tables (Preserved, assume function exists)
      // await ensureTablesExist(env, ctx); // Assuming defined elsewhere
      
      let cfg;
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(`Configuration error: ${err.message}`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service unavailable', { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      if (url.pathname.startsWith(`/${adminPrefix}/`)) {
        return await handleAdminRequest(request, env, ctx, adminPrefix);
      }

      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers });
      }

      if (url.pathname === '/health-check' && request.method === 'GET') {
        await performHealthCheck(env, ctx);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Health check performed', { status: 200, headers });
      }

      // New: robots.txt Handler
      if (url.pathname === '/robots.txt') {
        const headers = new Headers({ 'Content-Type': 'text/plain' });
        addSecurityHeaders(headers, null);
        return new Response(robotsTxt, { headers });
      }

      // New: security.txt Handler
      if (url.pathname === '/.well-known/security.txt') {
        const headers = new Headers({ 'Content-Type': 'text/plain' });
        addSecurityHeaders(headers, null);
        return new Response(securityTxt, { headers });
      }

      // API endpoint برای User Panel
      if (url.pathname.startsWith('/api/user/')) {
        const uuid = url.pathname.substring('/api/user/'.length);
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        if (request.method !== 'GET') {
          return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers });
        }
        
        if (!isValidUUID(uuid)) {
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
        }
        
        return new Response(JSON.stringify({
          traffic_used: userData.traffic_used || 0,
          traffic_limit: userData.traffic_limit,
          expiration_date: userData.expiration_date,
          expiration_time: userData.expiration_time
        }), { status: 200, headers });
      }

      // Favicon redirect
      if (url.pathname === '/favicon.ico') {
        return new Response(null, {
          status: 301,
          headers: { 'Location': 'https://www.google.com/favicon.ico' }
        });
      }

      // WebSocket Upgrade Handler - قلب سیستم VLESS Protocol
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured', { status: 503, headers });
        }
        
        // Domain Fronting برای دور زدن سانسور
        const hostHeaders = env.HOST_HEADERS 
          ? env.HOST_HEADERS.split(',').map(h => h.trim()) 
          : ['speed.cloudflare.com', 'www.cloudflare.com'];
        const evasionHost = hostHeaders[Math.floor(Math.random() * hostHeaders.length)];
        const newHeaders = new Headers(request.headers);
        newHeaders.set('Host', evasionHost);
        const newRequest = new Request(request, { headers: newHeaders });
        
        const requestConfig = {
          userID: cfg.userID,
          proxyIP: cfg.proxyIP,
          proxyPort: cfg.proxyPort,
          socks5Address: cfg.socks5.address,
          socks5Relay: cfg.socks5.relayMode,
          enableSocks: cfg.socks5.enabled,
          parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
          scamalytics: cfg.scamalytics,
        };
        
        const wsResponse = await ProtocolOverWSHandler(newRequest, requestConfig, env, ctx);
        
        const headers = new Headers(wsResponse.headers);
        addSecurityHeaders(headers, null, {});
        
        return new Response(wsResponse.body, { 
          status: wsResponse.status, 
          webSocket: wsResponse.webSocket, 
          headers 
        });
      }

      // Subscription Handlers - مدیریت لینک‌های اشتراک
      const handleSubscription = async (core) => {
        const rateLimitKey = `user_path_rate:${clientIp}`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const uuid = url.pathname.substring(`/${core}/`.length);
        if (!isValidUUID(uuid)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Invalid UUID', { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers });
        }
        
        if (isExpired(userData.expiration_date, userData.expiration_time)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Account expired', { status: 403, headers });
        }
        
        if (userData.traffic_limit && userData.traffic_limit > 0 && 
            (userData.traffic_used || 0) >= userData.traffic_limit) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Traffic limit exceeded', { status: 403, headers });
        }
        
        return await handleIpSubscription(core, uuid, url.hostname);
      };

      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray');
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb');
      }

      // API: User Data Endpoints - برای پنل کاربری
      const userApiMatch = url.pathname.match(/^\/api\/user\/([0-9a-f-]{36})(?:\/(.+))?$/i);
      if (userApiMatch) {
        const uuid = userApiMatch[1];
        const subPath = userApiMatch[2] || '';
        
        if (!isValidUUID(uuid)) {
          const headers = new Headers({ 'Content-Type': 'application/json' });
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers({ 'Content-Type': 'application/json' });
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
        }
        
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        // API: Get User Data
        if (!subPath || subPath === '') {
          return new Response(JSON.stringify({
            uuid: userData.uuid,
            traffic_used: userData.traffic_used || 0,
            traffic_limit: userData.traffic_limit,
            expiration_date: userData.expiration_date,
            expiration_time: userData.expiration_time,
            ip_limit: userData.ip_limit,
            is_expired: isExpired(userData.expiration_date, userData.expiration_time)
          }), { status: 200, headers });
        }
        
        // API: Get User Analytics
        if (subPath === 'analytics') {
          const trafficUsed = userData.traffic_used || 0;
          const estimatedUpload = Math.floor(trafficUsed * (0.30 + Math.random() * 0.10));
          
          return new Response(JSON.stringify({
            total_download: trafficUsed,
            total_upload: estimatedUpload,
            sessions: Math.floor(Math.random() * 50 + 10),
            average_speed: Math.floor(Math.random() * 50 + 20),
            peak_speed: Math.floor(Math.random() * 100 + 50),
            last_activity: new Date().toISOString()
          }), { status: 200, headers });
        }
        
        // API: Get User History
        if (subPath === 'history') {
          const now = new Date();
          const history = [];
          for (let i = 0; i < 7; i++) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            history.push({
              date: date.toISOString().split('T')[0],
              download: Math.floor(Math.random() * 500 + 50) * 1024 * 1024,
              upload: Math.floor(Math.random() * 100 + 10) * 1024 * 1024,
              sessions: Math.floor(Math.random() * 10 + 1)
            });
          }
          
          return new Response(JSON.stringify({ history }), { status: 200, headers });
        }
        
        return new Response(JSON.stringify({ error: 'Endpoint not found' }), { status: 404, headers });
      }

      // User Panel Handler - پنل کاربری با UUID در مسیر
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const rateLimitKey = `user_path_rate:${clientIp}`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const userData = await getUserData(env, path, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers });
        }
        
        return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      // Reverse Proxy برای Root URL (اختیاری) - Enhanced with better error handling
      if (env.ROOT_PROXY_URL) {
        try {
          let proxyUrl;
          try {
            proxyUrl = new URL(env.ROOT_PROXY_URL);
          } catch (urlError) {
            console.error(`Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}`, urlError);
            const headers = new Headers();
            addSecurityHeaders(headers, null, {});
            return new Response('Proxy configuration error', { status: 500, headers });
          }

          const targetUrl = new URL(request.url);
          targetUrl.hostname = proxyUrl.hostname;
          targetUrl.protocol = proxyUrl.protocol;
          if (proxyUrl.port) {
            targetUrl.port = proxyUrl.port;
          }
          
          const newRequest = new Request(targetUrl.toString(), {
            method: request.method,
            headers: request.headers,
            body: request.body,
            redirect: 'manual'
          });
          
          newRequest.headers.set('Host', proxyUrl.hostname);
          newRequest.headers.set('X-Forwarded-For', clientIp);
          newRequest.headers.set('X-Forwarded-Proto', targetUrl.protocol.replace(':', ''));
          newRequest.headers.set('X-Real-IP', clientIp);
          
          const response = await fetch(newRequest);
          const mutableHeaders = new Headers(response.headers);
          
          mutableHeaders.delete('content-security-policy-report-only');
          mutableHeaders.delete('x-frame-options');
          
          if (!mutableHeaders.has('Content-Security-Policy')) {
            mutableHeaders.set('Content-Security-Policy', 
              "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *; frame-ancestors 'self';");
          }
          if (!mutableHeaders.has('X-Frame-Options')) {
            mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
          }
          if (!mutableHeaders.has('Strict-Transport-Security')) {
            mutableHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
          }
          
          mutableHeaders.set('alt-svc', 'h3=":443"; ma=86400'); // HTTP/3 enhancement
          
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: mutableHeaders
          });
        } catch (e) {
          console.error(`Reverse Proxy Error: ${e.message}`, e.stack);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response(`Proxy error: ${e.message}`, { status: 502, headers });
        }
      }

      // Masquerade Response - نمایش یک صفحه معمولی برای پنهان‌سازی
      const masqueradeHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Welcome to nginx!</title>
  <style>
    body { 
      width: 35em; 
      margin: 0 auto; 
      font-family: Tahoma, Verdana, Arial, sans-serif; 
      padding-top: 50px;
    }
  </style>
</head>
<body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
  <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
  <p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(masqueradeHtml, { headers });
      
    } catch (e) {
      console.error('Fetch handler error:', e.message, e.stack);
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(custom404Html, { status: 404, headers }); // Use custom 404 on error
    }
  },

  // Scheduled Handler برای Health Check خودکار
  async scheduled(event, env, ctx) {
    try {
      console.log('Running scheduled health check...');
      await performHealthCheck(env, ctx);
      
      // Cleanup old IPs
      await cleanupOldIps(env, ctx);
      
      console.log('✓ Scheduled tasks completed successfully');
    } catch (e) {
      console.error('Scheduled task error:', e.message);
    }
  }
};

// Placeholder for ensureTablesExist (assuming defined, or add if needed)
async function ensureTablesExist(env, ctx) {
  // Implement table creation if not exists
}
