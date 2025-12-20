// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - COMPLETE UNIFIED VERSION
 * ============================================================================
 * 
 * ویژگی‌های ترکیب شده:
 * - پنل ادمین پیشرفته با به‌روزرسانی خودکار
 * - پنل کاربری با تولیدکننده QR Code خودکار
 * - سیستم بررسی سلامت و جابجایی خودکار
 * - بررسی اعتبار IP با Scamalytics
 * - RASPS (نظرسنجی هوشمند تطبیقی واکنش‌پذیر)
 * - تشخیص کامل موقعیت جغرافیایی
 * - یکپارچه‌سازی پایگاه داده D1
 * - هدرهای امنیتی کامل و حفاظت CSRF
 * 
 * آخرین به‌روزرسانی: دسامبر 2025
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// بخش تنظیمات
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

    // بررسی سلامت و جابجایی خودکار از پایگاه داده
    if (env.DB) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
        ).all();
        selectedProxyIP = results[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log(`✓ استفاده از بهترین پروکسی سالم از پایگاه داده: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`خطا در خواندن سلامت پروکسی از پایگاه داده: ${e.message}`);
      }
    }

    // بازگشت به متغیر محیطی
    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`✓ استفاده از پروکسی از env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    // بازگشت نهایی به لیست ثابت
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`✓ استفاده از پروکسی از لیست تنظیمات: ${selectedProxyIP}`);
      }
    }
    
    // بازگشت بحرانی
    if (!selectedProxyIP) {
      console.error('بحرانی: هیچ آدرس IP پروکسی در دسترس نیست');
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
// ثابت‌ها - ترکیب تمام ثابت‌ها
// ============================================================================

const CONST = {
  // ثابت‌های پروتکل
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  
  // ثابت‌های پنل ادمین
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  
  // ثابت‌های امنیتی
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  
  // ثابت‌های به‌روزرسانی خودکار
  AUTO_REFRESH_INTERVAL: 60000, // 1 دقیقه
  
  // ثابت‌های نگهداری پایگاه داده
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000, // 5 دقیقه
  HEALTH_CHECK_TIMEOUT: 5000,
};

// ============================================================================
// توابع امنیتی و کمکی اصلی
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
  headers.set('alt-svc', 'h3=":443"; ma=0');
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
    return btoa(binary);
  } catch (e) {
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

// ============================================================================
// توابع ذخیره‌سازی کلید-مقدار (بر پایه D1)
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.error(`kvGet: پایگاه داده برای کلید ${key} در دسترس نیست`);
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
        console.error(`خطا در تجزیه JSON برای کلید ${key}: ${e}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`خطای kvGet برای ${key}: ${e}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.error(`kvPut: پایگاه داده برای کلید ${key} در دسترس نیست`);
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
    console.error(`خطای kvPut برای ${key}: ${e}`);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.error(`kvDelete: پایگاه داده برای کلید ${key} در دسترس نیست`);
    return;
  }
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`خطای kvDelete برای ${key}: ${e}`);
  }
}

// ============================================================================
// مدیریت داده‌های کاربر - با کش بهبود یافته
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("اتصال D1 موجود نیست");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    // تلاش برای کش اول
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error(`خطا در دریافت داده‌های کش شده برای ${uuid}`, e);
    }

    // دریافت از پایگاه داده
    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    // به‌روزرسانی کش به صورت ناهمگام
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    return userFromDb;
  } catch (e) {
    console.error(`خطای getUserData برای ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: اتصال D1 موجود نیست");
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    // دریافت قفل با زمان‌بندی
    while (!lockAcquired) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
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
    console.error(`خطا در به‌روزرسانی مصرف برای ${uuid}:`, err);
  } finally {
    if (lockAcquired) {
      try {
        await kvDelete(env.DB, usageLockKey);
      } catch (e) {
        console.error(`خطا در آزادسازی قفل برای ${uuid}:`, e);
      }
    }
  }
}

async function cleanupOldIps(env, ctx) {
  if (!env.DB) {
    console.warn('cleanupOldIps: اتصال D1 در دسترس نیست');
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
    console.error(`خطای cleanupOldIps: ${e.message}`);
  }
}

// ============================================================================
// بررسی اعتبار IP با Scamalytics
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️  Scamalytics پیکربندی نشده است. IP ${ip} مجاز است (حالت fail-open).`);
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    
    if (!response.ok) {
      console.warn(`API Scamalytics ${response.status} را برای ${ip} برگرداند. مجاز است (حالت fail-open).`);
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(`Scamalytics برای ${ip} به پایان رسید. مجاز است (حالت fail-open).`);
    } else {
      console.error(`خطای Scamalytics برای ${ip}: ${e.message}. مجاز است (حالت fail-open).`);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// سیستم اعتبارسنجی 2FA (TOTP)
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
    if (charValue === -1) throw new Error('کاراکتر Base32 نامعتبر است');
    
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
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
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
    console.error("خطا در رمزگشایی راز TOTP:", e.message);
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

async function checkRateLimit(db, key, limit, ttl) {
  if (!db) return false;
  try {
    const countStr = await kvGet(db, key);
    const count = parseInt(countStr, 10) || 0;
    if (count >= limit) return true;
    await kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
    return false;
  } catch (e) {
    console.error(`خطای checkRateLimit برای ${key}: ${e}`);
    return false;
  }
}

// ============================================================================
// ابزارهای UUID
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + 
    byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
    byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
    byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('UUID رشته‌ای شده نامعتبر است');
  return uuid;
}

// ============================================================================
// تولید لینک اشتراک
// ============================================================================

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
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

function createVlessLink({
  userID,
  address,
  port,
  host,
  path,
  security,
  sni,
  fp,
  alpn,
  extra = {},
  name,
}) {
  const params = new URLSearchParams({
    encryption: 'none',
    type: 'ws',
    host,
    path,
  });

  if (security) {
    params.set('security', security);
    if (security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === 'tls' ? randomizeCase(hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// ============================================================================
// مدیریت اشتراک
// ============================================================================

async function handleIpSubscription(core, userID, hostName) {
  // ترکیب دامنه‌ها از هر دو اسکریپت
  const mainDomains = [
    hostName,
    'creativecommons.org',
    'www.speedtest.net',
    'sky.rethinkdns.com',
    'cfip.1323123.xyz',
    'go.inmobi.com',
    'www.visa.com',
    'www.wto.org',
    'cf.090227.xyz',
    'cdnjs.com',
    'zula.ir',
    // از اسکریپت دوم:
    'mail.tm',
    'temp-mail.org',
    'ipaddress.my',
    'mdbmax.com',
    'check-host.net',
    'kodambroker.com',
    'iplocation.io',
    'whatismyip.org',
    'www.linkedin.com',
    'exir.io',
    'arzex.io',
    'ok-ex.io',
    'arzdigital.com',
    'pouyanit.com',
    'auth.grok.com',
    'grok.com',
    'maxmind.com',
    'whatsmyip.com',
    'iplocation.net',
    'ipchicken.com',
    'showmyip.com',
    'router-network.com',
    'whatismyipaddress.com',
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  // تولید کانفیگ‌های مبتنی بر دامنه
  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: 'tls',
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `D${i + 1}`,
      }),
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core,
          proto: 'tcp',
          userID,
          hostName,
          address: domain,
          port: pick(httpPorts),
          tag: `D${i + 1}`,
        }),
      );
    }
  });

  // دریافت آدرس‌های IP Cloudflare
  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
    );
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 20).map((x) => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(
          buildLink({
            core,
            proto: 'tls',
            userID,
            hostName,
            address: formattedAddress,
            port: pick(httpsPorts),
            tag: `IP${i + 1}`,
          }),
        );

        if (!isPagesDeployment) {
          links.push(
            buildLink({
              core,
              proto: 'tcp',
              userID,
              hostName,
              address: formattedAddress,
              port: pick(httpPorts),
              tag: `IP${i + 1}`,
            }),
          );
        }
      });
    }
  } catch (e) {
    console.error('دریافت لیست IP ناموفق بود', e);
  }

  const headers = new Headers({ 
    'Content-Type': 'text/plain;charset=utf-8',
    'Profile-Update-Interval': '6',
  });
  addSecurityHeaders(headers, null, {});

  return new Response(safeBase64Encode(links.join('\n')), { headers });
}

// ============================================================================
// مقداردهی اولیه پایگاه داده
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) {
    console.warn('ensureTablesExist: اتصال D1 در دسترس نیست');
    return;
  }
  
  try {
    const createTables = [
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
        PRIMARY KEY (uuid, ip),
        FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE
      )`,
      `CREATE TABLE IF NOT EXISTS key_value (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expiration INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS proxy_health (
        ip_port TEXT PRIMARY KEY,
        is_healthy INTEGER NOT NULL,
        latency_ms INTEGER,
        last_check INTEGER DEFAULT (strftime('%s', 'now'))
      )`
    ];
    
    const stmts = createTables.map(sql => env.DB.prepare(sql));
    await env.DB.batch(stmts);
    
    // درج کاربر تست برای توسعه (با UUID پیش‌فرض از تنظیمات)
    const testUUID = env.UUID || Config.userID;
    const futureDate = new Date();
    futureDate.setMonth(futureDate.getMonth() + 1);
    const expDate = futureDate.toISOString().split('T')[0];
    const expTime = '23:59:59';
    
    try {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(testUUID, expDate, expTime, 'کاربر تست - توسعه', null, 1073741824, -1).run();
    } catch (insertErr) {
      // کاربر ممکن است از قبل وجود داشته باشد - این مشکلی نیست
    }
    
    console.log('✓ جداول D1 با موفقیت مقداردهی اولیه شدند');
  } catch (e) {
    console.error('خطا در ایجاد جداول D1:', e);
  }
}

// ============================================================================
// سیستم بررسی سلامت
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: اتصال D1 در دسترس نیست');
    return;
  }
  
  const proxyIps = env.PROXYIPS 
    ? env.PROXYIPS.split(',').map(ip => ip.trim()) 
    : Config.proxyIPs;
  
  const healthStmts = [];
  
  for (const ipPort of proxyIps) {
    const [host, port = '443'] = ipPort.split(':');
    let latency = null;
    let isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch(`https://${host}:${port}`, { 
        signal: controller.signal,
        method: 'HEAD',
      });
      clearTimeout(timeoutId);
      
      if (response.ok || response.status === 404) {
        latency = Date.now() - start;
        isHealthy = 1;
      }
    } catch (e) {
      console.error(`بررسی سلامت برای ${ipPort} ناموفق بود: ${e.message}`);
    }
    
    healthStmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
      ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
    );
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('✓ بررسی سلامت پروکسی کامل شد');
  } catch (e) {
    console.error(`خطای دسته‌ای performHealthCheck: ${e.message}`);
  }
}

// ============================================================================
// HTML پنل ورود ادمین
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ورود ادمین - VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; margin: 0;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      direction: rtl;
    }
    .login-container {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      text-align: center;
      width: 100%;
      max-width: 400px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    h1 {
      color: #ffffff;
      margin-bottom: 24px;
      font-weight: 600;
      font-size: 28px;
    }
    form { display: flex; flex-direction: column; gap: 16px; }
    input[type="password"], input[type="text"] {
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #ffffff;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      transition: all 0.3s;
    }
    input:focus {
      outline: none;
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
      background: rgba(255, 255, 255, 0.15);
    }
    input::placeholder { color: rgba(255, 255, 255, 0.5); }
    button {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4);
    }
    button:active { transform: translateY(0); }
    .error {
      color: #ff6b6b;
      margin-top: 16px;
      font-size: 14px;
      background: rgba(255, 107, 107, 0.1);
      padding: 12px;
      border-radius: 8px;
      border: 1px solid rgba(255, 107, 107, 0.3);
    }
    @media (max-width: 480px) {
      .login-container { padding: 30px 20px; margin: 20px; }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>🔐 ورود ادمین</h1>
    <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
      <input type="password" name="password" placeholder="رمز عبور ادمین را وارد کنید" required autocomplete="current-password">
      <input type="text" name="totp" placeholder="کد 2FA (در صورت فعال بودن)" autocomplete="off" inputmode="numeric" pattern="[0-9]*" maxlength="6">
      <button type="submit">ورود</button>
    </form>
  </div>
</body>
</html>`;

// ============================================================================
// HTML پنل ادمین
// ============================================================================

const adminPanelHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پنل مدیریت ادمین - VLESS Proxy Manager</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root {
      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;
      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;
      --accent: #3B82F6; --accent-hover: #2563EB;
      --danger: #EF4444; --danger-hover: #DC2626;
      --success: #22C55E; --warning: #F59e0b;
      --btn-secondary-bg: #4B5563; --purple: #a855f7;
      --cyan: #06b6d4; --pink: #ec4899;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @keyframes gradient-flow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    @keyframes float-particles {
      0%, 100% { transform: translateY(0) rotate(0deg); opacity: 0.3; }
      50% { transform: translateY(-20px) rotate(180deg); opacity: 0.8; }
    }
    @keyframes counter-pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    @keyframes title-shimmer {
      0% { background-position: -200% center; }
      100% { background-position: 200% center; }
    }
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #111827 25%, #0d1321 50%, #0a0e17 75%, #111827 100%);
      background-size: 400% 400%;
      animation: gradient-flow 15s ease infinite;
      color: var(--text-primary);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
      direction: rtl;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: 
        radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px;
    }
    h1, h2 { font-weight: 600; }
    h1 {
      font-size: 32px;
      margin-bottom: 28px;
      background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 30%, #06b6d4 60%, #3B82F6 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: title-shimmer 4s linear infinite;
      text-shadow: 0 0 40px rgba(59, 130, 246, 0.3);
    }
    h2 {
      font-size: 18px;
      border-bottom: 2px solid transparent;
      border-image: linear-gradient(90deg, var(--accent), var(--purple), transparent) 1;
      padding-bottom: 12px;
      margin-bottom: 20px;
      position: relative;
    }
    .card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 28px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      box-shadow: 
        0 4px 24px rgba(0,0,0,0.2),
        0 0 0 1px rgba(255, 255, 255, 0.03),
        inset 0 1px 0 rgba(255, 255, 255, 0.05);
      margin-bottom: 24px;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent);
      transition: left 0.6s ease;
    }
    .card:hover::before {
      left: 100%;
    }
    .card:hover {
      box-shadow: 
        0 20px 40px rgba(0,0,0,0.3),
        0 0 80px rgba(59, 130, 246, 0.1),
        inset 0 1px 0 rgba(255, 255, 255, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
      transform: translateY(-4px);
    }
    .dashboard-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 24px 20px;
      border-radius: 16px;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.05);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--purple), var(--cyan));
      opacity: 0;
      transition: opacity 0.3s;
    }
    .stat-card::after {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
      opacity: 0;
      transition: opacity 0.4s;
    }
    .stat-card:hover::before { opacity: 1; }
    .stat-card:hover::after { opacity: 1; }
    .stat-card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 
        0 20px 40px rgba(59, 130, 246, 0.2),
        0 0 0 1px rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .stat-card.healthy { --card-accent: var(--success); }
    .stat-card.warning { --card-accent: var(--warning); }
    .stat-card.danger { --card-accent: var(--danger); }
    .stat-card.healthy::before, .stat-card.warning::before, .stat-card.danger::before {
      background: var(--card-accent);
      opacity: 1;
    }
    .stat-icon {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 12px;
      font-size: 20px;
    }
    .stat-icon.blue { background: rgba(59, 130, 246, 0.15); }
    .stat-icon.green { background: rgba(34, 197, 94, 0.15); }
    .stat-icon.orange { background: rgba(245, 158, 11, 0.15); }
    .stat-icon.purple { background: rgba(168, 85, 247, 0.15); }
    .stat-value {
      font-size: 28px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 6px;
      line-height: 1.2;
    }
    .stat-label {
      font-size: 11px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .stat-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 600;
      margin-top: 8px;
    }
    .stat-badge.online { background: rgba(34, 197, 94, 0.15); color: var(--success); }
    .stat-badge.offline { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
    .stat-badge.checking { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      align-items: flex-end;
    }
    .form-group {
      display: flex;
      flex-direction: column;
    }
    .form-group label {
      margin-bottom: 8px;
      font-weight: 500;
      color: var(--text-secondary);
      font-size: 13px;
    }
    input[type="text"], input[type="date"], input[type="time"], 
    input[type="number"], select {
      width: 100%;
      background: #374151;
      border: 1px solid #4B5563;
      color: var(--text-primary);
      padding: 12px;
      border-radius: 8px;
      font-size: 14px;
      transition: all 0.2s;
    }
    input:focus, select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    .btn {
      padding: 12px 22px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 14px;
      position: relative;
      overflow: hidden;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn:hover::before { left: 100%; }
    .btn:active { transform: scale(0.96); }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%);
      background-size: 200% 200%;
      color: white;
      box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:hover {
      background-position: 100% 50%;
      box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
      transform: translateY(-3px);
    }
    .btn-secondary {
      background: linear-gradient(135deg, #4B5563 0%, #374151 100%);
      color: white;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .btn-secondary:hover { 
      background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .btn-danger {
      background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
      color: white;
      box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
    }
    .btn-danger:hover {
      box-shadow: 0 8px 25px rgba(239, 68, 68, 0.5);
      transform: translateY(-3px);
    }
    .table-wrapper {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      border-radius: 10px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 14px 16px;
      text-align: right;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    th {
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: rgba(59, 130, 246, 0.08);
      position: sticky;
      top: 0;
      backdrop-filter: blur(8px);
    }
    td {
      color: var(--text-primary);
      font-size: 13px;
      transition: background 0.2s;
    }
    tbody tr {
      transition: all 0.2s ease;
    }
    tbody tr:hover {
      background: rgba(59, 130, 246, 0.08);
    }
    tbody tr:hover td {
      color: #fff;
    }
    tbody tr:last-child td {
      border-bottom: none;
    }
    .status-badge {
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      display: inline-block;
    }
    .status-active {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
      border: 1px solid var(--success);
    }
    .status-expired {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }
    .uuid-cell {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .btn-copy-uuid {
      padding: 4px 8px;
      font-size: 11px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: var(--accent);
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy-uuid:hover {
      background: rgba(59, 130, 246, 0.2);
      border-color: var(--accent);
    }
    .btn-copy-uuid.copied {
      background: rgba(34, 197, 94, 0.2);
      border-color: var(--success);
      color: var(--success);
    }
    #toast {
      position: fixed;
      top: 20px;
      left: 20px;
      background: rgba(31, 41, 55, 0.95);
      backdrop-filter: blur(12px);
      color: white;
      padding: 16px 20px;
      border-radius: 12px;
      z-index: 1001;
      display: none;
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 12px 32px rgba(0,0,0,0.4);
      animation: slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      min-width: 280px;
      max-width: 400px;
    }
    .toast-content {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .toast-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      flex-shrink: 0;
    }
    .toast-icon.success { background: rgba(34, 197, 94, 0.15); }
    .toast-icon.error { background: rgba(239, 68, 68, 0.15); }
    .toast-icon.warning { background: rgba(245, 158, 11, 0.15); }
    .toast-icon.info { background: rgba(59, 130, 246, 0.15); }
    .toast-message { flex: 1; font-size: 14px; line-height: 1.4; }
    @keyframes slideIn {
      from { transform: translateX(-120%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(-120%); opacity: 0; }
    }
    #toast.show { display: block; }
    #toast.hide { animation: slideOut 0.3s ease forwards; }
    #toast.success { border-right: 4px solid var(--success); }
    #toast.error { border-right: 4px solid var(--danger); }
    #toast.warning { border-right: 4px solid var(--warning); }
    #toast.info { border-right: 4px solid var(--accent); }
    .btn.loading {
      pointer-events: none;
      opacity: 0.7;
      position: relative;
    }
    .btn.loading::after {
      content: '';
      position: absolute;
      width: 16px;
      height: 16px;
      border: 2px solid transparent;
      border-top-color: currentColor;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      left: 12px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      animation: pulse 2s ease-in-out infinite;
    }
    .pulse-dot.green { background: var(--success); box-shadow: 0 0 8px var(--success); }
    .pulse-dot.red { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
    .pulse-dot.orange { background: var(--warning); box-shadow: 0 0 8px var(--warning); }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.8); }
    }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: center;
      opacity: 0;
      visibility: hidden;
      transition: all 0.3s;
    }
    .modal-overlay.show {
      opacity: 1;
      visibility: visible;
    }
    .modal-content {
      background: var(--bg-card);
      padding: 32px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
      border: 1px solid var(--border);
      transform: scale(0.9);
      transition: transform 0.3s;
    }
    .modal-overlay.show .modal-content {
      transform: scale(1);
    }
    .search-input {
      width: 100%;
      margin-bottom: 16px;
      padding: 12px 16px;
      background: #374151;
      border: 1px solid #4B5563;
      color: var(--text-primary);
      border-radius: 8px;
      font-size: 14px;
    }
    .time-quick-set-group {
      display: flex;
      gap: 8px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    .btn-outline-secondary {
      background: transparent;
      border: 1px solid var(--btn-secondary-bg);
      color: var(--text-secondary);
      padding: 6px 12px;
      font-size: 12px;
    }
    .btn-outline-secondary:hover {
      background: var(--btn-secondary-bg);
      color: white;
    }
    @media (max-width: 768px) {
      .container { padding: 20px 12px; }
      .dashboard-stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
      .form-grid { grid-template-columns: 1fr; }
      h1 { font-size: 24px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚡ پنل مدیریت ادمین</h1>
    <div style="position: absolute; top: 20px; left: 20px; display: flex; gap: 12px;">
      <button id="healthCheckBtn" class="btn btn-secondary">🔄 بررسی سلامت</button>
      <button id="logoutBtn" class="btn btn-danger">🚪 خروج</button>
    </div>

    <div class="dashboard-stats">
      <div class="stat-card">
        <div class="stat-icon blue">👥</div>
        <div class="stat-value" id="total-users">0</div>
        <div class="stat-label">کل کاربران</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">✓</div>
        <div class="stat-value" style="color: var(--success);" id="active-users">0</div>
        <div class="stat-label">کاربران فعال</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon orange">⏱</div>
        <div class="stat-value" style="color: var(--warning);" id="expired-users">0</div>
        <div class="stat-label">کاربران منقضی شده</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">📊</div>
        <div class="stat-value" id="total-traffic">0 KB</div>
        <div class="stat-label">کل ترافیک</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon blue">🕐</div>
        <div class="stat-value" style="font-size:16px;" id="server-time">--:--:--</div>
        <div class="stat-label">زمان سرور</div>
      </div>
      <div class="stat-card" id="proxy-health-card">
        <div class="stat-icon green">💚</div>
        <div class="stat-value" style="font-size: 22px;" id="proxy-health">بررسی...</div>
        <div class="stat-label">سلامت پروکسی</div>
        <div class="stat-badge checking" id="proxy-health-badge"><span class="pulse-dot orange"></span> در حال بررسی</div>
      </div>
      <div class="stat-card" id="server-status-card">
        <div class="stat-icon blue">🖥</div>
        <div class="stat-value" style="font-size: 22px;" id="server-status">آنلاین</div>
        <div class="stat-label">وضعیت سرور</div>
        <div class="stat-badge online" id="server-status-badge"><span class="pulse-dot green"></span> عملیاتی</div>
      </div>
    </div>

    <div class="card">
      <h2>➕ ایجاد کاربر جدید</h2>
      <form id="createUserForm" class="form-grid">
        <div class="form-group" style="grid-column: 1 / -1;">
          <label for="uuid">UUID</label>
          <div style="display: flex; gap: 8px;">
            <input type="text" id="uuid" required style="flex: 1;">
            <button type="button" id="generateUUID" class="btn btn-secondary">🎲 تولید</button>
          </div>
        </div>
        <div class="form-group">
          <label for="expiryDate">تاریخ انقضا</label>
          <input type="date" id="expiryDate" required>
        </div>
        <div class="form-group">
          <label for="expiryTime">زمان انقضا</label>
          <input type="time" id="expiryTime" required>
        </div>
        <div class="form-group">
          <label for="trafficLimit">محدودیت ترافیک (GB)</label>
          <input type="number" id="trafficLimit" min="0" step="0.1">
        </div>
        <div class="form-group">
          <label for="ipLimit">محدودیت IP</label>
          <input type="number" id="ipLimit" min="-1" value="-1">
        </div>
        <div class="form-group" style="grid-column: 1 / -1;">
          <label for="notes">یادداشت‌ها</label>
          <input type="text" id="notes">
        </div>
        <div class="form-group" style="grid-column: 1 / -1;">
          <button type="submit" class="btn btn-primary">✨ ایجاد کاربر</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>👥 مدیریت کاربران</h2>
      <input type="text" id="userSearch" class="search-input" placeholder="جستجوی کاربر بر اساس UUID یا یادداشت...">
      <div class="table-wrapper">
        <table id="usersTable">
          <thead>
            <tr>
              <th>UUID</th>
              <th>تاریخ انقضا</th>
              <th>ترافیک استفاده شده</th>
              <th>محدودیت ترافیک</th>
              <th>محدودیت IP</th>
              <th>یادداشت‌ها</th>
              <th>وضعیت</th>
              <th>عملیات</th>
            </tr>
          </thead>
          <tbody id="usersTableBody">
            <!-- کاربران به صورت پویا اضافه خواهند شد -->
          </tbody>
        </table>
      </div>
      <div style="margin-top: 16px; display: flex; gap: 8px; justify-content: flex-end;">
        <button id="refreshUsersBtn" class="btn btn-secondary">🔄 به‌روزرسانی</button>
        <button id="deleteSelectedBtn" class="btn btn-danger">🗑️ حذف انتخاب شده‌ها</button>
      </div>
    </div>
  </div>

  <div id="toast">
    <div class="toast-content">
      <div class="toast-icon" id="toast-icon"></div>
      <div class="toast-message" id="toast-message"></div>
    </div>
  </div>

  <script nonce="CSP_NONCE_PLACEHOLDER">
    // توابع کمکی
    function showToast(message, type = 'info') {
      const toast = document.getElementById('toast');
      const toastIcon = document.getElementById('toast-icon');
      const toastMessage = document.getElementById('toast-message');
      
      toast.className = 'toast ' + type;
      toastMessage.textContent = message;
      
      // تنظیم آیکون بر اساس نوع
      toastIcon.innerHTML = type === 'success' ? '✓' : 
                            type === 'error' ? '✕' : 
                            type === 'warning' ? '⚠' : 'ℹ';
      
      toast.classList.add('show');
      
      setTimeout(() => {
        toast.classList.remove('show');
        toast.classList.add('hide');
        setTimeout(() => {
          toast.classList.remove('hide');
        }, 300);
      }, 3000);
    }
    
    function formatBytes(bytes) {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function generateUUID() {
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    }
    
    // به‌روزرسانی زمان سرور
    function updateServerTime() {
      const now = new Date();
      const timeString = now.toLocaleTimeString('fa-IR', { hour12: false });
      document.getElementById('server-time').textContent = timeString;
    }
    
    setInterval(updateServerTime, 1000);
    updateServerTime();
    
    // تولید UUID
    document.getElementById('generateUUID').addEventListener('click', () => {
      document.getElementById('uuid').value = generateUUID();
    });
    
    // تنظیم زمان‌های سریع برای انقضا
    const expiryTimeInput = document.getElementById('expiryTime');
    const quickTimeButtons = document.createElement('div');
    quickTimeButtons.className = 'time-quick-set-group';
    
    const quickTimes = [
      { label: 'انتهای روز', time: '23:59:59' },
      { label: 'ظهر', time: '12:00:00' },
      { label: 'نیمه‌شب', time: '00:00:00' }
    ];
    
    quickTimes.forEach(({ label, time }) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn-outline-secondary';
      btn.textContent = label;
      btn.addEventListener('click', () => {
        expiryTimeInput.value = time;
      });
      quickTimeButtons.appendChild(btn);
    });
    
    expiryTimeInput.parentNode.appendChild(quickTimeButtons);
    
    // تاریخ پیش‌فرض برای انقضا (یک ماه دیگر)
    const expiryDateInput = document.getElementById('expiryDate');
    const futureDate = new Date();
    futureDate.setMonth(futureDate.getMonth() + 1);
    expiryDateInput.value = futureDate.toISOString().split('T')[0];
    expiryTimeInput.value = '23:59:59';
    
    // ارسال فرم ایجاد کاربر
    document.getElementById('createUserForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const submitBtn = e.target.querySelector('button[type="submit"]');
      submitBtn.classList.add('loading');
      submitBtn.disabled = true;
      
      const formData = {
        uuid: document.getElementById('uuid').value,
        expiryDate: document.getElementById('expiryDate').value,
        expiryTime: document.getElementById('expiryTime').value,
        trafficLimit: document.getElementById('trafficLimit').value ? 
                      parseFloat(document.getElementById('trafficLimit').value) * 1024 * 1024 * 1024 : null,
        ipLimit: parseInt(document.getElementById('ipLimit').value),
        notes: document.getElementById('notes').value
      };
      
      try {
        const response = await fetch('/admin/api/users', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(formData)
        });
        
        if (response.ok) {
          showToast('کاربر با موفقیت ایجاد شد', 'success');
          e.target.reset();
          
          // تنظیم مجدد مقادیر پیش‌فرض
          const newFutureDate = new Date();
          newFutureDate.setMonth(newFutureDate.getMonth() + 1);
          expiryDateInput.value = newFutureDate.toISOString().split('T')[0];
          expiryTimeInput.value = '23:59:59';
          document.getElementById('ipLimit').value = '-1';
          
          // به‌روزرسانی جدول کاربران
          loadUsers();
        } else {
          const error = await response.text();
          showToast(`خطا: ${error}`, 'error');
        }
      } catch (err) {
        showToast(`خطا در ارتباط با سرور: ${err.message}`, 'error');
      } finally {
        submitBtn.classList.remove('loading');
        submitBtn.disabled = false;
      }
    });
    
    // بارگذاری کاربران
    async function loadUsers() {
      try {
        const response = await fetch('/admin/api/users');
        const users = await response.json();
        
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';
        
        users.forEach(user => {
          const row = document.createElement('tr');
          
          const now = new Date();
          const expiryDate = new Date(`${user.expiration_date}T${user.expiration_time}`);
          const isExpired = expiryDate <= now;
          
          row.innerHTML = \`
            <td>
              <div class="uuid-cell">
                <span>\${user.uuid.substring(0, 8)}...</span>
                <button class="btn-copy-uuid" data-uuid="\${user.uuid}">کپی</button>
              </div>
            </td>
            <td>\${user.expiration_date} \${user.expiration_time}</td>
            <td>\${formatBytes(user.traffic_used || 0)}</td>
            <td>\${user.traffic_limit ? formatBytes(user.traffic_limit) : 'نامحدود'}</td>
            <td>\${user.ip_limit === -1 ? 'نامحدود' : user.ip_limit}</td>
            <td>\${user.notes || '-'}</td>
            <td>
              <span class="status-badge \${isExpired ? 'status-expired' : 'status-active'}">
                \${isExpired ? 'منقضی شده' : 'فعال'}
              </span>
            </td>
            <td>
              <input type="checkbox" class="user-checkbox" data-uuid="\${user.uuid}">
            </td>
          \`;
          
          tbody.appendChild(row);
        });
        
        // اضافه کردن رویداد به دکمه‌های کپی UUID
        document.querySelectorAll('.btn-copy-uuid').forEach(btn => {
          btn.addEventListener('click', (e) => {
            const uuid = e.target.getAttribute('data-uuid');
            navigator.clipboard.writeText(uuid).then(() => {
              e.target.textContent = 'کپی شد!';
              e.target.classList.add('copied');
              setTimeout(() => {
                e.target.textContent = 'کپی';
                e.target.classList.remove('copied');
              }, 2000);
            });
          });
        });
        
        // به‌روزرسانی آمار
        document.getElementById('total-users').textContent = users.length;
        document.getElementById('active-users').textContent = users.filter(u => {
          const expiryDate = new Date(\`\${u.expiration_date}T\${u.expiration_time}\`);
          return expiryDate > new Date();
        }).length;
        document.getElementById('expired-users').textContent = users.filter(u => {
          const expiryDate = new Date(\`\${u.expiration_date}T\${u.expiration_time}\`);
          return expiryDate <= new Date();
        }).length;
        
        const totalTraffic = users.reduce((sum, u) => sum + (u.traffic_used || 0), 0);
        document.getElementById('total-traffic').textContent = formatBytes(totalTraffic);
        
      } catch (err) {
        showToast(\`خطا در بارگذاری کاربران: \${err.message}\`, 'error');
      }
    }
    
    // بارگذاری اولیه کاربران
    loadUsers();
    
    // دکمه به‌روزرسانی کاربران
    document.getElementById('refreshUsersBtn').addEventListener('click', () => {
      loadUsers();
      showToast('لیست کاربران به‌روزرسانی شد', 'info');
    });
    
    // حذف کاربران انتخاب شده
    document.getElementById('deleteSelectedBtn').addEventListener('click', async () => {
      const checkboxes = document.querySelectorAll('.user-checkbox:checked');
      if (checkboxes.length === 0) {
        showToast('هیچ کاربری انتخاب نشده است', 'warning');
        return;
      }
      
      if (!confirm(\`آیا از حذف \${checkboxes.length} کاربر اطمینان دارید؟\`)) {
        return;
      }
      
      const uuids = Array.from(checkboxes).map(cb => cb.getAttribute('data-uuid'));
      
      try {
        const response = await fetch('/admin/api/users', {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ uuids })
        });
        
        if (response.ok) {
          showToast(\`\${checkboxes.length} کاربر با موفقیت حذف شدند\`, 'success');
          loadUsers();
        } else {
          const error = await response.text();
          showToast(\`خطا: \${error}\`, 'error');
        }
      } catch (err) {
        showToast(\`خطا در ارتباط با سرور: \${err.message}\`, 'error');
      }
    });
    
    // جستجوی کاربران
    document.getElementById('userSearch').addEventListener('input', (e) => {
      const searchTerm = e.target.value.toLowerCase();
      const rows = document.querySelectorAll('#usersTableBody tr');
      
      rows.forEach(row => {
        const uuid = row.querySelector('.uuid-cell span').textContent.toLowerCase();
        const notes = row.querySelector('td:nth-child(6)').textContent.toLowerCase();
        
        if (uuid.includes(searchTerm) || notes.includes(searchTerm)) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });
    
    // بررسی سلامت پروکسی
    document.getElementById('healthCheckBtn').addEventListener('click', async () => {
      const healthCard = document.getElementById('proxy-health-card');
      const healthText = document.getElementById('proxy-health');
      const healthBadge = document.getElementById('proxy-health-badge');
      
      healthText.textContent = 'در حال بررسی...';
      healthBadge.className = 'stat-badge checking';
      healthBadge.innerHTML = '<span class="pulse-dot orange"></span> در حال بررسی';
      
      try {
        const response = await fetch('/admin/api/health-check');
        const result = await response.json();
        
        if (result.success) {
          healthText.textContent = 'سالم';
          healthBadge.className = 'stat-badge online';
          healthBadge.innerHTML = '<span class="pulse-dot green"></span> سالم';
          healthCard.className = 'stat-card healthy';
          showToast('بررسی سلامت با موفقیت انجام شد', 'success');
        } else {
          healthText.textContent = 'ناسالم';
          healthBadge.className = 'stat-badge offline';
          healthBadge.innerHTML = '<span class="pulse-dot red"></span> ناسالم';
          healthCard.className = 'stat-card danger';
          showToast('مشکلی در پروکسی شناسایی شد', 'warning');
        }
      } catch (err) {
        healthText.textContent = 'خطا';
        healthBadge.className = 'stat-badge offline';
        healthBadge.innerHTML = '<span class="pulse-dot red"></span> خطا';
        healthCard.className = 'stat-card danger';
        showToast(\`خطا در بررسی سلامت: \${err.message}\`, 'error');
      }
    });
    
    // خروج از پنل ادمین
    document.getElementById('logoutBtn').addEventListener('click', () => {
      if (confirm('آیا از خروج اطمینان دارید؟')) {
        window.location.href = '/admin/logout';
      }
    });
    
    // بررسی سلامت خودکار
    setInterval(async () => {
      try {
        const response = await fetch('/admin/api/health-status');
        const result = await response.json();
        
        const healthText = document.getElementById('proxy-health');
        const healthBadge = document.getElementById('proxy-health-badge');
        const healthCard = document.getElementById('proxy-health-card');
        
        if (result.healthy) {
          healthText.textContent = 'سالم';
          healthBadge.className = 'stat-badge online';
          healthBadge.innerHTML = '<span class="pulse-dot green"></span> سالم';
          healthCard.className = 'stat-card healthy';
        } else {
          healthText.textContent = 'ناسالم';
          healthBadge.className = 'stat-badge offline';
          healthBadge.innerHTML = '<span class="pulse-dot red"></span> ناسالم';
          healthCard.className = 'stat-card danger';
        }
      } catch (err) {
        // نادیده گرفتن خطا در بررسی خودکار
      }
    }, 60000); // هر دقیقه یک بار
  </script>
</body>
</html>`;

// ============================================================================
// HTML پنل کاربری
// ============================================================================

const userPanelHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پنل کاربری - VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root {
      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;
      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;
      --accent: #3B82F6; --accent-hover: #2563EB;
      --danger: #EF4444; --danger-hover: #DC2626;
      --success: #22C55E; --warning: #F59e0b;
      --btn-secondary-bg: #4B5563; --purple: #a855f7;
      --cyan: #06b6d4; --pink: #ec4899;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @keyframes gradient-flow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    @keyframes title-shimmer {
      0% { background-position: -200% center; }
      100% { background-position: 200% center; }
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.7; transform: scale(0.95); }
    }
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #111827 25%, #0d1321 50%, #0a0e17 75%, #111827 100%);
      background-size: 400% 400%;
      animation: gradient-flow 15s ease infinite;
      color: var(--text-primary);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
      direction: rtl;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: 
        radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px 20px;
    }
    h1, h2 { font-weight: 600; }
    h1 {
      font-size: 32px;
      margin-bottom: 28px;
      background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 30%, #06b6d4 60%, #3B82F6 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: title-shimmer 4s linear infinite;
      text-shadow: 0 0 40px rgba(59, 130, 246, 0.3);
    }
    h2 {
      font-size: 18px;
      border-bottom: 2px solid transparent;
      border-image: linear-gradient(90deg, var(--accent), var(--purple), transparent) 1;
      padding-bottom: 12px;
      margin-bottom: 20px;
      position: relative;
    }
    .card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 28px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      box-shadow: 
        0 4px 24px rgba(0,0,0,0.2),
        0 0 0 1px rgba(255, 255, 255, 0.03),
        inset 0 1px 0 rgba(255, 255, 255, 0.05);
      margin-bottom: 24px;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent);
      transition: left 0.6s ease;
    }
    .card:hover::before {
      left: 100%;
    }
    .card:hover {
      box-shadow: 
        0 20px 40px rgba(0,0,0,0.3),
        0 0 80px rgba(59, 130, 246, 0.1),
        inset 0 1px 0 rgba(255, 255, 255, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
      transform: translateY(-4px);
    }
    .user-info {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .info-card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 20px;
      border-radius: 16px;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.05);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .info-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--purple), var(--cyan));
      opacity: 0;
      transition: opacity 0.3s;
    }
    .info-card:hover::before { opacity: 1; }
    .info-card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 
        0 20px 40px rgba(59, 130, 246, 0.2),
        0 0 0 1px rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .info-icon {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 12px;
      font-size: 20px;
    }
    .info-icon.blue { background: rgba(59, 130, 246, 0.15); }
    .info-icon.green { background: rgba(34, 197, 94, 0.15); }
    .info-icon.orange { background: rgba(245, 158, 11, 0.15); }
    .info-icon.purple { background: rgba(168, 85, 247, 0.15); }
    .info-value {
      font-size: 20px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 6px;
      line-height: 1.2;
    }
    .info-label {
      font-size: 11px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .subscription-section {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 20px;
    }
    .btn {
      padding: 12px 22px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 14px;
      position: relative;
      overflow: hidden;
      margin: 5px;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn:hover::before { left: 100%; }
    .btn:active { transform: scale(0.96); }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%);
      background-size: 200% 200%;
      color: white;
      box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:hover {
      background-position: 100% 50%;
      box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
      transform: translateY(-3px);
    }
    .btn-secondary {
      background: linear-gradient(135deg, #4B5563 0%, #374151 100%);
      color: white;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .btn-secondary:hover { 
      background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .btn-success {
      background: linear-gradient(135deg, var(--success) 0%, #16a34a 100%);
      color: white;
      box-shadow: 0 4px 15px rgba(34, 197, 94, 0.3);
    }
    .btn-success:hover {
      box-shadow: 0 8px 25px rgba(34, 197, 94, 0.5);
      transform: translateY(-3px);
    }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: center;
      opacity: 0;
      visibility: hidden;
      transition: all 0.3s;
    }
    .modal-overlay.show {
      opacity: 1;
      visibility: visible;
    }
    .modal-content {
      background: var(--bg-card);
      padding: 32px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
      border: 1px solid var(--border);
      transform: scale(0.9);
      transition: transform 0.3s;
      position: relative;
    }
    .modal-overlay.show .modal-content {
      transform: scale(1);
    }
    .modal-close {
      position: absolute;
      top: 16px;
      left: 16px;
      background: rgba(255,255,255,0.1);
      border: none;
      color: white;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.2s;
    }
    .modal-close:hover {
      background: rgba(255,255,255,0.2);
      transform: rotate(90deg);
    }
    .qr-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      margin: 20px 0;
    }
    .qr-code {
      background: white;
      padding: 20px;
      border-radius: 16px;
      margin-bottom: 20px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    }
    .qr-code img {
      display: block;
      max-width: 100%;
      height: auto;
    }
    .config-link {
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 8px;
      padding: 12px 16px;
      font-family: monospace;
      font-size: 12px;
      word-break: break-all;
      margin-bottom: 16px;
      width: 100%;
      color: var(--text-primary);
    }
    .copy-btn {
      background: var(--accent);
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      margin-top: 8px;
      transition: all 0.2s;
    }
    .copy-btn:hover {
      background: var(--accent-hover);
    }
    .copy-btn.copied {
      background: var(--success);
    }
    .tabs {
      display: flex;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }
    .tab {
      padding: 12px 20px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
      font-weight: 500;
    }
    .tab.active {
      border-bottom-color: var(--accent);
      color: var(--accent);
    }
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }
    .progress-bar {
      width: 100%;
      height: 8px;
      background: rgba(255,255,255,0.1);
      border-radius: 4px;
      overflow: hidden;
      margin: 10px 0;
    }
    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--accent), var(--purple));
      border-radius: 4px;
      transition: width 0.5s ease;
    }
    .status-badge {
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      display: inline-block;
    }
    .status-active {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
      border: 1px solid var(--success);
    }
    .status-expired {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }
    .status-warning {
      background: rgba(245, 158, 11, 0.2);
      color: var(--warning);
      border: 1px solid var(--warning);
    }
    .client-buttons {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px;
      margin-top: 20px;
    }
    .client-btn {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
    }
    .client-btn:hover {
      background: rgba(255,255,255,0.1);
      transform: translateY(-2px);
    }
    .client-icon {
      font-size: 24px;
      margin-bottom: 8px;
    }
    .client-name {
      font-weight: 500;
      font-size: 14px;
    }
    @media (max-width: 768px) {
      .container { padding: 20px 12px; }
      .user-info { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
      .subscription-section { grid-template-columns: 1fr; }
      h1 { font-size: 24px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚡ پنل کاربری</h1>
    
    <div class="user-info">
      <div class="info-card">
        <div class="info-icon blue">👤</div>
        <div class="info-value" id="user-uuid">در حال بارگذاری...</div>
        <div class="info-label">شناسه کاربری</div>
      </div>
      <div class="info-card">
        <div class="info-icon green">📅</div>
        <div class="info-value" id="expiry-date">در حال بارگذاری...</div>
        <div class="info-label">تاریخ انقضا</div>
      </div>
      <div class="info-card">
        <div class="info-icon orange">📊</div>
        <div class="info-value" id="traffic-used">در حال بارگذاری...</div>
        <div class="info-label">ترافیک مصرفی</div>
        <div class="progress-bar">
          <div class="progress-fill" id="traffic-progress" style="width: 0%"></div>
        </div>
      </div>
      <div class="info-card">
        <div class="info-icon purple">📈</div>
        <div class="info-value" id="traffic-limit">در حال بارگذاری...</div>
        <div class="info-label">محدودیت ترافیک</div>
      </div>
      <div class="info-card">
        <div class="info-icon blue">🌐</div>
        <div class="info-value" id="ip-count">در حال بارگذاری...</div>
        <div class="info-label">تعداد IP متصل</div>
      </div>
      <div class="info-card">
        <div class="info-icon green">✓</div>
        <div class="info-value" id="user-status">در حال بارگذاری...</div>
        <div class="info-label">وضعیت حساب</div>
      </div>
    </div>
    
    <div class="card">
      <h2>📱 اشتراک و کانفیگ</h2>
      <div class="tabs">
        <div class="tab active" data-tab="xray">Xray / V2Ray</div>
        <div class="tab" data-tab="singbox">Sing-Box / Clash</div>
        <div class="tab" data-tab="import">واردات سریع</div>
      </div>
      
      <div class="tab-content active" id="xray-tab">
        <div class="subscription-section">
          <div>
            <h3>اشتراک Xray / V2Ray</h3>
            <p>کپی URL اشتراک یا واردات مستقیم.</p>
            <div style="margin-top: 16px;">
              <button class="btn btn-primary" id="xray-sub-copy">📋 کپی لینک اشتراک</button>
              <button class="btn btn-secondary" id="xray-config-view">📋 مشاهده کانفیگ</button>
              <button class="btn btn-success" id="xray-qr-show">📱 کد QR</button>
            </div>
          </div>
        </div>
      </div>
      
      <div class="tab-content" id="singbox-tab">
        <div class="subscription-section">
          <div>
            <h3>اشتراک Sing-Box / Clash</h3>
            <p>کپی URL اشتراک یا واردات مستقیم.</p>
            <div style="margin-top: 16px;">
              <button class="btn btn-primary" id="singbox-sub-copy">📋 کپی لینک اشتراک</button>
              <button class="btn btn-secondary" id="singbox-config-view">📋 مشاهده کانفیگ</button>
              <button class="btn btn-success" id="singbox-qr-show">📱 کد QR</button>
            </div>
          </div>
        </div>
      </div>
      
      <div class="tab-content" id="import-tab">
        <div class="subscription-section">
          <div>
            <h3>واردات سریع</h3>
            <p>برنامه‌های پیشنهادی برای واردات سریع کانفیگ.</p>
            <div class="client-buttons">
              <div class="client-btn" data-client="v2rayng">
                <div class="client-icon">🤖</div>
                <div class="client-name">Android (V2rayNG)</div>
              </div>
              <div class="client-btn" data-client="shadowrocket">
                <div class="client-icon">🍎</div>
                <div class="client-name">iOS (Shadowrocket)</div>
              </div>
              <div class="client-btn" data-client="streisand">
                <div class="client-icon">🍎</div>
                <div class="client-name">iOS Streisand</div>
              </div>
              <div class="client-btn" data-client="karing">
                <div class="client-icon">🔧</div>
                <div class="client-name">Karing</div>
              </div>
              <div class="client-btn" data-client="clashmeta">
                <div class="client-icon">🌐</div>
                <div class="client-name">Clash Meta</div>
              </div>
              <div class="client-btn" data-client="exclave">
                <div class="client-icon">📦</div>
                <div class="client-name">Exclave</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <!-- مودال QR Code -->
  <div class="modal-overlay" id="qr-modal">
    <div class="modal-content">
      <button class="modal-close" id="qr-modal-close">✕</button>
      <h2 style="margin-bottom: 20px; text-align: center;">کد QR کانفیگ</h2>
      <div class="qr-container">
        <div class="qr-code" id="qr-code-image">
          <!-- کد QR اینجا قرار می‌گیرد -->
        </div>
        <div class="config-link" id="qr-config-link">
          <!-- لینک کانفیگ اینجا قرار می‌گیرد -->
        </div>
        <button class="copy-btn" id="qr-copy-link">کپی لینک</button>
        <button class="copy-btn" id="qr-download">دانلود QR Code</button>
      </div>
    </div>
  </div>
  
  <!-- مودال مشاهده کانفیگ -->
  <div class="modal-overlay" id="config-modal">
    <div class="modal-content">
      <button class="modal-close" id="config-modal-close">✕</button>
      <h2 style="margin-bottom: 20px; text-align: center;">کانفیگ</h2>
      <div class="config-link" id="config-content" style="max-height: 400px; overflow-y: auto;">
        <!-- محتوای کانفیگ اینجا قرار می‌گیرد -->
      </div>
      <button class="copy-btn" id="config-copy">کپی کانفیگ</button>
    </div>
  </div>
  
  <script nonce="CSP_NONCE_PLACEHOLDER">
    // متغیرهای سراسری
    let userData = null;
    let currentQRType = 'xray'; // xray یا singbox
    
    // توابع کمکی
    function formatBytes(bytes) {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function showToast(message, type = 'info') {
      // ایجاد یک toast ساده
      const toast = document.createElement('div');
      toast.style.cssText = \`
        position: fixed;
        top: 20px;
        left: 20px;
        background: \${type === 'success' ? 'rgba(34, 197, 94, 0.9)' : 
                  type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 
                  'rgba(59, 130, 246, 0.9)'};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        z-index: 2000;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        font-size: 14px;
        max-width: 300px;
        transform: translateX(-120%);
        transition: transform 0.3s ease;
      \`;
      toast.textContent = message;
      document.body.appendChild(toast);
      
      // انیمیشن نمایش
      setTimeout(() => {
        toast.style.transform = 'translateX(0)';
      }, 10);
      
      // حذف پس از 3 ثانیه
      setTimeout(() => {
        toast.style.transform = 'translateX(-120%)';
        setTimeout(() => {
          document.body.removeChild(toast);
        }, 300);
      }, 3000);
    }
    
    // بارگذاری اطلاعات کاربر
    async function loadUserData() {
      try {
        const uuid = window.location.pathname.substring(1); // UUID از URL
        const response = await fetch(\`/api/user/\${uuid}\`);
        
        if (!response.ok) {
          throw new Error('خطا در دریافت اطلاعات کاربر');
        }
        
        userData = await response.json();
        
        // به‌روزرسانی UI
        document.getElementById('user-uuid').textContent = userData.uuid.substring(0, 8) + '...';
        document.getElementById('expiry-date').textContent = \`\${userData.expiration_date} \${userData.expiration_time}\`;
        
        const trafficUsed = userData.traffic_used || 0;
        const trafficLimit = userData.traffic_limit || 0;
        
        document.getElementById('traffic-used').textContent = formatBytes(trafficUsed);
        document.getElementById('traffic-limit').textContent = trafficLimit ? formatBytes(trafficLimit) : 'نامحدود';
        
        // به‌روزرسانی نوار پیشرفت ترافیک
        if (trafficLimit > 0) {
          const percentage = Math.min((trafficUsed / trafficLimit) * 100, 100);
          document.getElementById('traffic-progress').style.width = \`\${percentage}%\`;
        }
        
        document.getElementById('ip-count').textContent = userData.ip_count || 0;
        
        // بررسی وضعیت کاربر
        const now = new Date();
        const expiryDate = new Date(\`\${userData.expiration_date}T\${userData.expiration_time}\`);
        const isExpired = expiryDate <= now;
        const isNearExpiry = !isExpired && (expiryDate - now) / (1000 * 60 * 60 * 24) <= 3; // 3 روز یا کمتر
        
        const statusElement = document.getElementById('user-status');
        if (isExpired) {
          statusElement.textContent = 'منقضی شده';
          statusElement.className = 'info-value';
          statusElement.style.color = 'var(--danger)';
        } else if (isNearExpiry) {
          statusElement.textContent = 'نزدیک به انقضا';
          statusElement.className = 'info-value';
          statusElement.style.color = 'var(--warning)';
        } else {
          statusElement.textContent = 'فعال';
          statusElement.className = 'info-value';
          statusElement.style.color = 'var(--success)';
        }
        
      } catch (error) {
        console.error('خطا در بارگذاری اطلاعات کاربر:', error);
        showToast('خطا در بارگذاری اطلاعات کاربر', 'error');
      }
    }
    
    // تولید QR Code
    async function generateQRCode(configLink) {
      try {
        // استفاده از API خارجی برای تولید QR Code
        const qrApiUrl = \`https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=\${encodeURIComponent(configLink)}\`;
        
        const qrImage = document.createElement('img');
        qrImage.src = qrApiUrl;
        qrImage.alt = 'QR Code';
        
        const qrContainer = document.getElementById('qr-code-image');
        qrContainer.innerHTML = '';
        qrContainer.appendChild(qrImage);
        
        document.getElementById('qr-config-link').textContent = configLink;
        
        return true;
      } catch (error) {
        console.error('خطا در تولید QR Code:', error);
        showToast('خطا در تولید QR Code', 'error');
        return false;
      }
    }
    
    // نمایش مودال QR
    async function showQRModal(type) {
      currentQRType = type;
      
      try {
        const uuid = window.location.pathname.substring(1);
        const response = await fetch(\`/api/config/\${type}/\${uuid}\`);
        
        if (!response.ok) {
          throw new Error('خطا در دریافت کانفیگ');
        }
        
        const configData = await response.json();
        const configLink = configData.link;
        
        if (await generateQRCode(configLink)) {
          document.getElementById('qr-modal').classList.add('show');
        }
      } catch (error) {
        console.error('خطا در نمایش QR Code:', error);
        showToast('خطا در نمایش QR Code', 'error');
      }
    }
    
    // نمایش مودال کانفیگ
    async function showConfigModal(type) {
      try {
        const uuid = window.location.pathname.substring(1);
        const response = await fetch(\`/api/config/\${type}/\${uuid}\`);
        
        if (!response.ok) {
          throw new Error('خطا در دریافت کانفیگ');
        }
        
        const configData = await response.json();
        
        document.getElementById('config-content').textContent = configData.config;
        document.getElementById('config-modal').classList.add('show');
      } catch (error) {
        console.error('خطا در نمایش کانفیگ:', error);
        showToast('خطا در نمایش کانفیگ', 'error');
      }
    }
    
    // کپی لینک اشتراک
    async function copySubscriptionLink(type) {
      try {
        const uuid = window.location.pathname.substring(1);
        const response = await fetch(\`/api/subscription/\${type}/\${uuid}\`);
        
        if (!response.ok) {
          throw new Error('خطا در دریافت لینک اشتراک');
        }
        
        const data = await response.json();
        const subLink = data.link;
        
        await navigator.clipboard.writeText(subLink);
        showToast('لینک اشتراک کپی شد', 'success');
      } catch (error) {
        console.error('خطا در کپی لینک اشتراک:', error);
        showToast('خطا در کپی لینک اشتراک', 'error');
      }
    }
    
    // دانلود QR Code
    function downloadQRCode() {
      const qrImage = document.querySelector('#qr-code-image img');
      if (!qrImage) {
        showToast('QR Code در دسترس نیست', 'error');
        return;
      }
      
      // ایجاد یک لینک دانلود موقت
      const link = document.createElement('a');
      link.href = qrImage.src;
      link.download = \`vless-config-\${currentQRType}.png\`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      showToast('دانلود QR Code آغاز شد', 'success');
    }
    
    // رویدادها
    document.addEventListener('DOMContentLoaded', () => {
      // بارگذاری اطلاعات کاربر
      loadUserData();
      
      // تب‌ها
      document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
          // حذف کلاس active از همه تب‌ها و محتواها
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
          
          // اضافه کردن کلاس active به تب و محتوای مورد نظر
          tab.classList.add('active');
          const tabId = tab.getAttribute('data-tab');
          document.getElementById(\`\${tabId}-tab\`).classList.add('active');
        });
      });
      
      // دکمه‌های Xray
      document.getElementById('xray-sub-copy').addEventListener('click', () => copySubscriptionLink('xray'));
      document.getElementById('xray-config-view').addEventListener('click', () => showConfigModal('xray'));
      document.getElementById('xray-qr-show').addEventListener('click', () => showQRModal('xray'));
      
      // دکمه‌های Sing-Box
      document.getElementById('singbox-sub-copy').addEventListener('click', () => copySubscriptionLink('singbox'));
      document.getElementById('singbox-config-view').addEventListener('click', () => showConfigModal('singbox'));
      document.getElementById('singbox-qr-show').addEventListener('click', () => showQRModal('singbox'));
      
      // دکمه‌های مودال QR
      document.getElementById('qr-modal-close').addEventListener('click', () => {
        document.getElementById('qr-modal').classList.remove('show');
      });
      
      document.getElementById('qr-copy-link').addEventListener('click', () => {
        const linkText = document.getElementById('qr-config-link').textContent;
        navigator.clipboard.writeText(linkText).then(() => {
          showToast('لینک کپی شد', 'success');
        });
      });
      
      document.getElementById('qr-download').addEventListener('click', downloadQRCode);
      
      // دکمه‌های مودال کانفیگ
      document.getElementById('config-modal-close').addEventListener('click', () => {
        document.getElementById('config-modal').classList.remove('show');
      });
      
      document.getElementById('config-copy').addEventListener('click', () => {
        const configText = document.getElementById('config-content').textContent;
        navigator.clipboard.writeText(configText).then(() => {
          showToast('کانفیگ کپی شد', 'success');
        });
      });
      
      // دکمه‌های واردات سریع
      document.querySelectorAll('.client-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const client = btn.getAttribute('data-client');
          
          // پیاده‌سازی برای هر کلاینت
          switch(client) {
            case 'v2rayng':
              showToast('برای V2rayNG، لینک اشتراک را کپی کرده و در برنامه وارد کنید', 'info');
              copySubscriptionLink('xray');
              break;
            case 'shadowrocket':
              showToast('برای Shadowrocket، لینک اشتراک را کپی کرده و در برنامه وارد کنید', 'info');
              copySubscriptionLink('xray');
              break;
            case 'streisand':
              showToast('برای Streisand، لینک اشتراک را کپی کرده و در برنامه وارد کنید', 'info');
              copySubscriptionLink('xray');
              break;
            case 'karing':
              showToast('برای Karing، لینک اشتراک را کپی کرده و در برنامه وارد کنید', 'info');
              copySubscriptionLink('xray');
              break;
            case 'clashmeta':
              showToast('برای Clash Meta، لینک اشتراک Sing-Box را کپی کرده و در برنامه وارد کنید', 'info');
              copySubscriptionLink('singbox');
              break;
            case 'exclave':
              showToast('برای Exclave، لینک اشتراک Sing-Box را کپی کرده و در برنامه وارد کنید', 'info');
              copySubscriptionLink('singbox');
              break;
          }
        });
      });
      
      // بستن مودال با کلیک روی پس‌زمینه
      document.getElementById('qr-modal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
          e.currentTarget.classList.remove('show');
        }
      });
      
      document.getElementById('config-modal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
          e.currentTarget.classList.remove('show');
        }
      });
    });
  </script>
</body>
</html>`;

// ============================================================================
// HTML صفحه فرود (Landing Page)
// ============================================================================

const landingPageHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VLESS Proxy - سرویس پراکسی سریع و امن</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root {
      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;
      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;
      --accent: #3B82F6; --accent-hover: #2563EB;
      --danger: #EF4444; --danger-hover: #DC2626;
      --success: #22C55E; --warning: #F59e0b;
      --btn-secondary-bg: #4B5563; --purple: #a855f7;
      --cyan: #06b6d4; --pink: #ec4899;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @keyframes gradient-flow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-20px); }
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #111827 25%, #0d1321 50%, #0a0e17 75%, #111827 100%);
      background-size: 400% 400%;
      animation: gradient-flow 15s ease infinite;
      color: var(--text-primary);
      font-size: 16px;
      line-height: 1.6;
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
      direction: rtl;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: 
        radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px 20px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 60px;
    }
    .logo {
      font-size: 24px;
      font-weight: 700;
      color: var(--accent);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .nav-links {
      display: flex;
      gap: 24px;
    }
    .nav-link {
      color: var(--text-secondary);
      text-decoration: none;
      transition: color 0.2s;
    }
    .nav-link:hover {
      color: var(--accent);
    }
    .hero {
      text-align: center;
      margin-bottom: 80px;
    }
    h1 {
      font-size: 56px;
      font-weight: 700;
      margin-bottom: 24px;
      background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 30%, #06b6d4 60%, #3B82F6 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: gradient-flow 4s linear infinite;
    }
    .hero-description {
      font-size: 20px;
      color: var(--text-secondary);
      max-width: 700px;
      margin: 0 auto 40px;
    }
    .cta-buttons {
      display: flex;
      gap: 16px;
      justify-content: center;
      flex-wrap: wrap;
    }
    .btn {
      padding: 14px 28px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 16px;
      position: relative;
      overflow: hidden;
      text-decoration: none;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn:hover::before { left: 100%; }
    .btn:active { transform: scale(0.96); }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%);
      background-size: 200% 200%;
      color: white;
      box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:hover {
      background-position: 100% 50%;
      box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
      transform: translateY(-3px);
    }
    .btn-secondary {
      background: linear-gradient(135deg, #4B5563 0%, #374151 100%);
      color: white;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .btn-secondary:hover { 
      background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .features {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 30px;
      margin-bottom: 80px;
    }
    .feature-card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 30px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      box-shadow: 
        0 4px 24px rgba(0,0,0,0.2),
        0 0 0 1px rgba(255, 255, 255, 0.03),
        inset 0 1px 0 rgba(255, 255, 255, 0.05);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .feature-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent);
      transition: left 0.6s ease;
    }
    .feature-card:hover::before {
      left: 100%;
    }
    .feature-card:hover {
      box-shadow: 
        0 20px 40px rgba(0,0,0,0.3),
        0 0 80px rgba(59, 130, 246, 0.1),
        inset 0 1px 0 rgba(255, 255, 255, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
      transform: translateY(-4px);
    }
    .feature-icon {
      width: 60px;
      height: 60px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 20px;
      font-size: 24px;
    }
    .feature-icon.blue { background: rgba(59, 130, 246, 0.15); }
    .feature-icon.green { background: rgba(34, 197, 94, 0.15); }
    .feature-icon.orange { background: rgba(245, 158, 11, 0.15); }
    .feature-icon.purple { background: rgba(168, 85, 247, 0.15); }
    .feature-title {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 12px;
      color: var(--text-primary);
    }
    .feature-description {
      color: var(--text-secondary);
      line-height: 1.6;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 80px;
    }
    .stat-card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 24px;
      border-radius: 16px;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.05);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--purple), var(--cyan));
      opacity: 0;
      transition: opacity 0.3s;
    }
    .stat-card:hover::before { opacity: 1; }
    .stat-card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 
        0 20px 40px rgba(59, 130, 246, 0.2),
        0 0 0 1px rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .stat-value {
      font-size: 36px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 8px;
      line-height: 1.2;
    }
    .stat-label {
      font-size: 14px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    footer {
      text-align: center;
      padding: 40px 0;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text-secondary);
    }
    .footer-links {
      display: flex;
      justify-content: center;
      gap: 24px;
      margin-bottom: 20px;
    }
    .footer-link {
      color: var(--text-secondary);
      text-decoration: none;
      transition: color 0.2s;
    }
    .footer-link:hover {
      color: var(--accent);
    }
    .floating-shapes {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      overflow: hidden;
      z-index: -1;
    }
    .shape {
      position: absolute;
      border-radius: 50%;
      filter: blur(40px);
      opacity: 0.1;
    }
    .shape-1 {
      width: 300px;
      height: 300px;
      background: var(--accent);
      top: 10%;
      left: 10%;
      animation: float 15s ease-in-out infinite;
    }
    .shape-2 {
      width: 200px;
      height: 200px;
      background: var(--purple);
      top: 60%;
      right: 10%;
      animation: float 12s ease-in-out infinite 2s;
    }
    .shape-3 {
      width: 250px;
      height: 250px;
      background: var(--cyan);
      bottom: 10%;
      left: 30%;
      animation: float 18s ease-in-out infinite 4s;
    }
    @media (max-width: 768px) {
      .container { padding: 20px 12px; }
      h1 { font-size: 36px; }
      .hero-description { font-size: 18px; }
      .cta-buttons { flex-direction: column; align-items: center; }
      .nav-links { display: none; }
      .features { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
  <div class="floating-shapes">
    <div class="shape shape-1"></div>
    <div class="shape shape-2"></div>
    <div class="shape shape-3"></div>
  </div>
  
  <div class="container">
    <header>
      <div class="logo">
        ⚡ VLESS Proxy
      </div>
      <nav class="nav-links">
        <a href="#features" class="nav-link">ویژگی‌ها</a>
        <a href="#stats" class="nav-link">آمار</a>
        <a href="/admin" class="nav-link">ورود ادمین</a>
      </nav>
    </header>
    
    <section class="hero">
      <h1>سرویس پراکسی سریع و امن</h1>
      <p class="hero-description">
        با VLESS Proxy به اینترنت سریع و امن دسترسی داشته باشید. سرویسی با پایداری بالا و بدون محدودیت.
      </p>
      <div class="cta-buttons">
        <a href="#features" class="btn btn-primary">بیشتر بدانید</a>
        <a href="/admin" class="btn btn-secondary">ورود ادمین</a>
      </div>
    </section>
    
    <section id="features" class="features">
      <div class="feature-card">
        <div class="feature-icon blue">🚀</div>
        <h3 class="feature-title">سرعت بالا</h3>
        <p class="feature-description">
          با استفاده از آخرین تکنولوژی‌ها، تجربه‌ی اینترنت پرسرعتی را داشته باشید.
        </p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon green">🔒</div>
        <h3 class="feature-title">امنیت کامل</h3>
        <p class="feature-description">
          ترافیک شما با رمزنگاری پیشرفته محافظت می‌شود و حریم خصوصی شما تضمین می‌شود.
        </p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon orange">🌍</div>
        <h3 class="feature-title">دسترسی جهانی</h3>
        <p class="feature-description">
          به سرورهای در سراسر جهان دسترسی داشته باشید و محدودیت‌های جغرافیایی را دور بزنید.
        </p>
      </div>
      
      <div class="feature-card">
        <div class="feature-icon purple">📱</div>
        <h3 class="feature-title">سازگاری با همه دستگاه‌ها</h3>
        <p class="feature-description">
          روی تمام دستگاه‌ها و سیستم‌عامل‌ها از جمله اندروید، iOS، ویندوز و مک کار می‌کند.
        </p>
      </div>
    </section>
    
    <section id="stats" class="stats">
      <div class="stat-card">
        <div class="stat-value">99.9%</div>
        <div class="stat-label">آپتایم</div>
      </div>
      
      <div class="stat-card">
        <div class="stat-value">50+</div>
        <div class="stat-label">سرور</div>
      </div>
      
      <div class="stat-card">
        <div class="stat-value">1Gbps</div>
        <div class="stat-label">سرعت</div>
      </div>
      
      <div class="stat-card">
        <div class="stat-value">24/7</div>
        <div class="stat-label">پشتیبانی</div>
      </div>
    </section>
    
    <footer>
      <div class="footer-links">
        <a href="/robots.txt" class="footer-link">Robots.txt</a>
        <a href="/security.txt" class="footer-link">Security.txt</a>
        <a href="/admin" class="footer-link">پنل ادمین</a>
      </div>
      <p>&copy; 2025 VLESS Proxy. تمام حقوق محفوظ است.</p>
    </footer>
  </div>
</body>
</html>`;

// ============================================================================
// HTML صفحه 404 سفارشی
// ============================================================================

const custom404HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>صفحه یافت نشد - 404 | VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root {
      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;
      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;
      --accent: #3B82F6; --accent-hover: #2563EB;
      --danger: #EF4444; --danger-hover: #DC2626;
      --success: #22C55E; --warning: #F59e0b;
      --btn-secondary-bg: #4B5563; --purple: #a855f7;
      --cyan: #06b6d4; --pink: #ec4899;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @keyframes gradient-flow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-20px); }
    }
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #111827 25%, #0d1321 50%, #0a0e17 75%, #111827 100%);
      background-size: 400% 400%;
      animation: gradient-flow 15s ease infinite;
      color: var(--text-primary);
      font-size: 16px;
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      position: relative;
      overflow: hidden;
      direction: rtl;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: 
        radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .container {
      text-align: center;
      max-width: 600px;
      padding: 40px 20px;
    }
    .error-code {
      font-size: 120px;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 20px;
      background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 50%, var(--cyan) 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: gradient-flow 4s linear infinite;
    }
    .error-title {
      font-size: 32px;
      font-weight: 600;
      margin-bottom: 16px;
      color: var(--text-primary);
    }
    .error-description {
      font-size: 18px;
      color: var(--text-secondary);
      margin-bottom: 40px;
      line-height: 1.6;
    }
    .btn {
      padding: 14px 28px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 16px;
      position: relative;
      overflow: hidden;
      text-decoration: none;
      margin: 0 8px;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn:hover::before { left: 100%; }
    .btn:active { transform: scale(0.96); }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%);
      background-size: 200% 200%;
      color: white;
      box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:hover {
      background-position: 100% 50%;
      box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
      transform: translateY(-3px);
    }
    .btn-secondary {
      background: linear-gradient(135deg, #4B5563 0%, #374151 100%);
      color: white;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .btn-secondary:hover { 
      background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .floating-shapes {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      overflow: hidden;
      z-index: -1;
    }
    .shape {
      position: absolute;
      border-radius: 50%;
      filter: blur(40px);
      opacity: 0.1;
    }
    .shape-1 {
      width: 300px;
      height: 300px;
      background: var(--accent);
      top: 10%;
      left: 10%;
      animation: float 15s ease-in-out infinite;
    }
    .shape-2 {
      width: 200px;
      height: 200px;
      background: var(--purple);
      top: 60%;
      right: 10%;
      animation: float 12s ease-in-out infinite 2s;
    }
    .shape-3 {
      width: 250px;
      height: 250px;
      background: var(--cyan);
      bottom: 10%;
      left: 30%;
      animation: float 18s ease-in-out infinite 4s;
    }
    @media (max-width: 768px) {
      .error-code { font-size: 80px; }
      .error-title { font-size: 24px; }
      .error-description { font-size: 16px; }
      .btn { margin: 8px 0; }
    }
  </style>
</head>
<body>
  <div class="floating-shapes">
    <div class="shape shape-1"></div>
    <div class="shape shape-2"></div>
    <div class="shape shape-3"></div>
  </div>
  
  <div class="container">
    <div class="error-code">404</div>
    <h1 class="error-title">صفحه یافت نشد</h1>
    <p class="error-description">
      متاسفانه صفحه‌ای که به دنبال آن بودید وجود ندارد. ممکن است آدرس را اشتباه وارد کرده باشید یا صفحه حذف شده باشد.
    </p>
    <div>
      <a href="/" class="btn btn-primary">صفحه اصلی</a>
      <a href="/admin" class="btn btn-secondary">پنل ادمین</a>
    </div>
  </div>
</body>
</html>`;

// ============================================================================
 robots.txt
// ============================================================================

const robotsTxt = `User-agent: *
Allow: /
Sitemap: https://example.com/sitemap.xml`;

// ============================================================================
// security.txt
// ============================================================================

const securityTxt = `Contact: mailto:admin@example.com
Expires: 2025-12-31T23:59:59.000Z
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/security-acknowledgments.txt
Preferred-Languages: en, fa
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy.html`;

// ============================================================================
// توابع مدیریت رویداد اصلی
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      // مقداردهی اولیه جداول پایگاه داده
      ctx.waitUntil(ensureTablesExist(env, ctx));
      
      // اجرای دوره‌ای بررسی سلامت
      ctx.waitUntil(
        (async () => {
          await new Promise(resolve => setTimeout(resolve, 5000)); // تأخیر اولیه
          while (true) {
            await performHealthCheck(env, ctx);
            await cleanupOldIps(env, ctx);
            await new Promise(resolve => setTimeout(resolve, CONST.HEALTH_CHECK_INTERVAL));
          }
        })()
      );
      
      const config = await Config.fromEnv(env);
      const url = new URL(request.url);
      const path = url.pathname;
      const host = request.headers.get('Host');
      
      // مدیریت مسیرهای استاتیک
      if (path === '/robots.txt') {
        return new Response(robotsTxt, {
          headers: { 'Content-Type': 'text/plain' }
        });
      }
      
      if (path === '/security.txt') {
        return new Response(securityTxt, {
          headers: { 'Content-Type': 'text/plain' }
        });
      }
      
      // مدیریت مسیرهای API
      if (path.startsWith('/api/')) {
        return handleApiRequest(request, env, config, path);
      }
      
      // مدیریت مسیرهای ادمین
      if (path.startsWith('/admin')) {
        return handleAdminRequest(request, env, config, path);
      }
      
      // بررسی مسیر کاربری (UUID)
      const uuidMatch = path.match(/^\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i);
      if (uuidMatch) {
        const uuid = uuidMatch[1];
        return handleUserRequest(request, env, config, uuid);
      }
      
      // مدیریت مسیرهای اشتراک
      if (path.startsWith('/sub/')) {
        const uuid = path.substring(5);
        return handleSubscriptionRequest(request, env, config, uuid);
      }
      
      // صفحه فرود برای مسیر ریشه
      if (path === '/') {
        const nonce = generateNonce();
        const headers = new Headers();
        addSecurityHeaders(headers, nonce);
        
        return new Response(landingPageHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce), {
          headers: {
            ...headers,
            'Content-Type': 'text/html; charset=utf-8',
          },
        });
      }
      
      // صفحه 404 برای مسیرهای دیگر
      const nonce = generateNonce();
      const headers = new Headers();
      addSecurityHeaders(headers, nonce);
      
      return new Response(custom404HTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce), {
        status: 404,
        headers: {
          ...headers,
          'Content-Type': 'text/html; charset=utf-8',
        },
      });
      
    } catch (err) {
      console.error('خطای عمومی:', err);
      return new Response('خطای سرور داخلی', { status: 500 });
    }
  },
};

// ============================================================================
// توابع مدیریت درخواست‌های API
// ============================================================================

async function handleApiRequest(request, env, config, path) {
  const url = new URL(request.url);
  const nonce = generateNonce();
  const headers = new Headers();
  addSecurityHeaders(headers, nonce);
  
  // API برای اطلاعات کاربر
  if (path.startsWith('/api/user/')) {
    const uuid = path.substring(10);
    
    if (!isValidUUID(uuid)) {
      return new Response('UUID نامعتبر است', { status: 400 });
    }
    
    const userData = await getUserData(env, uuid);
    if (!userData) {
      return new Response('کاربر یافت نشد', { status: 404 });
    }
    
    return new Response(JSON.stringify(userData), {
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
    });
  }
  
  // API برای کانفیگ
  if (path.startsWith('/api/config/')) {
    const parts = path.substring(12).split('/');
    const type = parts[0]; // xray یا singbox
    const uuid = parts[1];
    
    if (!isValidUUID(uuid)) {
      return new Response('UUID نامعتبر است', { status: 400 });
    }
    
    const userData = await getUserData(env, uuid);
    if (!userData) {
      return new Response('کاربر یافت نشد', { status: 404 });
    }
    
    // بررسی انقضا
    if (isExpired(userData.expiration_date, userData.expiration_time)) {
      return new Response('اشتراک منقضی شده است', { status: 403 });
    }
    
    // تولید کانفیگ
    const configLink = \`\${url.protocol}//\${url.host}/sub/\${type}/\${uuid}\`;
    
    return new Response(JSON.stringify({
      link: configLink,
      config: await getConfigContent(type, uuid, url.host, config)
    }), {
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
    });
  }
  
  // API برای اشتراک
  if (path.startsWith('/api/subscription/')) {
    const parts = path.substring(18).split('/');
    const type = parts[0]; // xray یا singbox
    const uuid = parts[1];
    
    if (!isValidUUID(uuid)) {
      return new Response('UUID نامعتبر است', { status: 400 });
    }
    
    const userData = await getUserData(env, uuid);
    if (!userData) {
      return new Response('کاربر یافت نشد', { status: 404 });
    }
    
    // بررسی انقضا
    if (isExpired(userData.expiration_date, userData.expiration_time)) {
      return new Response('اشتراک منقضی شده است', { status: 403 });
    }
    
    // تولید لینک اشتراک
    const subLink = \`\${url.protocol}//\${url.host}/sub/\${type}/\${uuid}\`;
    
    return new Response(JSON.stringify({
      link: subLink
    }), {
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
    });
  }
  
  return new Response('API یافت نشد', { status: 404 });
}

// ============================================================================
// توابع مدیریت درخواست‌های ادمین
// ============================================================================

async function handleAdminRequest(request, env, config, path) {
  const url = new URL(request.url);
  const nonce = generateNonce();
  const headers = new Headers();
  addSecurityHeaders(headers, nonce);
  
  // ورود به پنل ادمین
  if (path === '/admin/login' && request.method === 'GET') {
    return new Response(adminLoginHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce).replace(/ADMIN_PATH_PLACEHOLDER/g, '/admin/login'), {
      headers: {
        ...headers,
        'Content-Type': 'text/html; charset=utf-8',
      },
    });
  }
  
  if (path === '/admin/login' && request.method === 'POST') {
    return handleAdminLogin(request, env, config);
  }
  
  if (path === '/admin/logout') {
    return handleAdminLogout(request, env);
  }
  
  // بررسی احراز هویت برای سایر مسیرهای ادمین
  const isAuthenticated = await checkAdminAuth(request, env);
  if (!isAuthenticated) {
    return Response.redirect(`${url.origin}/admin/login`, 302);
  }
  
  // پنل اصلی ادمین
  if (path === '/admin' || path === '/admin/') {
    return new Response(adminPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce), {
      headers: {
        ...headers,
        'Content-Type': 'text/html; charset=utf-8',
      },
    });
  }
  
  // API ادمین
  if (path.startsWith('/admin/api/')) {
    return handleAdminApi(request, env, path.substring(11));
  }
  
  return new Response('صفحه ادمین یافت نشد', { status: 404 });
}

// ============================================================================
// توابع مدیریت درخواست‌های کاربر
// ============================================================================

async function handleUserRequest(request, env, config, uuid) {
  const url = new URL(request.url);
  const nonce = generateNonce();
  const headers = new Headers();
  addSecurityHeaders(headers, nonce);
  
  // بررسی اعتبار UUID
  if (!isValidUUID(uuid)) {
    return new Response('UUID نامعتبر است', { status: 400 });
  }
  
  // دریافت اطلاعات کاربر
  const userData = await getUserData(env, uuid);
  if (!userData) {
    return new Response('کاربر یافت نشد', { status: 404 });
  }
  
  // نمایش پنل کاربری
  return new Response(userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce), {
    headers: {
      ...headers,
      'Content-Type': 'text/html; charset=utf-8',
    },
  });
}

// ============================================================================
// توابع مدیریت درخواست‌های اشتراک
// ============================================================================

async function handleSubscriptionRequest(request, env, config, path) {
  const parts = path.split('/');
  const type = parts[0]; // xray یا singbox
  const uuid = parts[1];
  
  if (!isValidUUID(uuid)) {
    return new Response('UUID نامعتبر است', { status: 400 });
  }
  
  const userData = await getUserData(env, uuid);
  if (!userData) {
    return new Response('کاربر یافت نشد', { status: 404 });
  }
  
  // بررسی انقضا
  if (isExpired(userData.expiration_date, userData.expiration_time)) {
    return new Response('اشتراک منقضی شده است', { status: 403 });
  }
  
  // ثبت IP کاربر
  const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  ctx.waitUntil(updateUserIP(env, uuid, clientIP));
  
  // تولید اشتراک
  return handleIpSubscription(type, uuid, request.headers.get('Host'));
}

// ============================================================================
// توابع کمکی ادمین
// ============================================================================

async function checkAdminAuth(request, env) {
  const url = new URL(request.url);
  const cookies = request.headers.get('Cookie') || '';
  const cookieMatch = cookies.match(/admin_session=([^;]+)/);
  
  if (!cookieMatch) {
    return false;
  }
  
  const sessionId = cookieMatch[1];
  const sessionData = await kvGet(env.DB, \`admin_session:\${sessionId}\`, 'json');
  
  if (!sessionData || !sessionData.valid) {
    return false;
  }
  
  return true;
}

async function handleAdminLogin(request, env, config) {
  const formData = await request.formData();
  const password = formData.get('password');
  const totp = formData.get('totp');
  
  // بررسی رمز عبور
  const adminPassword = env.ADMIN_PASSWORD || 'admin123';
  if (password !== adminPassword) {
    return new Response('رمز عبور نادرست است', { status: 401 });
  }
  
  // بررسی 2FA در صورت فعال بودن
  if (env.ADMIN_TOTP_SECRET) {
    if (!totp || !await validateTOTP(env.ADMIN_TOTP_SECRET, totp)) {
      return new Response('کد 2FA نادرست است', { status: 401 });
    }
  }
  
  // ایجاد جلسه
  const sessionId = generateUUID();
  await kvPut(env.DB, \`admin_session:\${sessionId}\`, {
    valid: true,
    created: Date.now()
  }, { expirationTtl: 86400 }); // 24 ساعت
  
  const headers = new Headers();
  headers.set('Set-Cookie', \`admin_session=\${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400\`);
  headers.set('Location', '/admin');
  
  return new Response(null, {
    status: 302,
    headers
  });
}

async function handleAdminLogout(request, env) {
  const url = new URL(request.url);
  const cookies = request.headers.get('Cookie') || '';
  const cookieMatch = cookies.match(/admin_session=([^;]+)/);
  
  if (cookieMatch) {
    const sessionId = cookieMatch[1];
    await kvDelete(env.DB, \`admin_session:\${sessionId}\`);
  }
  
  const headers = new Headers();
  headers.set('Set-Cookie', 'admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
  headers.set('Location', '/admin/login');
  
  return new Response(null, {
    status: 302,
    headers
  });
}

async function handleAdminApi(request, env, path) {
  const nonce = generateNonce();
  const headers = new Headers();
  addSecurityHeaders(headers, nonce);
  
  if (path === 'users' && request.method === 'GET') {
    // دریافت لیست کاربران
    try {
      const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
      return new Response(JSON.stringify(results), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    } catch (e) {
      return new Response(\`خطا در دریافت کاربران: \${e.message}\`, { status: 500 });
    }
  }
  
  if (path === 'users' && request.method === 'POST') {
    // ایجاد کاربر جدید
    try {
      const userData = await request.json();
      
      // اعتبارسنجی
      if (!isValidUUID(userData.uuid)) {
        return new Response('UUID نامعتبر است', { status: 400 });
      }
      
      if (!userData.expiryDate || !userData.expiryTime) {
        return new Response('تاریخ و زمان انقضا الزامی است', { status: 400 });
      }
      
      // درج کاربر جدید
      await env.DB.prepare(
        "INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(
        userData.uuid,
        userData.expiryDate,
        userData.expiryTime,
        userData.notes || null,
        userData.trafficLimit || null,
        userData.ipLimit || -1
      ).run();
      
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    } catch (e) {
      return new Response(\`خطا در ایجاد کاربر: \${e.message}\`, { status: 500 });
    }
  }
  
  if (path === 'users' && request.method === 'DELETE') {
    // حذف کاربران
    try {
      const { uuids } = await request.json();
      
      if (!Array.isArray(uuids) || uuids.length === 0) {
        return new Response('لیست UUID الزامی است', { status: 400 });
      }
      
      // حذف کاربران
      const placeholders = uuids.map(() => '?').join(',');
      await env.DB.prepare(\`DELETE FROM users WHERE uuid IN (\${placeholders})\`).bind(...uuids).run();
      
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    } catch (e) {
      return new Response(\`خطا در حذف کاربران: \${e.message}\`, { status: 500 });
    }
  }
  
  if (path === 'health-check' && request.method === 'GET') {
    // بررسی سلامت پروکسی
    try {
      await performHealthCheck(env);
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    }
  }
  
  if (path === 'health-status' && request.method === 'GET') {
    // وضعیت سلامت پروکسی
    try {
      const { results } = await env.DB.prepare(
        "SELECT is_healthy FROM proxy_health WHERE is_healthy = 1 LIMIT 1"
      ).all();
      
      const isHealthy = results.length > 0;
      
      return new Response(JSON.stringify({ healthy: isHealthy }), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    } catch (e) {
      return new Response(JSON.stringify({ healthy: false, error: e.message }), {
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
      });
    }
  }
  
  return new Response('API ادمین یافت نشد', { status: 404 });
}

// ============================================================================
// توابع کمکی دیگر
// ============================================================================

async function updateUserIP(env, uuid, ip) {
  if (!env.DB) return;
  
  try {
    await env.DB.prepare(
      "INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, datetime('now'))"
    ).bind(uuid, ip).run();
  } catch (e) {
    console.error(\`خطا در به‌روزرسانی IP کاربر \${uuid}: \${e.message}\`);
  }
}

async function getConfigContent(type, uuid, host, config) {
  // این تابع باید بر اساس نوع کانفیگ (xray یا singbox) محتوای مناسب را تولید کند
  // در اینجا یک پیاده‌سازی ساده ارائه شده است
  
  const configTemplate = {
    xray: {
      "inbounds": [],
      "outbounds": [
        {
          "protocol": "vless",
          "settings": {
            "vnext": [
              {
                "address": host,
                "port": 443,
                "users": [
                  {
                    "id": uuid,
                    "encryption": "none"
                  }
                ]
              }
            ]
          },
          "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
              "path": generateRandomPath()
            },
            "tlsSettings": {
              "serverName": host,
              "allowInsecure": true
            }
          }
        }
      ]
    },
    singbox: {
      "outbounds": [
        {
          "type": "vless",
          "tag": "proxy",
          "server": host,
          "server_port": 443,
          "uuid": uuid,
          "network": "ws",
          "tls": {
            "enabled": true,
            "server_name": host,
            "insecure": true
          },
          "transport": {
            "path": generateRandomPath(),
            "headers": {
              "Host": host
            }
          }
        }
      ]
    }
  };
  
  return JSON.stringify(configTemplate[type] || configTemplate.xray, null, 2);
}
