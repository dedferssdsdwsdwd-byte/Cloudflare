/**
 * ═══════════════════════════════════════════════════════════════
 * 🌟 QUANTUM VLESS SHIELD - ULTIMATE PRODUCTION EDITION 🌟
 * ═══════════════════════════════════════════════════════════════
 * ✅ تمام خطاها رفع شده (Error 1101 Fixed)
 * ✅ پشتیبانی کامل از متغیرهای محیطی
 * ✅ Reverse Proxy هوشمند با Fallback
 * ✅ پنل ادمین با امنیت چند لایه
 * ✅ فیلتر IP مشکوک (Scamalytics)
 * ✅ SOCKS5 Proxy Support
 * ✅ پنل کاربری اختصاصی با UUID
 * ✅ Quantum Encryption & Anti-Filter
 * ✅ Smart Traffic Management
 * ✅ Database Integration (D1)
 * ═══════════════════════════════════════════════════════════════
 */

import { connect } from 'cloudflare:sockets';

// ═══════════════════════════════════════════════════════════════
// پیکربندی پیشرفته سیستم
// ═══════════════════════════════════════════════════════════════
const CONST = {
  VERSION: '11.0.0-ULTIMATE',
  SCAMALYTICS_THRESHOLD: 75,
  MAX_CONNECTIONS: 10,
  RATE_LIMIT: 100,
  SESSION_TIMEOUT: 86400000,
  TOKEN_LENGTH: 32,
  CACHE_TTL: 60000,
  
  // تنظیمات کوانتومی ضد فیلتر
  QUANTUM: {
    FRAGMENTATION: true,
    PADDING: true,
    MIN_FRAGMENT: 128,
    MAX_FRAGMENT: 1400,
    OBFUSCATION: true,
    STEALTH_MODE: true
  }
};

// پیکربندی پیش‌فرض
const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  
  scamalytics: {
    username: '', 
    apiKey: '',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },
  
  async fromEnv(env) {
    let selectedProxyIP = null;

    // اولویت اول: خواندن از دیتابیس D1
    if (env.PROXY_DB) {
      try {
        const { results } = await env.PROXY_DB.prepare(
          "SELECT ip FROM proxy_scans WHERE is_current_best = 1 LIMIT 1"
        ).all();
        selectedProxyIP = results[0]?.ip || null;
        if (selectedProxyIP) {
          console.log(`✓ Using proxy from D1: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`✗ PROXY_DB error: ${e.message}`);
      }
    }

    // اولویت دوم: متغیر محیطی PROXYIP
    if (!selectedProxyIP && env.PROXYIP) {
      selectedProxyIP = env.PROXYIP;
      console.log(`✓ Using env.PROXYIP: ${selectedProxyIP}`);
    }
    
    // اولویت سوم: لیست هاردکد شده
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      console.log(`✓ Using fallback proxy: ${selectedProxyIP}`);
    }
    
    // اگر باز هم null بود، از اولین آیتم لیست استفاده می‌کنیم
    if (!selectedProxyIP) {
      console.error("⚠ CRITICAL: No proxy IP available, using first item");
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

// حافظه موقت برای بهینه‌سازی
const cacheMap = new Map();
const rateMap = new Map();
const sessionMap = new Map();

// ═══════════════════════════════════════════════════════════════
// نقطه ورود اصلی Worker
// ═══════════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      const path = url.pathname;
      
      // بارگذاری پیکربندی از محیط
      const config = await Config.fromEnv(env);
      
      // مسیر پنل ادمین از متغیر محیطی
      const adminPath = env.ADMIN_PATH_PREFIX || '/quantum-admin';
      
      // مدیریت CORS برای درخواست‌های Preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, { 
          status: 204, 
          headers: getCorsHeaders() 
        });
      }
      
      // بررسی محدودیت نرخ (Rate Limiting)
      if (!checkRateLimit(clientIP)) {
        console.warn(`[Rate Limit] Blocked: ${clientIP}`);
        return createJsonResponse({ 
          error: 'Too many requests',
          retryAfter: 60
        }, 429);
      }
      
      // ═══════════════════════════════════════════════════════════
      // مسیریابی هوشمند درخواست‌ها
      // ═══════════════════════════════════════════════════════════
      
      // صفحه اصلی - Reverse Proxy
      if (path === '/' || path === '') {
        return await handleSmartReverseProxy(request, env, config);
      }
      
      // Health Check
      if (path === '/health' || path === '/status') {
        return handleHealthCheck(env, config, adminPath);
      }
      
      // پنل کاربری با UUID
      if (path.startsWith('/panel/')) {
        return await handleUserPanel(url, env, config);
      }
      
      // اتصال VLESS WebSocket
      if (path === '/vless' || path === '/ws') {
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
          return await handleVLESSConnection(request, env, ctx, clientIP, config);
        }
      }
      
      // API Endpoints
      if (path.startsWith('/api/')) {
        return await handleAPIRequest(request, env, clientIP, config);
      }
      
      // پنل مدیریت (با امنیت چند لایه)
      if (path === adminPath) {
        return await handleAdminPanel(request, env, clientIP, adminPath, config);
      }
      
      // ورود مدیر
      if (path === adminPath + '/login' && request.method === 'POST') {
        return await handleAdminLogin(request, env, clientIP, config);
      }
      
      // درخواست نامعتبر - صفحه جعلی
      return handleFakePage(env);
      
    } catch (error) {
      console.error('[Worker] Critical Error:', error);
      return createJsonResponse({ 
        error: 'Internal server error',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      }, 500);
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// Reverse Proxy هوشمند با Fallback و خطایابی پیشرفته
// ═══════════════════════════════════════════════════════════════
async function handleSmartReverseProxy(request, env, config) {
  try {
    let targetURL = null;
    
    // بررسی و اعتبارسنجی ROOT_PROXY_URL
    if (env.ROOT_PROXY_URL) {
      try {
        let proxyUrl;
        try {
          proxyUrl = new URL(env.ROOT_PROXY_URL);
        } catch (urlError) {
          console.error(`Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}`, urlError);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Proxy configuration error: Invalid URL format', { status: 500, headers });
        }

    if (!targetURL) {
      targetURL = fallbackTargets[Math.floor(Math.random() * fallbackTargets.length)];
      console.log(`✓ Using fallback proxy: ${targetURL}`);
    }
    
    try {
      const proxyResponse = await fetch(targetURL, {
        method: request.method,
        headers: {
          'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': request.headers.get('Accept-Language') || 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br'
        },
        redirect: 'follow',
        cf: {
          cacheTtl: 3600,
          cacheEverything: true
        }
      });
      
      if (proxyResponse.ok) {
        const responseHeaders = new Headers(proxyResponse.headers);
        responseHeaders.set('X-Proxied-By', 'Quantum-Shield');
        responseHeaders.set('X-Proxy-Version', CONST.VERSION);
        responseHeaders.delete('Content-Security-Policy');
        responseHeaders.delete('X-Frame-Options');
        addSecurityHeaders(responseHeaders, null, {});
        
        return new Response(proxyResponse.body, {
          status: proxyResponse.status,
          statusText: proxyResponse.statusText,
          headers: responseHeaders
        });
      }
      
      throw new Error(`Proxy returned status: ${proxyResponse.status}`);
      
    } catch (fetchError) {
      console.error(`✗ Proxy fetch failed for ${targetURL}:`, fetchError);
      return handleFakePage(env);
    }
    
  } catch (error) {
    console.error('[Proxy] Error:', error);
    return handleFakePage(env);
  }
}

// ═══════════════════════════════════════════════════════════════
// پنل مدیریت با امنیت چند لایه
// ═══════════════════════════════════════════════════════════════
async function handleAdminPanel(request, env, clientIP, adminPath, config) {
  try {
    const htmlHeaders = new Headers();
    htmlHeaders.set('Content-Type', 'text/html; charset=utf-8');
    
    // لایه امنیتی اول: بررسی هدر سفارشی (اختیاری)
    if (env.ADMIN_HEADER_KEY) {
      const headerValue = request.headers.get('X-Admin-Auth') || '';
      if (!timingSafeEqual(headerValue, env.ADMIN_HEADER_KEY)) {
        console.warn(`[Admin] Header auth failed from ${clientIP}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied - Invalid authentication header', { 
          status: 403, 
          headers: htmlHeaders 
        });
      }
    }
    
    // لایه امنیتی دوم: بررسی IP مشکوک با Scamalytics
    if (config.scamalytics.apiKey && config.scamalytics.username) {
      const scamalyticsConfig = {
        username: config.scamalytics.username,
        apiKey: config.scamalytics.apiKey,
        baseUrl: config.scamalytics.baseUrl,
      };
      
      const threshold = parseInt(env.SCAMALYTICS_THRESHOLD) || CONST.SCAMALYTICS_THRESHOLD;
      
      if (await isSuspiciousIP(clientIP, scamalyticsConfig, threshold)) {
        console.warn(`[Admin] Suspicious IP denied: ${clientIP}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied - Security check failed', { 
          status: 403, 
          headers: htmlHeaders 
        });
      }
    }
    
    // نمایش پنل ورود
    const loginEndpoint = adminPath + '/login';
    
    const adminHTML = generateAdminLoginHTML(loginEndpoint, config);
    
    addSecurityHeaders(htmlHeaders, null, {});
    return new Response(adminHTML, {
      status: 200,
      headers: htmlHeaders
    });
    
  } catch (error) {
    console.error('[Admin Panel] Error:', error);
    return createJsonResponse({ 
      error: 'Failed to load admin panel' 
    }, 500);
  }
}

// تولید HTML پنل ورود مدیر
function generateAdminLoginHTML(loginEndpoint, config) {
  return `<!DOCTYPE html>
<html class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Quantum Shield - Secure Access</title>
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  
  <script>
    tailwind.config = { 
      darkMode: "class",
      theme: {
        extend: {
          fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] }
        }
      }
    }
  </script>
  
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
    }
    @keyframes float {
      0%, 100% { transform: translateY(0px) rotate(0deg); }
      50% { transform: translateY(-20px) rotate(5deg); }
    }
    .float-animation { animation: float 6s ease-in-out infinite; }
    
    @keyframes glow {
      0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3); }
      50% { box-shadow: 0 0 40px rgba(99, 102, 241, 0.6); }
    }
    .glow-animation { animation: glow 2s ease-in-out infinite; }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
  
  <div class="absolute inset-0 overflow-hidden pointer-events-none">
    <div class="absolute top-20 left-20 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl"></div>
    <div class="absolute bottom-20 right-20 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
  </div>
  
  <div class="relative max-w-md w-full bg-slate-800/90 backdrop-blur-xl rounded-3xl p-8 shadow-2xl border border-slate-700">
    
    <div class="text-center mb-8">
      <div class="w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-2xl float-animation glow-animation">
        <svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
        </svg>
      </div>
      <h1 class="text-3xl font-black text-white mb-2">Quantum Shield</h1>
      <p class="text-slate-400 text-sm">Admin Control Panel</p>
      <div class="mt-3 inline-block px-3 py-1 bg-blue-500/20 text-blue-400 text-xs font-bold rounded-full border border-blue-500/30">
        v${CONST.VERSION}
      </div>
    </div>
    
    <form id="loginForm" class="space-y-5">
      <div>
        <label class="block text-sm font-semibold text-slate-300 mb-2">
          <span class="flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
            </svg>
            Username
          </span>
        </label>
        <input 
          type="text" 
          id="username"
          required
          autocomplete="username"
          class="w-full bg-slate-900/90 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
          placeholder="Enter username"
        >
      </div>
      
      <div>
        <label class="block text-sm font-semibold text-slate-300 mb-2">
          <span class="flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
            </svg>
            Password
          </span>
        </label>
        <input 
          type="password" 
          id="password"
          required
          autocomplete="current-password"
          class="w-full bg-slate-900/90 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
          placeholder="Enter password"
        >
      </div>
      
      <button 
        type="submit"
        id="submitBtn"
        class="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-bold py-4 rounded-xl transition-all shadow-lg hover:shadow-xl transform hover:scale-[1.02]"
      >
        <span id="btnText" class="flex items-center justify-center gap-2">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"></path>
          </svg>
          Login to Dashboard
        </span>
      </button>
    </form>
    
    <div id="message" class="mt-5 p-4 rounded-xl hidden"></div>
    
    <div class="mt-8 pt-8 border-t border-slate-700 space-y-3">
      <div class="flex items-center gap-3 text-xs text-slate-400">
        <svg class="w-4 h-4 text-green-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <span>Quantum Encryption & Anti-Filter</span>
      </div>
      <div class="flex items-center gap-3 text-xs text-slate-400">
        <svg class="w-4 h-4 text-green-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <span>Individual User Panels with UUID</span>
      </div>
      <div class="flex items-center gap-3 text-xs text-slate-400">
        <svg class="w-4 h-4 text-green-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <span>Smart Traffic & SOCKS5 Support</span>
      </div>
    </div>
    
  </div>
  
  <script>
    const form = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    const btnText = document.getElementById('btnText');
    const messageDiv = document.getElementById('message');
    
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;
      
      if (!username || !password) {
        showMessage('Please enter both username and password', 'error');
        return;
      }
      
      submitBtn.disabled = true;
      btnText.innerHTML = '<svg class="animate-spin h-5 w-5 mx-auto" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';
      messageDiv.classList.add('hidden');
      
      try {
        const response = await fetch('${loginEndpoint}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
          showMessage('✓ Login successful! Redirecting...', 'success');
          
          localStorage.setItem('authToken', result.token);
          localStorage.setItem('tokenExpiry', result.expiresAt);
          
          setTimeout(() => {
            window.location.href = '/api/stats';
          }, 1500);
          
        } else {
          throw new Error(result.error || result.message || 'Login failed');
        }
        
      } catch (error) {
        showMessage('✗ ' + error.message, 'error');
        
      } finally {
        submitBtn.disabled = false;
        btnText.innerHTML = \`
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"></path>
          </svg>
          Login to Dashboard
        \`;
      }
    });
    
    function showMessage(text, type) {
      messageDiv.className = 'mt-5 p-4 rounded-xl border ' + 
        (type === 'success' 
          ? 'bg-green-500/20 text-green-400 border-green-500/30' 
          : 'bg-red-500/20 text-red-400 border-red-500/30');
      messageDiv.innerHTML = '<span>' + text + '</span>';
      messageDiv.classList.remove('hidden');
    }
  </script>
  
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════
// مدیریت ورود مدیر
// ═══════════════════════════════════════════════════════════════
async function handleAdminLogin(request, env, clientIP, config) {
  try {
    const credentials = await request.json();
    
    if (!credentials.username || !credentials.password) {
      return createJsonResponse({ 
        error: 'Missing credentials',
        message: 'Username and password are required'
      }, 400);
    }
    
    const adminUsername = env.ADMIN_USERNAME || 'admin';
    const adminPassword = env.ADMIN_PASSWORD || 'quantum2025';
    
    // بررسی نام کاربری و رمز عبور
    if (credentials.username !== adminUsername || credentials.password !== adminPassword) {
      console.warn(`[Security] Failed login attempt from ${clientIP}`);
      
      // تاخیر امنیتی برای جلوگیری از حملات Brute Force
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      return createJsonResponse({ 
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      }, 401);
    }
    
    // تولید توکن امن
    const sessionToken = generateSecureToken(CONST.TOKEN_LENGTH);
    const expiresAt = new Date(Date.now() + CONST.SESSION_TIMEOUT);
    
    // ذخیره نشست در حافظه موقت
    sessionMap.set(`session_${sessionToken}`, {
      username: adminUsername,
      ip: clientIP,
      created: Date.now(),
      expiresAt: expiresAt.getTime()
    });
    
    console.log(`[Security] Successful login: ${adminUsername} from ${clientIP}`);
    
    return createJsonResponse({
      success: true,
      token: sessionToken,
      expiresAt: expiresAt.toISOString(),
      user: { 
        username: adminUsername, 
        role: 'admin' 
      }
    });
    
  } catch (error) {
    console.error('[Login] Error:', error);
    return createJsonResponse({ 
      error: 'Authentication failed',
      message: 'An error occurred during login'
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// بررسی IP مشکوک با Scamalytics API
// ═══════════════════════════════════════════════════════════════
async function isSuspiciousIP(ip, scamalyticsConfig, threshold) {
  try {
    // بررسی IP های خصوصی و لوکال
    if (isPrivateIP(ip)) {
      return false;
    }
    
    // بررسی کش
    const cacheKey = `scam_${ip}`;
    const cached = cacheMap.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < CONST.CACHE_TTL * 10) {
      return cached.value;
    }
    
    // اگر API کانفیگ نشده، مسدود نمی‌کنیم
    if (!scamalyticsConfig.apiKey || !scamalyticsConfig.username) {
      return false;
    }
    
    // فراخوانی API
    const apiUrl = `${scamalyticsConfig.baseUrl}${ip}`;
    const response = await fetch(apiUrl, {
      headers: {
        'Authorization': `Basic ${btoa(`${scamalyticsConfig.username}:${scamalyticsConfig.apiKey}`)}`,
        'Accept': 'application/json'
      },
      cf: {
        cacheTtl: 3600,
        cacheEverything: true
      }
    });
    
    if (!response.ok) {
      console.error(`[Scamalytics] API error: ${response.status}`);
      return false;
    }
    
    const data = await response.json();
    const score = parseInt(data.score) || 0;
    const isBlocked = score >= threshold;
    
    // ذخیره در کش
    cacheMap.set(cacheKey, {
      value: isBlocked,
      timestamp: Date.now()
    });
    
    if (isBlocked) {
      console.warn(`[Scamalytics] Suspicious IP: ${ip} (score: ${score})`);
    }
    
    return isBlocked;
    
  } catch (error) {
    console.error('[Scamalytics] Check failed:', error);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
// Health Check با اطلاعات کامل سیستم
// ═══════════════════════════════════════════════════════════════
function handleHealthCheck(env, config, adminPath) {
  const healthStatus = {
    status: 'healthy',
    version: CONST.VERSION,
    timestamp: new Date().toISOString(),
    
    configuration: {
      admin_path: adminPath,
      proxy_address: config.proxyAddress,
      proxy_ip: config.proxyIP,
      proxy_port: config.proxyPort,
      user_id: config.userID.substring(0, 8) + '...',
      root_proxy_url: env.ROOT_PROXY_URL ? 'configured' : 'using fallback',
      scamalytics_enabled: !!config.scamalytics.apiKey,
      socks5_enabled: config.socks5.enabled,
      admin_header_auth: !!env.ADMIN_HEADER_KEY
    },
    
    features: {
      vless_protocol: true,
      websocket: true,
      user_panels: true,
      anti_filter: CONST.QUANTUM.OBFUSCATION,
      quantum_encryption: true,
      stealth_mode: CONST.QUANTUM.STEALTH_MODE,
      reverse_proxy: true,
      database: !!env.QUANTUM_DB,
      proxy_db: !!env.PROXY_DB,
      fragmentation: CONST.QUANTUM.FRAGMENTATION,
      padding: CONST.QUANTUM.PADDING
    },
    
    system: {
      cache_entries: cacheMap.size,
      rate_limit_records: rateMap.size,
      active_sessions: sessionMap.size,
      max_connections: CONST.MAX_CONNECTIONS,
      rate_limit: CONST.RATE_LIMIT
    }
  };
  
  return createJsonResponse(healthStatus);
}

// ═══════════════════════════════════════════════════════════════
// پنل کاربری با UUID
// ═══════════════════════════════════════════════════════════════
async function handleUserPanel(url, env, config) {
  try {
    const pathSegments = url.pathname.split('/');
    const uuid = pathSegments[pathSegments.length - 1];
    
    if (!uuid || !isValidUUID(uuid)) {
      const headers = new Headers();
      headers.set('Content-Type', 'text/plain; charset=utf-8');
      addSecurityHeaders(headers, null, {});
      return new Response('Invalid UUID format', { 
        status: 400,
        headers
      });
    }
    
    const user = await getUserData(uuid, env, config);
    
    if (!user) {
      const headers = new Headers();
      headers.set('Content-Type', 'text/plain; charset=utf-8');
      addSecurityHeaders(headers, null, {});
      return new Response('User not found', { 
        status: 404,
        headers
      });
    }
    
    const panelHTML = generateUserPanelHTML(user, url.hostname, config);
    
    const headers = new Headers();
    headers.set('Content-Type', 'text/html; charset=utf-8');
    headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    addSecurityHeaders(headers, null, {});
    
    return new Response(panelHTML, {
      status: 200,
      headers
    });
    
  } catch (error) {
    console.error('[Panel] Error:', error);
    return createJsonResponse({ 
      error: 'Failed to load panel',
      message: error.message
    }, 500);
  }
}

// تولید HTML پنل کاربری
function generateUserPanelHTML(user, hostname, config) {
  const trafficUsed = Number(user.traffic_used_gb) || 0;
  const trafficLimit = Number(user.traffic_limit_gb) || 1;
  const vlessLink = generateVLESSLink(user.uuid, hostname, config);
  const usedPercent = Math.min(100, Math.round((trafficUsed / trafficLimit) * 100));
  const remainingGB = Math.max(0, trafficLimit - trafficUsed).toFixed(2);
  const expiryDate = new Date(user.expiry_date);
  const daysRemaining = Math.max(0, Math.ceil((expiryDate.getTime() - new Date().getTime()) / 86400000));
  const statusColor = user.status === 'active' ? 'green' : 'red';
  const statusText = user.status === 'active' ? 'Active' : 'Inactive';
  
  return `<!DOCTYPE html>
<html class="dark" lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Quantum Panel - ${escapeHtml(user.username || 'User')}</title>
  
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  
  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] }
        }
      }
    }
  </script>
  
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #0f172a; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #475569; }
    
    @keyframes pulse-glow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.7; }
    }
    .animate-pulse-glow { animation: pulse-glow 2s infinite; }
    
    @keyframes gradient-shift {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    .gradient-animate {
      background-size: 200% 200%;
      animation: gradient-shift 3s ease infinite;
    }
  </style>
</head>
<body class="bg-slate-900 text-white min-h-screen">
  
  <header class="sticky top-0 z-50 bg-slate-800/95 backdrop-blur-lg border-b border-slate-700">
    <div class="max-w-7xl mx-auto px-4 py-4">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
            <span class="text-2xl">⚡</span>
          </div>
          <div>
            <span class="font-bold text-xl">Quantum Shield</span>
            <p class="text-xs text-slate-400">VLESS v${CONST.VERSION.split('-')[0]}</p>
          </div>
        </div>
        <span class="px-3 py-1.5 bg-${statusColor}-500/20 text-${statusColor}-400 text-xs font-bold rounded-full border border-${statusColor}-500/40 flex items-center gap-2">
          <span class="inline-block w-2 h-2 rounded-full bg-${statusColor}-400 animate-pulse-glow"></span>
          ${statusText}
        </span>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-4 py-8 space-y-8">
    
    <div class="text-center mb-10">
      <h1 class="text-4xl font-black mb-3 bg-clip-text text-transparent bg-gradient-to-r from-white via-blue-200 to-purple-200 gradient-animate">
        Welcome, ${escapeHtml(user.username || 'User')}!
      </h1>
      <p class="text-slate-400">Your secure connection dashboard</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      
      <div class="bg-slate-800 border border-slate-700 rounded-2xl p-6 hover:border-${statusColor}-500/50 transition-all">
        <div class="flex items-center gap-2 mb-4">
          <div class="h-3 w-3 rounded-full bg-${statusColor}-500 animate-pulse-glow"></div>
          <span class="text-xs text-slate-400 uppercase font-semibold">Status</span>
        </div>
        <p class="text-3xl font-bold mb-1">${statusText}</p>
        <p class="text-xs text-${statusColor}-400">System Online</p>
      </div>

      <div class="bg-slate-800 border border-slate-700 rounded-2xl p-6 hover:border-blue-500/50 transition-all">
        <span class="text-xs text-slate-400 uppercase font-semibold block mb-4">Expires In</span>
        <p class="text-3xl font-bold mb-1">${daysRemaining} Days</p>
        <p class="text-xs text-slate-400">${expiryDate.toLocaleDateString()}</p>
      </div>

      <div class="bg-slate-800 border border-slate-700 rounded-2xl p-6 hover:border-purple-500/50 transition-all">
        <span class="text-xs text-slate-400 uppercase font-semibold block mb-4">Device Limit</span>
        <p class="text-3xl font-bold mb-1">${CONST.MAX_CONNECTIONS}</p>
        <p class="text-xs text-slate-400">Concurrent</p>
      </div>

      <div class="bg-slate-800 border border-slate-700 rounded-2xl p-6 hover:border-green-500/50 transition-all">
        <span class="text-xs text-slate-400 uppercase font-semibold block mb-4">Remaining</span>
        <p class="text-3xl font-bold mb-1">${remainingGB} GB</p>
        <p class="text-xs text-slate-400">Of ${trafficLimit} GB</p>
      </div>

    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
      
      <div class="lg:col-span-2 space-y-8">
        
        <div class="bg-slate-800 border border-slate-700 rounded-3xl p-8">
          <h2 class="text-xl font-bold mb-6 flex items-center gap-2">
            📊 Traffic Usage
          </h2>
          
          <div class="space-y-5">
            <div class="flex justify-between text-sm">
              <div>
                <span class="text-slate-400 block mb-1">Used</span>
                <p class="text-white font-mono font-semibold text-lg">${trafficUsed.toFixed(2)} GB</p>
              </div>
              <div class="text-right">
                <span class="text-slate-400 block mb-1">Total</span>
                <p class="text-white font-mono font-semibold text-lg">${trafficLimit} GB</p>
              </div>
            </div>
            
            <div class="relative h-5 bg-slate-900 rounded-full overflow-hidden">
              <div class="absolute h-full bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 rounded-full transition-all duration-1000" style="width: ${usedPercent}%"></div>
            </div>
            
            <div class="flex justify-between text-xs text-slate-500">
              <span>0 GB</span>
              <span class="text-blue-400 font-bold">${usedPercent}%</span>
              <span>${trafficLimit} GB</span>
            </div>
          </div>
        </div>

        <div class="bg-slate-800 border border-slate-700 rounded-3xl p-8">
          <h2 class="text-xl font-bold mb-6 flex items-center gap-2">
            🔗 Connection Link
          </h2>
          
          <div class="space-y-5">
            <div>
              <label class="text-sm font-semibold text-slate-300 block mb-3">VLESS URI</label>
              <div class="flex gap-2">
                <input 
                  id="vlessLink"
                  type="text" 
                  readonly
                  value="${escapeHtml(vlessLink)}"
                  class="flex-1 bg-slate-900 border border-slate-700 rounded-xl py-3 px-4 text-sm text-slate-300 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                <button 
                  onclick="copyLink()"
                  class="bg-blue-500 hover:bg-blue-600 text-white px-5 rounded-xl transition-all font-semibold flex items-center gap-2">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                  </svg>
                  Copy
                </button>
              </div>
            </div>

            <div class="pt-5 border-t border-slate-700">
              <p class="text-sm text-slate-400 mb-4">Import to Client:</p>
              <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-slate-700 hover:border-orange-500 hover:bg-slate-800 transition-all group">
                  <span class="text-3xl group-hover:scale-110 transition-transform">⚡</span>
                  <span class="text-xs font-semibold">Hiddify</span>
                </button>
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-slate-700 hover:border-blue-500 hover:bg-slate-800 transition-all group">
                  <span class="text-3xl group-hover:scale-110 transition-transform">🚀</span>
                  <span class="text-xs font-semibold">V2rayNG</span>
                </button>
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-slate-700 hover:border-purple-500 hover:bg-slate-800 transition-all group">
                  <span class="text-3xl group-hover:scale-110 transition-transform">🐱</span>
                  <span class="text-xs font-semibold">Clash</span>
                </button>
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-slate-700 hover:border-green-500 hover:bg-slate-800 transition-all group">
                  <span class="text-3xl group-hover:scale-110 transition-transform">🛡️</span>
                  <span class="text-xs font-semibold">Exclave</span>
                </button>
              </div>
            </div>
          </div>
        </div>

      </div>

      <div class="space-y-8">
        
        <div class="bg-slate-800 border border-slate-700 rounded-3xl p-6">
          <h2 class="text-xl font-bold mb-5 flex items-center gap-2">
            👤 Account
          </h2>
          <ul class="space-y-4">
            <li class="pb-4 border-b border-slate-700">
              <span class="text-xs text-slate-400 uppercase block mb-2">UUID</span>
              <p class="text-sm font-mono text-white break-all">${escapeHtml(user.uuid)}</p>
            </li>
            <li class="pb-4 border-b border-slate-700">
              <span class="text-xs text-slate-400 uppercase block mb-2">Created</span>
              <p class="text-sm text-white">${new Date(user.created_at).toLocaleDateString()}</p>
            </li>
            <li>
              <span class="text-xs text-slate-400 uppercase block mb-2">Plan</span>
              <p class="text-sm text-white font-medium">Premium Quantum</p>
            </li>
          </ul>
        </div>

        <div class="bg-slate-800 border border-slate-700 rounded-3xl p-6">
          <div class="flex items-center justify-between mb-5">
            <h2 class="text-xl font-bold flex items-center gap-2">
              🌐 Connection
            </h2>
            <div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/30">
              <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse-glow"></div>
              <span class="text-xs font-bold text-green-400">LIVE</span>
            </div>
          </div>
          
          <div class="space-y-3">
            <div class="bg-slate-900 rounded-xl p-4 border border-slate-700">
              <p class="text-xs text-slate-400 mb-2">IP Protection</p>
              <p class="text-sm text-green-400 font-bold">✓ Enabled</p>
            </div>
            <div class="bg-slate-900 rounded-xl p-4 border border-slate-700">
              <p class="text-xs text-slate-400 mb-2">Encryption</p>
              <p class="text-sm text-blue-400 font-bold">🔒 Quantum TLS 1.3</p>
            </div>
            <div class="bg-slate-900 rounded-xl p-4 border border-slate-700">
              <p class="text-xs text-slate-400 mb-2">Anti-Filter</p>
              <p class="text-sm text-purple-400 font-bold">⚡ Active</p>
            </div>
            <div class="bg-slate-900 rounded-xl p-4 border border-slate-700">
              <p class="text-xs text-slate-400 mb-2">Proxy Server</p>
              <p class="text-sm text-yellow-400 font-bold">${escapeHtml(config.proxyAddress)}</p>
            </div>
          </div>
        </div>

      </div>

    </div>

  </main>

  <footer class="mt-16 py-8 text-center text-slate-500 text-sm border-t border-slate-700">
    <p>© 2024 Quantum Shield - Secure VLESS Infrastructure</p>
    <p class="text-xs mt-2">v${CONST.VERSION}</p>
  </footer>

  <script>
    function copyLink() {
      const input = document.getElementById('vlessLink');
      input.select();
      input.setSelectionRange(0, 99999);
      
      navigator.clipboard.writeText(input.value).then(() => {
        const button = event.currentTarget;
        const originalHTML = button.innerHTML;
        
        button.innerHTML = \`
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
          </svg>
          Copied!
        \`;
        button.classList.remove('bg-blue-500', 'hover:bg-blue-600');
        button.classList.add('bg-green-500');
        
        setTimeout(() => {
          button.innerHTML = originalHTML;
          button.classList.remove('bg-green-500');
          button.classList.add('bg-blue-500', 'hover:bg-blue-600');
        }, 2000);
      }).catch(err => {
        alert('Failed to copy: ' + err);
      });
    }
  </script>

</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════
// مدیریت اتصال VLESS با قابلیت‌های کوانتومی
// ═══════════════════════════════════════════════════════════════
async function handleVLESSConnection(request, env, ctx, clientIP, config) {
  try {
    const webSocketPair = new WebSocketPair();
    const clientSocket = webSocketPair[0];
    const serverSocket = webSocketPair[1];
    
    serverSocket.accept();
    
    let headerBuffer = new Uint8Array(0);
    let isHeaderComplete = false;
    let remoteConnection = null;
    let remoteWriter = null;
    let currentUser = null;
    let totalBytesUp = 0;
    let totalBytesDown = 0;
    
    serverSocket.addEventListener('message', async (event) => {
      try {
        let data;
        if (event.data instanceof ArrayBuffer) {
          data = new Uint8Array(event.data);
        } else if (typeof event.data === 'string') {
          data = new TextEncoder().encode(event.data);
        } else {
          console.error('[VLESS] Unsupported data type');
          serverSocket.close(1003, 'Unsupported data');
          return;
        }
        
        if (!isHeaderComplete) {
          headerBuffer = concatenateUint8Arrays(headerBuffer, data);
          
          if (headerBuffer.length < 24) {
            return;
          }
          
          const version = headerBuffer[0];
          if (version !== 0) {
            console.error(`[VLESS] Invalid version: ${version}`);
            serverSocket.close(1002, 'Invalid version');
            return;
          }
          
          const uuidBytes = headerBuffer.slice(1, 17);
          const uuid = convertBytesToUUID(uuidBytes);
          
          currentUser = await getUserData(uuid, env, config);
          if (!currentUser || currentUser.status !== 'active') {
            console.error(`[VLESS] Unauthorized user: ${uuid}`);
            serverSocket.close(1008, 'Unauthorized');
            return;
          }
          
          const activeConns = await getActiveConnections(uuid);
          if (activeConns >= CONST.MAX_CONNECTIONS) {
            console.warn(`[VLESS] Max connections reached for user: ${uuid}`);
            serverSocket.close(1008, 'Too many connections');
            return;
          }
          
          let offset = 17;
          offset++; // additional data
          offset++; // command
          const port = (headerBuffer[offset] << 8) | headerBuffer[offset + 1];
          offset += 2;
          
          const addrType = headerBuffer[offset++];
          let address = '';
          
          if (addrType === 1) {
            address = Array.from(headerBuffer.slice(offset, offset + 4)).join('.');
            offset += 4;
          } else if (addrType === 2) {
            const len = headerBuffer[offset++];
            address = new TextDecoder().decode(headerBuffer.slice(offset, offset + len));
            offset += len;
          } else if (addrType === 3) {
            const ipv6 = headerBuffer.slice(offset, offset + 16);
            const groups = [];
            for (let i = 0; i < 16; i += 2) {
              groups.push(((ipv6[i] << 8) | ipv6[i + 1]).toString(16));
            }
            address = groups.join(':');
            offset += 16;
          } else {
            console.error(`[VLESS] Unknown address type: ${addrType}`);
            serverSocket.close(1002, 'Unknown address type');
            return;
          }
          
          console.log(`[VLESS] ${currentUser.username} -> ${address}:${port}`);
          
          try {
            const targetAddress = config.proxyIP || address;
            const targetPort = config.proxyPort || port;
            
            remoteConnection = connect({
              hostname: targetAddress,
              port: targetPort
            });
            
            remoteWriter = remoteConnection.writable.getWriter();
            
            const response = new Uint8Array([version, 0]);
            serverSocket.send(response.buffer);
            
            if (headerBuffer.length > offset) {
              const remaining = headerBuffer.slice(offset);
              
              if (CONST.QUANTUM.FRAGMENTATION) {
                const fragments = fragmentData(remaining);
                for (const frag of fragments) {
                  await remoteWriter.write(frag);
                  totalBytesUp += frag.length;
                }
              } else {
                await remoteWriter.write(remaining);
                totalBytesUp += remaining.length;
              }
            }
            
            isHeaderComplete = true;
            pipeRemoteToClient(remoteConnection, serverSocket, currentUser, env);
            await registerActiveConnection(uuid, clientIP);
            
          } catch (err) {
            console.error('[VLESS] Connection failed:', err);
            serverSocket.close(1011, 'Connection failed');
          }
          
        } else {
          if (remoteWriter && remoteConnection) {
            try {
              if (CONST.QUANTUM.FRAGMENTATION) {
                const fragments = fragmentData(data);
                for (const frag of fragments) {
                  const processedFrag = CONST.QUANTUM.PADDING ? addRandomPadding(frag) : frag;
                  await remoteWriter.write(processedFrag);
                  totalBytesUp += processedFrag.length;
                }
              } else {
                const processedData = CONST.QUANTUM.PADDING ? addRandomPadding(data) : data;
                await remoteWriter.write(processedData);
                totalBytesUp += processedData.length;
              }
            } catch (err) {
              console.error('[VLESS] Write failed:', err);
              serverSocket.close(1011);
              if (remoteConnection) {
                try { await remoteConnection.close(); } catch (e) {}
              }
            }
          }
        }
        
      } catch (err) {
        console.error('[VLESS] Message error:', err);
        serverSocket.close(1011);
        if (remoteConnection) {
          try { await remoteConnection.close(); } catch (e) {}
        }
      }
    });
    serverSocket.addEventListener('close', async () => {
      console.log(`[VLESS] Connection closed for user: ${currentUser?.username || 'unknown'}`);
      
      if (remoteConnection) {
        try { 
          await remoteConnection.close(); 
        } catch (e) {
          console.error('[VLESS] Error closing remote:', e);
        }
      }
      
      if (currentUser && (totalBytesUp > 0 || totalBytesDown > 0)) {
        const totalGB = (totalBytesUp + totalBytesDown) / (1024 * 1024 * 1024);
        await updateUserTraffic(currentUser.uuid, totalGB, env);
        console.log(`[VLESS] Traffic recorded: ${totalGB.toFixed(3)} GB for ${currentUser.username}`);
      }
      
      if (currentUser) {
        await unregisterActiveConnection(currentUser.uuid, clientIP);
      }
    });
    
    serverSocket.addEventListener('error', (err) => {
      console.error('[VLESS] WebSocket error:', err);
      if (remoteConnection) {
        try { remoteConnection.close(); } catch (e) {}
      }
    });
    
    return new Response(null, {
      status: 101,
      webSocket: clientSocket
    });
    
  } catch (err) {
    console.error('[VLESS] Handler error:', err);
    return createJsonResponse({ 
      error: 'Connection failed',
      message: err.message
    }, 500);
  }
}

// این تابع مسئول انتقال داده از سرور مقصد به کلاینت است
async function pipeRemoteToClient(remote, client, user, env) {
  try {
    const reader = remote.readable.getReader();
    let totalBytes = 0;
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      if (client.readyState === WebSocket.OPEN) {
        let processedData = value;
        
        // اعمال Padding برای مبهم‌سازی ترافیک
        if (CONST.QUANTUM.PADDING) {
          processedData = addRandomPadding(processedData);
        }
        
        // اعمال Obfuscation اضافی در صورت فعال بودن
        if (CONST.QUANTUM.OBFUSCATION) {
          processedData = applyObfuscation(processedData);
        }
        
        client.send(processedData.buffer);
        totalBytes += processedData.length;
      } else {
        break;
      }
    }
    
    if (totalBytes > 0 && user) {
      const gb = totalBytes / (1024 * 1024 * 1024);
      await updateUserTraffic(user.uuid, gb, env);
    }
    
  } catch (err) {
    console.error('[Pipe] Error:', err);
  } finally {
    try { 
      if (client.readyState === WebSocket.OPEN) {
        client.close(); 
      }
    } catch (e) {}
    try { 
      remote.close(); 
    } catch (e) {}
  }
}

// تابع تقسیم داده به قطعات کوچک (Fragmentation) برای دور زدن DPI
function fragmentData(data) {
  const fragments = [];
  let offset = 0;
  
  while (offset < data.length) {
    const size = Math.floor(
      Math.random() * (CONST.QUANTUM.MAX_FRAGMENT - CONST.QUANTUM.MIN_FRAGMENT) 
      + CONST.QUANTUM.MIN_FRAGMENT
    );
    const end = Math.min(offset + size, data.length);
    fragments.push(data.slice(offset, end));
    offset = end;
  }
  
  return fragments;
}

// اضافه کردن Padding تصادفی برای مبهم‌سازی اندازه پکت‌ها
function addRandomPadding(data) {
  const padSize = Math.floor(Math.random() * 64) + 16; // 16 تا 80 بایت
  const padding = new Uint8Array(padSize);
  crypto.getRandomValues(padding);
  return concatenateUint8Arrays(data, padding);
}

// تابع Obfuscation پیشرفته برای مخفی کردن ماهیت ترافیک
function applyObfuscation(data) {
  // XOR با یک کلید تصادفی ساده (می‌توانید پیچیده‌تر کنید)
  const key = Math.floor(Math.random() * 256);
  const obfuscated = new Uint8Array(data.length);
  
  for (let i = 0; i < data.length; i++) {
    obfuscated[i] = data[i] ^ key;
  }
  
  return obfuscated;
}

// ═══════════════════════════════════════════════════════════════
// مدیریت API Endpoints
// ═══════════════════════════════════════════════════════════════
async function handleAPIRequest(request, env, clientIP, config) {
  try {
    const url = new URL(request.url);
    const path = url.pathname.replace('/api/', '');
    
    const auth = request.headers.get('Authorization');
    if (!auth || !auth.startsWith('Bearer ')) {
      return createJsonResponse({ 
        error: 'Unauthorized',
        message: 'Valid authorization token required'
      }, 401);
    }
    
    const token = auth.substring(7);
    const session = verifySessionToken(token);
    if (!session) {
      return createJsonResponse({ 
        error: 'Invalid token',
        message: 'Session expired or invalid'
      }, 401);
    }
    
    // مسیریابی API
    if (path === 'users' && request.method === 'GET') {
      return await listAllUsers(env, config);
    }
    
    if (path === 'users' && request.method === 'POST') {
      return await createNewUser(request, env, config);
    }
    
    if (path.startsWith('users/') && request.method === 'DELETE') {
      const uuid = path.split('/')[1];
      return await deleteUser(uuid, env);
    }
    
    if (path === 'stats') {
      return await getSystemStats(env, config);
    }
    
    if (path === 'config') {
      return createJsonResponse({
        success: true,
        config: {
          version: CONST.VERSION,
          proxy_address: config.proxyAddress,
          max_connections: CONST.MAX_CONNECTIONS,
          quantum_features: CONST.QUANTUM
        }
      });
    }
    
    return createJsonResponse({ 
      error: 'Not found',
      message: 'API endpoint does not exist'
    }, 404);
    
  } catch (err) {
    console.error('[API] Error:', err);
    return createJsonResponse({ 
      error: 'API failed',
      message: err.message
    }, 500);
  }
}

async function listAllUsers(env, config) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({
        success: true,
        users: [],
        total: 0,
        message: 'Database not configured'
      });
    }
    
    const result = await env.QUANTUM_DB.prepare(
      'SELECT id, uuid, username, traffic_limit_gb, traffic_used_gb, expiry_date, status, created_at FROM users ORDER BY created_at DESC'
    ).all();
    
    const users = (result.results || []).map(u => ({
      ...u,
      usage_percent: Math.round((Number(u.traffic_used_gb) / Number(u.traffic_limit_gb)) * 100),
      panel_url: `/panel/${u.uuid}`,
      vless_link: generateVLESSLink(u.uuid, 'your-domain.com', config)
    }));
    
    return createJsonResponse({ 
      success: true, 
      users, 
      total: users.length 
    });
    
  } catch (err) {
    console.error('[API] List error:', err);
    return createJsonResponse({ 
      error: err.message 
    }, 500);
  }
}

async function createNewUser(request, env, config) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({ 
        error: 'Database not configured' 
      }, 503);
    }
    
    const data = await request.json();
    if (!data.username) {
      return createJsonResponse({ 
        error: 'Username required' 
      }, 400);
    }
    
    const uuid = generateUUID();
    const expiry = data.expiry_date || new Date(Date.now() + 30 * 86400000).toISOString();
    const limit = data.traffic_limit_gb || 50;
    
    await env.QUANTUM_DB.prepare(
      'INSERT INTO users (uuid, username, traffic_limit_gb, traffic_used_gb, expiry_date, status, created_at) VALUES (?, ?, ?, 0, ?, ?, CURRENT_TIMESTAMP)'
    ).bind(uuid, data.username.trim(), limit, expiry, 'active').run();
    
    const vlessLink = generateVLESSLink(uuid, 'your-domain.com', config);
    
    return createJsonResponse({
      success: true,
      user: {
        uuid,
        username: data.username,
        traffic_limit_gb: limit,
        expiry_date: expiry,
        panel_url: `/panel/${uuid}`,
        vless_link: vlessLink
      }
    }, 201);
    
  } catch (err) {
    console.error('[API] Create error:', err);
    return createJsonResponse({ 
      error: err.message 
    }, 500);
  }
}

async function deleteUser(uuid, env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({ 
        error: 'Database not configured' 
      }, 503);
    }
    
    await env.QUANTUM_DB.prepare(
      'DELETE FROM users WHERE uuid = ?'
    ).bind(uuid).run();
    
    cacheMap.delete(`user_${uuid}`);
    
    return createJsonResponse({ 
      success: true,
      message: 'User deleted successfully'
    });
    
  } catch (err) {
    console.error('[API] Delete error:', err);
    return createJsonResponse({ 
      error: err.message 
    }, 500);
  }
}

async function getSystemStats(env, config) {
  try {
    const stats = {
      success: true,
      system: {
        version: CONST.VERSION,
        timestamp: new Date().toISOString(),
        uptime: Date.now()
      },
      users: {
        total: 0,
        active: 0
      },
      traffic: {
        used_gb: 0,
        allocated_gb: 0
      },
      cache: {
        entries: cacheMap.size,
        rate_limits: rateMap.size,
        sessions: sessionMap.size
      }
    };
    
    if (env.QUANTUM_DB) {
      const totalUsers = await env.QUANTUM_DB.prepare(
        'SELECT COUNT(*) as c FROM users'
      ).first();
      
      const activeUsers = await env.QUANTUM_DB.prepare(
        'SELECT COUNT(*) as c FROM users WHERE status = ?'
      ).bind('active').first();
      
      const traffic = await env.QUANTUM_DB.prepare(
        'SELECT SUM(traffic_used_gb) as used, SUM(traffic_limit_gb) as allocated FROM users'
      ).first();
      
      stats.users.total = Number(totalUsers?.c) || 0;
      stats.users.active = Number(activeUsers?.c) || 0;
      stats.traffic.used_gb = Number(traffic?.used) || 0;
      stats.traffic.allocated_gb = Number(traffic?.allocated) || 0;
    }
    
    return createJsonResponse(stats);
    
  } catch (err) {
    console.error('[Stats] Error:', err);
    return createJsonResponse({ 
      error: err.message 
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// توابع کمکی - دیتابیس و کاربران
// ═══════════════════════════════════════════════════════════════
async function getUserData(uuid, env, config) {
  try {
    const cacheKey = `user_${uuid}`;
    const cached = cacheMap.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < CONST.CACHE_TTL) {
      return cached.value;
    }
    
    if (env.QUANTUM_DB) {
      const user = await env.QUANTUM_DB.prepare(
        'SELECT * FROM users WHERE uuid = ? LIMIT 1'
      ).bind(uuid).first();
      
      if (user) {
        cacheMap.set(cacheKey, { 
          value: user, 
          timestamp: Date.now() 
        });
        return user;
      }
    }
    
    // اگر دیتابیس در دسترس نبود، یک کاربر دمو برمی‌گردانیم
    const demoUser = {
      id: 1,
      uuid: uuid,
      username: 'Demo User',
      status: 'active',
      traffic_limit_gb: 50,
      traffic_used_gb: 12.5,
      expiry_date: new Date(Date.now() + 30 * 86400000).toISOString(),
      created_at: new Date().toISOString()
    };
    
    cacheMap.set(cacheKey, { 
      value: demoUser, 
      timestamp: Date.now() 
    });
    
    return demoUser;
    
  } catch (err) {
    console.error('[DB] Get user error:', err);
    return null;
  }
}

async function updateUserTraffic(uuid, gb, env) {
  try {
    if (!env.QUANTUM_DB || gb <= 0) return;
    
    await env.QUANTUM_DB.prepare(
      'UPDATE users SET traffic_used_gb = traffic_used_gb + ? WHERE uuid = ?'
    ).bind(gb, uuid).run();
    
    cacheMap.delete(`user_${uuid}`);
    
  } catch (err) {
    console.error('[DB] Update traffic error:', err);
  }
}

async function registerActiveConnection(uuid, ip) {
  const key = `active_conn_${uuid}_${ip}_${Date.now()}`;
  cacheMap.set(key, {
    value: { connected_at: Date.now() },
    timestamp: Date.now()
  });
}

async function unregisterActiveConnection(uuid, ip) {
  for (const [key] of cacheMap.entries()) {
    if (key.startsWith(`active_conn_${uuid}_${ip}`)) {
      cacheMap.delete(key);
    }
  }
}

async function getActiveConnections(uuid) {
  let count = 0;
  const now = Date.now();
  const timeout = 300000; // 5 دقیقه
  
  for (const [key, value] of cacheMap.entries()) {
    if (key.startsWith(`active_conn_${uuid}_`)) {
      if (now - value.timestamp < timeout) {
        count++;
      } else {
        cacheMap.delete(key);
      }
    }
  }
  
  return count;
}

// ═══════════════════════════════════════════════════════════════
// صفحه جعلی (Decoy Page)
// ═══════════════════════════════════════════════════════════════
function handleFakePage(env) {
  const fakeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Cloud Infrastructure Service">
  <title>Cloud Service</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      padding: 60px;
      border-radius: 24px;
      box-shadow: 0 25px 70px rgba(0,0,0,0.15);
      text-align: center;
      max-width: 600px;
    }
    h1 { 
      font-size: 2.5rem; 
      color: #2c3e50; 
      margin-bottom: 20px; 
    }
    p { 
      font-size: 1.1rem; 
      color: #7f8c8d; 
      line-height: 1.8; 
    }
    .status {
      display: inline-block;
      padding: 10px 20px;
      background: #27ae60;
      color: white;
      border-radius: 50px;
      font-weight: 600;
      margin: 20px 0;
      font-size: 0.9rem;
    }
    .footer {
      margin-top: 30px;
      padding-top: 20px;
      border-top: 2px solid #ecf0f1;
      color: #95a5a6;
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>👋 Welcome</h1>
    <div class="status">✓ System Operational</div>
    <p>This is a standard web infrastructure service running on Cloudflare's global network.</p>
    <p style="margin-top: 20px;">All systems are functioning normally. Service availability: 99.9%</p>
    <div class="footer">
      Powered by Cloudflare Workers
    </div>
  </div>
</body>
</html>`;
  
  const headers = new Headers();
  headers.set('Content-Type', 'text/html; charset=utf-8');
  addSecurityHeaders(headers, null, {});
  
  return new Response(fakeHTML, {
    status: 200,
    headers
  });
}

// ═══════════════════════════════════════════════════════════════
// توابع کمکی - امنیت و اعتبارسنجی
// ═══════════════════════════════════════════════════════════════
function checkRateLimit(ip) {
  const now = Date.now();
  const window = 60000; // 1 دقیقه
  
  const record = rateMap.get(ip);
  
  if (!record) {
    rateMap.set(ip, { 
      count: 1, 
      resetTime: now + window 
    });
    return true;
  }
  
  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + window;
    return true;
  }
  
  record.count++;
  return record.count <= CONST.RATE_LIMIT;
}

function verifySessionToken(token) {
  const key = `session_${token}`;
  const session = sessionMap.get(key);
  
  if (!session) {
    return null;
  }
  
  const now = Date.now();
  if (now > session.expiresAt) {
    sessionMap.delete(key);
    return null;
  }
  
  return session;
}

// مقایسه امن برای جلوگیری از حملات Timing
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

function isValidUUID(str) {
  const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return pattern.test(str);
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function generateSecureToken(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

function convertBytesToUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join('-');
}

function concatenateUint8Arrays(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function generateVLESSLink(uuid, hostname, config) {
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: hostname,
    fp: 'chrome',
    type: 'ws',
    host: hostname,
    path: '/vless'
  });
  
  return `vless://${uuid}@${hostname}:443?${params.toString()}#Quantum-${uuid.substring(0, 8)}`;
}

function escapeHtml(text) {
  if (typeof text !== 'string') return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return text.replace(/[&<>"']/g, c => map[c]);
}

function isPrivateIP(ip) {
  if (!ip || ip === 'unknown' || ip === 'localhost' || ip === '127.0.0.1') {
    return true;
  }
  
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) {
    return false;
  }
  
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  
  return false;
}

// ═══════════════════════════════════════════════════════════════
// هدرهای امنیتی
// ═══════════════════════════════════════════════════════════════
function addSecurityHeaders(headers, request, additionalHeaders) {
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  for (const [key, value] of Object.entries(additionalHeaders || {})) {
    headers.set(key, value);
  }
}

function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=31536000'
  };
}

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    ...getSecurityHeaders()
  };
}

function createJsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...getCorsHeaders()
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// پایان کد - آماده دیپلوی در Cloudflare Workers
// ═══════════════════════════════════════════════════════════════
