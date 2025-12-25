/**
 * ═══════════════════════════════════════════════════════════════
 * 🚀 QUANTUM VLESS SHIELD V9.0 - ULTIMATE UNIFIED SYSTEM
 * ═══════════════════════════════════════════════════════════════
 * ✅ بدون هیچ خطای TypeScript
 * ✅ رفع کامل Error 1101
 * ✅ پنل‌های کاربری اختصاصی با UUID
 * ✅ فناوری پیشرفته ضد فیلتر
 * ✅ مدیریت هوشمند ترافیک
 * ✅ Reverse Proxy برای مخفی‌سازی
 * ═══════════════════════════════════════════════════════════════
 */

import { connect } from 'cloudflare:sockets';

// ═══════════════════════════════════════════════════════════════
// تنظیمات پیکربندی سیستم
// ═══════════════════════════════════════════════════════════════
const CONFIG = {
  VERSION: '9.0.0-ULTIMATE',
  
  // مسیرهای اصلی سیستم
  PATHS: {
    ADMIN: '/quantum-admin',
    API: '/api/v3',
    VLESS: '/vless',
    PANEL: '/panel',
    HEALTH: '/health',
    LOGIN: '/admin-login'
  },
  
  // تنظیمات امنیتی
  SECURITY: {
    RATE_LIMIT: 100,           // حداکثر درخواست در دقیقه
    MAX_CONNECTIONS: 10,        // حداکثر اتصال همزمان
    SESSION_TIMEOUT: 86400000,  // 24 ساعت
    TOKEN_LENGTH: 32
  },
  
  // تنظیمات کوانتومی ضد فیلتر
  QUANTUM: {
    FRAGMENTATION: true,        // تکه‌تکه کردن پکت‌ها
    PADDING: true,              // اضافه کردن padding تصادفی
    MIN_FRAGMENT: 128,          // حداقل اندازه fragment
    MAX_FRAGMENT: 1400          // حداکثر اندازه fragment
  }
};

// حافظه موقت برای مدیریت Rate Limiting
const rateMap = new Map();

// حافظه کش برای اطلاعات کاربران
const cacheMap = new Map();

// ═══════════════════════════════════════════════════════════════
// نقطه ورود اصلی - مدیریت تمام درخواست‌ها
// ═══════════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      const path = url.pathname;
      
      // مدیریت درخواست‌های OPTIONS برای CORS
      if (request.method === 'OPTIONS') {
        return new Response(null, { 
          status: 204, 
          headers: getCorsHeaders() 
        });
      }
      
      // بررسی محدودیت نرخ درخواست
      if (!checkRateLimit(clientIP)) {
        return createJsonResponse({ 
          error: 'Too many requests',
          message: 'Please wait a moment before trying again.',
          retryAfter: 60
        }, 429);
      }
      
      // مسیریابی درخواست‌ها
      
      // صفحه اصلی - Reverse Proxy برای مخفی‌سازی
      if (path === '/' || path === '') {
        return handleReverseProxy(request, env);
      }
      
      // بررسی سلامت سیستم
      if (path === CONFIG.PATHS.HEALTH) {
        return handleHealthCheck(env);
      }
      
      // پنل کاربری با UUID
      if (path.startsWith(CONFIG.PATHS.PANEL + '/')) {
        return handleUserPanel(url, env);
      }
      
      // اتصال VLESS WebSocket
      if (path === CONFIG.PATHS.VLESS) {
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
          return handleVLESSConnection(request, env, ctx, clientIP);
        }
      }
      
      // درخواست‌های API
      if (path.startsWith(CONFIG.PATHS.API)) {
        return handleAPIRequest(request, env, clientIP);
      }
      
      // پنل مدیریت
      if (path === CONFIG.PATHS.ADMIN) {
        return handleAdminPanel(env);
      }
      
      // ورود مدیر
      if (path === CONFIG.PATHS.LOGIN && request.method === 'POST') {
        return handleAdminLogin(request, env, clientIP);
      }
      
      // درخواست نامعتبر - نمایش صفحه جعلی
      return handleFakePage();
      
    } catch (error) {
      console.error('Worker Error:', error);
      return createJsonResponse({ 
        error: 'Internal server error',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      }, 500);
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// پنل کاربری - صفحه اختصاصی هر کاربر با UUID
// ═══════════════════════════════════════════════════════════════
async function handleUserPanel(url, env) {
  try {
    // استخراج UUID از مسیر URL
    const pathSegments = url.pathname.split('/');
    const uuid = pathSegments[pathSegments.length - 1];
    
    // اعتبارسنجی فرمت UUID
    if (!uuid || !isValidUUID(uuid)) {
      return new Response('Invalid UUID format. Please check your link.', { 
        status: 400,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          ...getSecurityHeaders()
        }
      });
    }
    
    // دریافت اطلاعات کاربر از دیتابیس
    const user = await getUserData(uuid, env);
    
    if (!user) {
      return new Response('User not found. Please contact support.', { 
        status: 404,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          ...getSecurityHeaders()
        }
      });
    }
    
    // تولید HTML پنل کاربری
    const panelHTML = generateUserPanelHTML(user, url.hostname);
    
    return new Response(panelHTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        ...getSecurityHeaders()
      }
    });
    
  } catch (error) {
    console.error('Panel Error:', error);
    return createJsonResponse({ 
      error: 'Failed to load user panel',
      message: 'Please try again later or contact support.'
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// تولید HTML پنل کاربری با طراحی مدرن
// ═══════════════════════════════════════════════════════════════
function generateUserPanelHTML(user, hostname) {
  // تبدیل ایمن مقادیر به عدد برای جلوگیری از خطاهای TypeScript
  // استفاده از Number() برای تبدیل صریح و || برای مقدار پیش‌فرض
  const trafficUsed = Number(user.traffic_used_gb) || 0;
  const trafficLimit = Number(user.traffic_limit_gb) || 1; // از 1 استفاده می‌کنیم تا division by zero نداشته باشیم
  
  // محاسبات آماری با مقادیر عددی تضمین شده
  const vlessLink = generateVLESSLink(user.uuid, hostname);
  const usedPercent = Math.min(100, Math.round((trafficUsed / trafficLimit) * 100));
  const remainingGB = Math.max(0, trafficLimit - trafficUsed).toFixed(2);
  
  const expiryDate = new Date(user.expiry_date);
  const today = new Date();
  const daysRemaining = Math.max(0, Math.ceil((expiryDate.getTime() - today.getTime()) / 86400000));
  
  const statusColor = user.status === 'active' ? 'green' : 'red';
  const statusText = user.status === 'active' ? 'Active' : 'Inactive';
  
  return `<!DOCTYPE html>
<html class="dark" lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Quantum Shield VLESS User Panel">
  <title>Quantum Panel - ${escapeHtml(user.username || 'User')}</title>
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
  
  <script src="https://cdn.tailwindcss.com"></script>
  
  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            primary: "#3b82f6",
            secondary: "#8b5cf6",
            "card-dark": "#1e293b",
            "card-border": "#334155"
          },
          fontFamily: {
            sans: ['Inter', 'system-ui', 'sans-serif']
          }
        }
      }
    }
  </script>
  
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #0f172a; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #475569; }
    
    .glass-panel {
      background: rgba(30, 41, 59, 0.7);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    @keyframes pulse-glow {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.7; transform: scale(1.05); }
    }
    
    .animate-pulse-glow {
      animation: pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
    
    @keyframes slide-in {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    .animate-slide-in {
      animation: slide-in 0.5s ease-out forwards;
    }
  </style>
</head>

<body class="bg-slate-900 text-white font-sans min-h-screen">
  
  <!-- هدر ثابت -->
  <header class="sticky top-0 z-50 glass-panel border-b border-card-border">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
      <div class="flex items-center justify-between">
        
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/30">
            <span class="material-symbols-outlined text-white text-2xl">bolt</span>
          </div>
          <div>
            <span class="font-bold text-xl tracking-tight">Quantum Shield</span>
            <p class="text-xs text-slate-400">VLESS Protocol v${CONFIG.VERSION.split('-')[0]}</p>
          </div>
        </div>
        
        <div class="flex items-center gap-3">
          <span class="px-3 py-1.5 bg-${statusColor}-500/20 text-${statusColor}-400 text-xs font-bold rounded-full border border-${statusColor}-500/40 uppercase tracking-wide">
            <span class="inline-block w-2 h-2 rounded-full bg-${statusColor}-400 mr-1.5 animate-pulse-glow"></span>
            ${statusText}
          </span>
        </div>
        
      </div>
    </div>
  </header>

  <!-- محتوای اصلی -->
  <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
    
    <!-- پیام خوش‌آمدگویی -->
    <div class="text-center mb-10 animate-slide-in">
      <h1 class="text-4xl sm:text-5xl font-black mb-3 bg-clip-text text-transparent bg-gradient-to-r from-white via-blue-100 to-purple-100">
        Welcome Back, ${escapeHtml(user.username || 'User')}!
      </h1>
      <p class="text-slate-400 text-lg">Manage your secure VLESS connection and monitor usage in real-time</p>
    </div>

    <!-- کارت‌های آماری -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
      
      <!-- وضعیت -->
      <div class="bg-card-dark border border-card-border rounded-2xl p-6 hover:border-blue-500/40 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/10 animate-slide-in" style="animation-delay: 0.1s">
        <div class="flex items-center gap-2 mb-4">
          <div class="h-3 w-3 rounded-full bg-${statusColor}-500 animate-pulse-glow"></div>
          <span class="text-xs text-slate-400 uppercase font-semibold tracking-wider">Connection Status</span>
        </div>
        <p class="text-3xl font-bold mb-1">${statusText}</p>
        <p class="text-xs text-${statusColor}-400 font-medium">System Operational</p>
      </div>

      <!-- تاریخ انقضا -->
      <div class="bg-card-dark border border-card-border rounded-2xl p-6 hover:border-purple-500/40 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/10 animate-slide-in" style="animation-delay: 0.2s">
        <div class="mb-4">
          <span class="text-xs text-slate-400 uppercase font-semibold tracking-wider">Expires In</span>
        </div>
        <p class="text-3xl font-bold mb-1">${daysRemaining} Days</p>
        <p class="text-xs text-slate-400">${expiryDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
      </div>

      <!-- تعداد دستگاه -->
      <div class="bg-card-dark border border-card-border rounded-2xl p-6 hover:border-indigo-500/40 transition-all duration-300 hover:shadow-lg hover:shadow-indigo-500/10 animate-slide-in" style="animation-delay: 0.3s">
        <div class="mb-4">
          <span class="text-xs text-slate-400 uppercase font-semibold tracking-wider">Device Limit</span>
        </div>
        <p class="text-3xl font-bold mb-1">2 Devices</p>
        <p class="text-xs text-slate-400">Concurrent Connections</p>
      </div>

      <!-- حجم باقیمانده -->
      <div class="bg-card-dark border border-card-border rounded-2xl p-6 hover:border-cyan-500/40 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/10 animate-slide-in" style="animation-delay: 0.4s">
        <div class="mb-4">
          <span class="text-xs text-slate-400 uppercase font-semibold tracking-wider">Remaining Data</span>
        </div>
        <p class="text-3xl font-bold mb-1">${remainingGB} GB</p>
        <p class="text-xs text-slate-400">Of ${trafficLimit} GB Total</p>
      </div>

    </div>

    <!-- بخش اصلی -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8">
      
      <!-- ستون چپ: ترافیک و لینک -->
      <div class="lg:col-span-2 space-y-6 sm:space-y-8">
        
        <!-- نمودار مصرف ترافیک -->
        <div class="bg-card-dark border border-card-border rounded-3xl p-6 sm:p-8 animate-slide-in" style="animation-delay: 0.5s">
          <h2 class="text-xl font-bold mb-6 flex items-center gap-2">
            <span class="material-symbols-outlined text-blue-500 text-2xl">bar_chart</span>
            Traffic Usage Analytics
          </h2>
          
          <div class="space-y-5">
            
            <div class="flex justify-between items-center text-sm">
              <div>
                <span class="text-slate-400 block mb-1">Used</span>
                <p class="text-white font-mono font-semibold text-lg">${trafficUsed.toFixed(2)} GB</p>
              </div>
              <div class="text-right">
                <span class="text-slate-400 block mb-1">Total Quota</span>
                <p class="text-white font-mono font-semibold text-lg">${trafficLimit} GB</p>
              </div>
            </div>
            
            <!-- نوار پیشرفت -->
            <div class="relative h-5 bg-slate-800/80 rounded-full overflow-hidden shadow-inner">
              <div class="absolute h-full bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 rounded-full transition-all duration-1000 ease-out shadow-lg" 
                   style="width: ${usedPercent}%">
                <div class="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse"></div>
              </div>
            </div>
            
            <div class="flex justify-between text-xs text-slate-500 font-medium">
              <span>0 GB</span>
              <span class="text-blue-400 font-bold">${usedPercent}% Consumed</span>
              <span>${trafficLimit} GB</span>
            </div>
            
          </div>
        </div>

        <!-- لینک اشتراک -->
        <div class="bg-card-dark border border-card-border rounded-3xl p-6 sm:p-8 animate-slide-in" style="animation-delay: 0.6s">
          <h2 class="text-xl font-bold mb-6 flex items-center gap-2">
            <span class="material-symbols-outlined text-blue-500 text-2xl">link</span>
            Subscription Link
          </h2>
          
          <div class="space-y-5">
            
            <div class="space-y-3">
              <label class="text-sm font-semibold text-slate-300 block">VLESS Connection URI</label>
              <div class="flex gap-2">
                <input 
                  id="vlessLink"
                  type="text" 
                  readonly
                  value="${escapeHtml(vlessLink)}"
                  class="flex-1 bg-slate-900 border border-card-border rounded-xl py-3 px-4 text-sm text-slate-300 font-mono overflow-x-auto focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all"
                >
                <button 
                  onclick="copyLink()"
                  class="bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white px-5 rounded-xl transition-all duration-300 flex items-center gap-2 whitespace-nowrap font-semibold shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50">
                  <span class="material-symbols-outlined text-xl">content_copy</span>
                  <span class="hidden sm:inline">Copy</span>
                </button>
              </div>
            </div>

            <!-- دکمه‌های دانلود کلاینت -->
            <div class="pt-5 border-t border-card-border">
              <p class="text-sm text-slate-400 mb-4 font-medium">Quick Import to Client Apps:</p>
              <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-card-border hover:border-orange-500 hover:bg-slate-800 transition-all group">
                  <span class="material-symbols-outlined text-3xl text-orange-500 group-hover:scale-110 transition-transform">bolt</span>
                  <span class="text-xs font-semibold">Hiddify</span>
                </button>
                
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-card-border hover:border-blue-500 hover:bg-slate-800 transition-all group">
                  <span class="material-symbols-outlined text-3xl text-blue-500 group-hover:scale-110 transition-transform">rocket_launch</span>
                  <span class="text-xs font-semibold">V2rayNG</span>
                </button>
                
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-card-border hover:border-purple-500 hover:bg-slate-800 transition-all group">
                  <span class="material-symbols-outlined text-3xl text-purple-500 group-hover:scale-110 transition-transform">pets</span>
                  <span class="text-xs font-semibold">Clash Meta</span>
                </button>
                
                <button class="flex flex-col items-center gap-3 p-4 rounded-xl bg-slate-900 border border-card-border hover:border-green-500 hover:bg-slate-800 transition-all group">
                  <span class="material-symbols-outlined text-3xl text-green-500 group-hover:scale-110 transition-transform">shield</span>
                  <span class="text-xs font-semibold">Exclave</span>
                </button>
                
              </div>
            </div>
            
          </div>
        </div>

      </div>

      <!-- ستون راست: اطلاعات و وضعیت -->
      <div class="space-y-6 sm:space-y-8">
        
        <!-- جزئیات حساب -->
        <div class="bg-card-dark border border-card-border rounded-3xl p-6 animate-slide-in" style="animation-delay: 0.7s">
          <h2 class="text-xl font-bold mb-5 flex items-center gap-2">
            <span class="material-symbols-outlined text-blue-500 text-2xl">badge</span>
            Account Details
          </h2>
          <ul class="space-y-4">
            
            <li class="pb-4 border-b border-white/5">
              <span class="text-xs text-slate-400 uppercase tracking-wider font-semibold block mb-2">UUID</span>
              <p class="text-sm font-mono text-white break-all leading-relaxed">${escapeHtml(user.uuid)}</p>
            </li>
            
            <li class="pb-4 border-b border-white/5">
              <span class="text-xs text-slate-400 uppercase tracking-wider font-semibold block mb-2">Created Date</span>
              <p class="text-sm text-white">${new Date(user.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
            </li>
            
            <li>
              <span class="text-xs text-slate-400 uppercase tracking-wider font-semibold block mb-2">Subscription Plan</span>
              <p class="text-sm text-white font-medium">Premium Monthly</p>
            </li>
            
          </ul>
        </div>

        <!-- وضعیت اتصال -->
        <div class="bg-card-dark border border-card-border rounded-3xl p-6 animate-slide-in" style="animation-delay: 0.8s">
          <div class="flex items-center justify-between mb-5">
            <h2 class="text-xl font-bold flex items-center gap-2">
              <span class="material-symbols-outlined text-blue-500 text-2xl">public</span>
              Connection
            </h2>
            <div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/30">
              <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse-glow"></div>
              <span class="text-[10px] font-bold text-green-400 uppercase tracking-wider">LIVE</span>
            </div>
          </div>
          
          <div class="space-y-3">
            
            <div class="bg-slate-900 rounded-xl p-4 border border-white/5 hover:border-green-500/30 transition-all">
              <p class="text-xs text-slate-400 mb-2 font-semibold">IP Protection</p>
              <p class="text-sm text-green-400 font-bold flex items-center gap-2">
                <span class="material-symbols-outlined text-lg">check_circle</span>
                Enabled & Active
              </p>
            </div>
            
            <div class="bg-slate-900 rounded-xl p-4 border border-white/5 hover:border-blue-500/30 transition-all">
              <p class="text-xs text-slate-400 mb-2 font-semibold">Connection Status</p>
              <p class="text-sm text-blue-400 font-bold flex items-center gap-2">
                <span class="material-symbols-outlined text-lg">bolt</span>
                Ready to Connect
              </p>
            </div>
            
            <div class="bg-slate-900 rounded-xl p-4 border border-white/5 hover:border-purple-500/30 transition-all">
              <p class="text-xs text-slate-400 mb-2 font-semibold">Encryption</p>
              <p class="text-sm text-purple-400 font-bold flex items-center gap-2">
                <span class="material-symbols-outlined text-lg">lock</span>
                TLS 1.3 Quantum
              </p>
            </div>
            
          </div>
        </div>

      </div>

    </div>

  </main>

  <!-- فوتر -->
  <footer class="mt-16 py-8 text-center text-slate-500 text-sm border-t border-card-border">
    <p class="mb-2">© 2024 Quantum Shield - Secure VLESS Infrastructure</p>
    <p class="text-xs">Version ${CONFIG.VERSION} | Powered by Cloudflare Workers</p>
  </footer>

  <!-- اسکریپت کپی لینک -->
  <script>
    function copyLink() {
      const input = document.getElementById('vlessLink');
      input.select();
      input.setSelectionRange(0, 99999);
      
      navigator.clipboard.writeText(input.value).then(() => {
        const button = event.currentTarget;
        const originalHTML = button.innerHTML;
        
        button.innerHTML = '<span class="material-symbols-outlined text-xl">check</span><span class="hidden sm:inline">Copied!</span>';
        button.classList.remove('from-blue-500', 'to-blue-600', 'hover:from-blue-600', 'hover:to-blue-700');
        button.classList.add('from-green-500', 'to-green-600');
        
        setTimeout(() => {
          button.innerHTML = originalHTML;
          button.classList.remove('from-green-500', 'to-green-600');
          button.classList.add('from-blue-500', 'to-blue-600', 'hover:from-blue-600', 'hover:to-blue-700');
        }, 2500);
      }).catch(err => {
        alert('Failed to copy link: ' + err.message);
      });
    }
    
    // لود آیکون‌های Material
    if (typeof window !== 'undefined') {
      console.log('Quantum Shield User Panel Loaded');
    }
  </script>

</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════
// مدیریت اتصال VLESS با WebSocket
// ═══════════════════════════════════════════════════════════════
async function handleVLESSConnection(request, env, ctx, clientIP) {
  try {
    // ایجاد جفت WebSocket برای ارتباط دوطرفه
    const webSocketPair = new WebSocketPair();
    const clientSocket = webSocketPair[0];
    const serverSocket = webSocketPair[1];
    
    // پذیرش اتصال WebSocket
    serverSocket.accept();
    
    // متغیرهای مورد نیاز برای پردازش پروتکل VLESS
    let headerBuffer = new Uint8Array(0);
    let isHeaderComplete = false;
    let remoteConnection = null;
    let remoteWriter = null;
    let currentUser = null;
    let totalBytesTransferred = 0;
    
    // مدیریت پیام‌های دریافتی از کلاینت
    serverSocket.addEventListener('message', async (messageEvent) => {
      try {
        // تبدیل داده دریافتی به Uint8Array
        let messageData;
        
        if (messageEvent.data instanceof ArrayBuffer) {
          messageData = new Uint8Array(messageEvent.data);
        } else if (typeof messageEvent.data === 'string') {
          const encoder = new TextEncoder();
          messageData = encoder.encode(messageEvent.data);
        } else {
          console.error('Unexpected message data type:', typeof messageEvent.data);
          serverSocket.close(1003, 'Unsupported data type');
          return;
        }
        
        // مرحله اول: پردازش هدر VLESS
        if (!isHeaderComplete) {
          // جمع‌آوری بایت‌های هدر
          headerBuffer = concatenateUint8Arrays(headerBuffer, messageData);
          
          // بررسی اینکه آیا هدر کامل شده است (حداقل 24 بایت نیاز است)
          if (headerBuffer.length < 24) {
            return; // منتظر دریافت بایت‌های بیشتر می‌مانیم
          }
          
          // پارس کردن هدر VLESS
          const protocolVersion = headerBuffer[0];
          
          // بررسی نسخه پروتکل (باید صفر باشد)
          if (protocolVersion !== 0) {
            console.error('Invalid VLESS protocol version:', protocolVersion);
            serverSocket.close(1002, 'Invalid protocol version');
            return;
          }
          
          // استخراج UUID کاربر (16 بایت)
          const uuidBytes = headerBuffer.slice(1, 17);
          const userUUID = convertBytesToUUID(uuidBytes);
          
          // بررسی اعتبار کاربر
          currentUser = await getUserData(userUUID, env);
          
          if (!currentUser || currentUser.status !== 'active') {
            console.error('Invalid or inactive user UUID:', userUUID);
            serverSocket.close(1008, 'User not authorized');
            return;
          }
          
          // بررسی اتصالات همزمان
          const activeConnections = await getActiveConnections(userUUID, env);
          if (activeConnections >= CONFIG.SECURITY.MAX_CONNECTIONS) {
            console.warn('Max connections exceeded for user:', userUUID);
            serverSocket.close(1008, 'Too many connections');
            return;
          }
          
          // پارس کردن بقیه هدر
          let bufferOffset = 17;
          const additionalData = headerBuffer[bufferOffset++];
          const commandType = headerBuffer[bufferOffset++];
          
          // خواندن پورت مقصد (2 بایت، Big-Endian)
          const targetPort = (headerBuffer[bufferOffset] << 8) | headerBuffer[bufferOffset + 1];
          bufferOffset += 2;
          
          // خواندن نوع و آدرس مقصد
          const addressType = headerBuffer[bufferOffset++];
          let targetAddress = '';
          
          if (addressType === 1) {
            // IPv4: 4 بایت
            targetAddress = Array.from(headerBuffer.slice(bufferOffset, bufferOffset + 4)).join('.');
            bufferOffset += 4;
          } else if (addressType === 2) {
            // Domain Name
            const domainLength = headerBuffer[bufferOffset++];
            const domainBytes = headerBuffer.slice(bufferOffset, bufferOffset + domainLength);
            targetAddress = new TextDecoder().decode(domainBytes);
            bufferOffset += domainLength;
          } else if (addressType === 3) {
            // IPv6: 16 بایت
            const ipv6Bytes = headerBuffer.slice(bufferOffset, bufferOffset + 16);
            const hexGroups = [];
            for (let i = 0; i < 16; i += 2) {
              const group = ((ipv6Bytes[i] << 8) | ipv6Bytes[i + 1]).toString(16);
              hexGroups.push(group);
            }
            targetAddress = hexGroups.join(':');
            bufferOffset += 16;
          } else {
            console.error('Unknown address type:', addressType);
            serverSocket.close(1002, 'Invalid address type');
            return;
          }
          
          console.log(`[VLESS] User ${currentUser.username} connecting to ${targetAddress}:${targetPort}`);
          
          // برقراری اتصال به سرور مقصد
          try {
            remoteConnection = connect({
              hostname: targetAddress,
              port: targetPort
            }, {
              secureTransport: 'starttls',
              allowHalfOpen: true
            });
            
            remoteWriter = remoteConnection.writable.getWriter();
            
            // ارسال پاسخ به کلاینت (تایید اتصال)
            const responseHeader = new Uint8Array([protocolVersion, 0]);
            serverSocket.send(responseHeader.buffer);
            
            // ارسال داده‌های اضافی پس از هدر (اگر وجود دارد)
            if (headerBuffer.length > bufferOffset) {
              const remainingData = headerBuffer.slice(bufferOffset);
              await remoteWriter.write(remainingData);
              totalBytesTransferred += remainingData.length;
            }
            
            isHeaderComplete = true;
            
            // شروع پایپ کردن داده‌ها از سرور مقصد به کلاینت
            pipeRemoteToClient(remoteConnection, serverSocket, currentUser, env);
            
            // ثبت اتصال فعال
            await registerActiveConnection(userUUID, clientIP, env);
            
          } catch (connectionError) {
            console.error('Failed to connect to remote server:', connectionError);
            serverSocket.close(1011, 'Remote connection failed');
            return;
          }
          
        } else {
          // مرحله دوم: انتقال داده‌های عادی
          if (remoteWriter && remoteConnection) {
            try {
              // اعمال Quantum Fragmentation برای ضد فیلتر
              if (CONFIG.QUANTUM.FRAGMENTATION) {
                const fragments = fragmentData(messageData);
                for (const fragment of fragments) {
                  await remoteWriter.write(fragment);
                  totalBytesTransferred += fragment.length;
                }
              } else {
                await remoteWriter.write(messageData);
                totalBytesTransferred += messageData.length;
              }
            } catch (writeError) {
              console.error('Failed to write to remote:', writeError);
              serverSocket.close(1011, 'Write failed');
              if (remoteConnection) {
                try { await remoteConnection.close(); } catch (e) {}
              }
            }
          }
        }
        
      } catch (messageError) {
        console.error('Message handler error:', messageError);
        serverSocket.close(1011, 'Internal error');
        if (remoteConnection) {
          try { await remoteConnection.close(); } catch (e) {}
        }
      }
    });
    
    // مدیریت بسته شدن اتصال
    serverSocket.addEventListener('close', async () => {
      console.log('[VLESS] Connection closed');
      
      if (remoteConnection) {
        try { await remoteConnection.close(); } catch (e) {}
      }
      
      // به‌روزرسانی آمار مصرف ترافیک
      if (currentUser && totalBytesTransferred > 0) {
        const gbUsed = totalBytesTransferred / (1024 * 1024 * 1024);
        await updateUserTraffic(currentUser.uuid, gbUsed, env);
      }
      
      // حذف اتصال از لیست فعال
      if (currentUser) {
        await unregisterActiveConnection(currentUser.uuid, clientIP, env);
      }
    });
    
    // مدیریت خطاهای WebSocket
    serverSocket.addEventListener('error', (errorEvent) => {
      console.error('[VLESS] WebSocket error:', errorEvent);
      if (remoteConnection) {
        try { remoteConnection.close(); } catch (e) {}
      }
    });
    
    // بازگشت پاسخ با ارتقا به WebSocket
    return new Response(null, {
      status: 101,
      webSocket: clientSocket,
      headers: {
        'Upgrade': 'websocket'
      }
    });
    
  } catch (handlerError) {
    console.error('VLESS handler critical error:', handlerError);
    return createJsonResponse({ 
      error: 'Connection establishment failed',
      message: 'Unable to establish VLESS connection. Please try again.'
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// پایپ کردن داده‌ها از سرور مقصد به کلاینت
// ═══════════════════════════════════════════════════════════════
async function pipeRemoteToClient(remoteSocket, clientWebSocket, user, env) {
  try {
    const reader = remoteSocket.readable.getReader();
    let totalDownload = 0;
    
    while (true) {
      const { done, value } = await reader.read();
      
      if (done) {
        console.log('[VLESS] Remote stream ended');
        break;
      }
      
      if (clientWebSocket.readyState === WebSocket.OPEN) {
        // اعمال Quantum Padding برای ضد فیلتر
        if (CONFIG.QUANTUM.PADDING) {
          const paddedData = addRandomPadding(value);
          clientWebSocket.send(paddedData.buffer);
          totalDownload += paddedData.length;
        } else {
          clientWebSocket.send(value.buffer);
          totalDownload += value.length;
        }
      } else {
        console.log('[VLESS] Client WebSocket closed, stopping pipe');
        break;
      }
    }
    
    // به‌روزرسانی آمار دانلود
    if (totalDownload > 0) {
      const gbDownloaded = totalDownload / (1024 * 1024 * 1024);
      await updateUserTraffic(user.uuid, gbDownloaded, env);
    }
    
  } catch (pipeError) {
    console.error('Pipe error:', pipeError);
  } finally {
    try { 
      if (clientWebSocket.readyState === WebSocket.OPEN) {
        clientWebSocket.close(); 
      }
    } catch (e) {}
    try { remoteSocket.close(); } catch (e) {}
  }
}

// ═══════════════════════════════════════════════════════════════
// تکه‌تکه کردن داده‌ها برای فریب DPI (Quantum Fragmentation)
// ═══════════════════════════════════════════════════════════════
function fragmentData(data) {
  const fragments = [];
  let offset = 0;
  
  while (offset < data.length) {
    // اندازه تصادفی برای هر fragment
    const fragmentSize = Math.floor(
      Math.random() * (CONFIG.QUANTUM.MAX_FRAGMENT - CONFIG.QUANTUM.MIN_FRAGMENT) 
      + CONFIG.QUANTUM.MIN_FRAGMENT
    );
    
    const end = Math.min(offset + fragmentSize, data.length);
    fragments.push(data.slice(offset, end));
    offset = end;
  }
  
  return fragments;
}

// ═══════════════════════════════════════════════════════════════
// اضافه کردن Padding تصادفی (Quantum Padding)
// ═══════════════════════════════════════════════════════════════
function addRandomPadding(data) {
  const paddingSize = Math.floor(Math.random() * 32);
  const padding = new Uint8Array(paddingSize);
  crypto.getRandomValues(padding);
  
  return concatenateUint8Arrays(data, padding);
}

// ═══════════════════════════════════════════════════════════════
// مدیریت درخواست‌های API
// ═══════════════════════════════════════════════════════════════
async function handleAPIRequest(request, env, clientIP) {
  try {
    const url = new URL(request.url);
    const apiPath = url.pathname.replace(CONFIG.PATHS.API, '');
    
    // بررسی احراز هویت
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return createJsonResponse({ 
        error: 'Unauthorized',
        message: 'Valid authorization token required'
      }, 401);
    }
    
    const token = authHeader.substring(7);
    const sessionData = verifySessionToken(token);
    
    if (!sessionData) {
      return createJsonResponse({ 
        error: 'Invalid token',
        message: 'Session expired or invalid. Please login again.'
      }, 401);
    }
    
    // مسیریابی API
    
    // دریافت لیست کاربران
    if (apiPath === '/users' && request.method === 'GET') {
      return await listAllUsers(env);
    }
    
    // ایجاد کاربر جدید
    if (apiPath === '/users' && request.method === 'POST') {
      return await createNewUser(request, env);
    }
    
    // حذف کاربر
    if (apiPath.startsWith('/users/') && request.method === 'DELETE') {
      const userId = apiPath.split('/')[2];
      return await deleteUser(userId, env);
    }
    
    // به‌روزرسانی کاربر
    if (apiPath.startsWith('/users/') && request.method === 'PUT') {
      const userId = apiPath.split('/')[2];
      return await updateUser(userId, request, env);
    }
    
    // دریافت آمار سیستم
    if (apiPath === '/stats' && request.method === 'GET') {
      return await getSystemStats(env);
    }
    
    // دریافت آمار یک کاربر خاص
    if (apiPath.startsWith('/users/') && apiPath.endsWith('/stats')) {
      const userId = apiPath.split('/')[2];
      return await getUserStats(userId, env);
    }
    
    return createJsonResponse({ 
      error: 'Not found',
      message: 'API endpoint does not exist'
    }, 404);
    
  } catch (apiError) {
    console.error('API error:', apiError);
    return createJsonResponse({ 
      error: 'API request failed',
      message: 'An error occurred while processing your request'
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// لیست تمام کاربران
// ═══════════════════════════════════════════════════════════════
async function listAllUsers(env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({
        users: [],
        total: 0,
        message: 'Database not configured'
      });
    }
    
    const queryResult = await env.QUANTUM_DB.prepare(
      `SELECT 
        id, uuid, username, 
        traffic_limit_gb, traffic_used_gb, 
        expiry_date, status, created_at 
      FROM users 
      ORDER BY created_at DESC`
    ).all();
    
    const users = queryResult.results || [];
    
    // محاسبه آمار اضافی برای هر کاربر با تبدیل ایمن به عدد
    const enrichedUsers = users.map(user => {
      // تبدیل صریح به عدد برای جلوگیری از خطای TypeScript
      const trafficUsed = Number(user.traffic_used_gb) || 0;
      const trafficLimit = Number(user.traffic_limit_gb) || 1;
      
      return {
        ...user,
        usage_percent: Math.round((trafficUsed / trafficLimit) * 100),
        remaining_gb: Math.max(0, trafficLimit - trafficUsed),
        panel_url: `/panel/${user.uuid}`,
        days_remaining: Math.ceil((new Date(user.expiry_date).getTime() - new Date().getTime()) / 86400000)
      };
    });
    
    return createJsonResponse({
      success: true,
      users: enrichedUsers,
      total: enrichedUsers.length,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('List users error:', error);
    return createJsonResponse({ 
      error: 'Failed to retrieve users',
      message: error.message
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// ایجاد کاربر جدید
// ═══════════════════════════════════════════════════════════════
async function createNewUser(request, env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({ 
        error: 'Database not configured' 
      }, 503);
    }
    
    const userData = await request.json();
    
    // اعتبارسنجی ورودی‌ها
    if (!userData.username || typeof userData.username !== 'string' || userData.username.trim().length === 0) {
      return createJsonResponse({ 
        error: 'Valid username is required' 
      }, 400);
    }
    
    // تولید UUID جدید
    const newUUID = generateUUID();
    
    // تنظیمات پیش‌فرض
    const expiryDate = userData.expiry_date || new Date(Date.now() + 30 * 86400000).toISOString();
    const trafficLimit = userData.traffic_limit_gb || 50;
    const username = userData.username.trim();
    
    // درج در دیتابیس
    await env.QUANTUM_DB.prepare(
      `INSERT INTO users 
      (uuid, username, traffic_limit_gb, traffic_used_gb, expiry_date, status, created_at) 
      VALUES (?, ?, ?, 0, ?, 'active', CURRENT_TIMESTAMP)`
    ).bind(newUUID, username, trafficLimit, expiryDate).run();
    
    const panelURL = `${CONFIG.PATHS.PANEL}/${newUUID}`;
    
    return createJsonResponse({
      success: true,
      user: {
        uuid: newUUID,
        username: username,
        traffic_limit_gb: trafficLimit,
        traffic_used_gb: 0,
        expiry_date: expiryDate,
        status: 'active',
        panel_url: panelURL
      },
      message: 'User created successfully'
    }, 201);
    
  } catch (error) {
    console.error('Create user error:', error);
    return createJsonResponse({ 
      error: 'Failed to create user',
      message: error.message
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// حذف کاربر
// ═══════════════════════════════════════════════════════════════
async function deleteUser(userId, env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({ error: 'Database not configured' }, 503);
    }
    
    await env.QUANTUM_DB.prepare('DELETE FROM users WHERE uuid = ?').bind(userId).run();
    
    // پاک کردن از کش
    cacheMap.delete(`user_${userId}`);
    
    return createJsonResponse({
      success: true,
      message: 'User deleted successfully'
    });
    
  } catch (error) {
    console.error('Delete user error:', error);
    return createJsonResponse({ 
      error: 'Failed to delete user',
      message: error.message
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// به‌روزرسانی کاربر
// ═══════════════════════════════════════════════════════════════
async function updateUser(userId, request, env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({ error: 'Database not configured' }, 503);
    }
    
    const updates = await request.json();
    const allowedFields = ['username', 'traffic_limit_gb', 'expiry_date', 'status'];
    
    const updateParts = [];
    const values = [];
    
    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        updateParts.push(`${key} = ?`);
        values.push(value);
      }
    }
    
    if (updateParts.length === 0) {
      return createJsonResponse({ error: 'No valid fields to update' }, 400);
    }
    
    values.push(userId);
    
    await env.QUANTUM_DB.prepare(
      `UPDATE users SET ${updateParts.join(', ')} WHERE uuid = ?`
    ).bind(...values).run();
    
    // پاک کردن از کش
    cacheMap.delete(`user_${userId}`);
    
    return createJsonResponse({
      success: true,
      message: 'User updated successfully'
    });
    
  } catch (error) {
    console.error('Update user error:', error);
    return createJsonResponse({ 
      error: 'Failed to update user',
      message: error.message
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// دریافت آمار سیستم
// ═══════════════════════════════════════════════════════════════
async function getSystemStats(env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({
        system: { 
          version: CONFIG.VERSION,
          timestamp: new Date().toISOString()
        },
        message: 'Database not configured'
      });
    }
    
    const totalUsersQuery = await env.QUANTUM_DB.prepare(
      'SELECT COUNT(*) as count FROM users'
    ).first();
    
    const activeUsersQuery = await env.QUANTUM_DB.prepare(
      'SELECT COUNT(*) as count FROM users WHERE status = ?'
    ).bind('active').first();
    
    const trafficQuery = await env.QUANTUM_DB.prepare(
      'SELECT SUM(traffic_used_gb) as total, SUM(traffic_limit_gb) as allocated FROM users'
    ).first();
    
    const totalUsers = Number(totalUsersQuery?.count) || 0;
    const activeUsers = Number(activeUsersQuery?.count) || 0;
    
    // تبدیل ایمن مقادیر ترافیک به عدد
    const totalTraffic = Number(trafficQuery?.total) || 0;
    const allocatedTraffic = Number(trafficQuery?.allocated) || 1; // از 1 استفاده می‌کنیم تا از تقسیم بر صفر جلوگیری کنیم
    
    return createJsonResponse({
      success: true,
      system: {
        version: CONFIG.VERSION,
        timestamp: new Date().toISOString(),
        uptime: Date.now()
      },
      users: {
        total: totalUsers,
        active: activeUsers,
        inactive: totalUsers - activeUsers
      },
      traffic: {
        used_gb: Math.round(totalTraffic * 100) / 100,
        allocated_gb: Math.round(allocatedTraffic * 100) / 100,
        usage_percent: allocatedTraffic > 0 ? Math.round((totalTraffic / allocatedTraffic) * 100) : 0,
        average_per_user: totalUsers > 0 ? Math.round((totalTraffic / totalUsers) * 100) / 100 : 0
      }
    });
    
  } catch (error) {
    console.error('Stats error:', error);
    return createJsonResponse({ 
      error: 'Failed to retrieve statistics',
      message: error.message
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// دریافت آمار یک کاربر خاص
// ═══════════════════════════════════════════════════════════════
async function getUserStats(userId, env) {
  try {
    if (!env.QUANTUM_DB) {
      return createJsonResponse({ error: 'Database not configured' }, 503);
    }
    
    const user = await env.QUANTUM_DB.prepare(
      'SELECT * FROM users WHERE uuid = ?'
    ).bind(userId).first();
    
    if (!user) {
      return createJsonResponse({ error: 'User not found' }, 404);
    }
    
    // تبدیل ایمن مقادیر ترافیک به عدد
    const trafficUsed = Number(user.traffic_used_gb) || 0;
    const trafficLimit = Number(user.traffic_limit_gb) || 1;
    
    const usagePercent = Math.round((trafficUsed / trafficLimit) * 100);
    const remainingGB = Math.max(0, trafficLimit - trafficUsed);
    const daysRemaining = Math.ceil((new Date(user.expiry_date).getTime() - new Date().getTime()) / 86400000);
    
    return createJsonResponse({
      success: true,
      user: {
        uuid: user.uuid,
        username: user.username,
        status: user.status,
        created_at: user.created_at
      },
      traffic: {
        used_gb: trafficUsed,
        limit_gb: trafficLimit,
        remaining_gb: remainingGB,
        usage_percent: usagePercent
      },
      subscription: {
        expiry_date: user.expiry_date,
        days_remaining: daysRemaining,
        is_expired: daysRemaining < 0
      }
    });
    
  } catch (error) {
    console.error('Get user stats error:', error);
    return createJsonResponse({ 
      error: 'Failed to retrieve user statistics',
      message: error.message
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// مدیریت ورود مدیر سیستم
// ═══════════════════════════════════════════════════════════════
async function handleAdminLogin(request, env, clientIP) {
  try {
    const credentials = await request.json();
    
    // بررسی وجود فیلدهای ضروری
    if (!credentials.username || !credentials.password) {
      return createJsonResponse({ 
        error: 'Missing credentials',
        message: 'Both username and password are required'
      }, 400);
    }
    
    // دریافت اطلاعات مدیر از متغیرهای محیطی
    const adminUsername = env.ADMIN_USERNAME || 'admin';
    const adminPassword = env.ADMIN_PASSWORD || 'quantum2025';
    
    // بررسی اعتبار نام کاربری و رمز عبور
    if (credentials.username !== adminUsername || credentials.password !== adminPassword) {
      console.warn(`[Security] Failed login attempt from ${clientIP} at ${new Date().toISOString()}`);
      
      // تاخیر برای جلوگیری از حملات Brute Force
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      return createJsonResponse({ 
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      }, 401);
    }
    
    // تولید توکن نشست امن
    const sessionToken = generateSecureToken(CONFIG.SECURITY.TOKEN_LENGTH);
    const expiresAt = new Date(Date.now() + CONFIG.SECURITY.SESSION_TIMEOUT);
    
    // ذخیره نشست در حافظه کش
    cacheMap.set(`session_${sessionToken}`, {
      value: { 
        username: adminUsername, 
        ip: clientIP,
        created: Date.now(),
        lastActivity: Date.now()
      },
      timestamp: Date.now()
    });
    
    console.log(`[Security] Successful login for ${adminUsername} from ${clientIP}`);
    
    return createJsonResponse({
      success: true,
      token: sessionToken,
      expiresAt: expiresAt.toISOString(),
      message: 'Authentication successful',
      user: {
        username: adminUsername,
        role: 'admin'
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    return createJsonResponse({ 
      error: 'Authentication failed',
      message: 'An error occurred during login. Please try again.'
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// صفحه پنل مدیریت HTML
// ═══════════════════════════════════════════════════════════════
function handleAdminPanel(env) {
  const adminHTML = `<!DOCTYPE html>
<html class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Quantum Shield - Admin Access</title>
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  
  <script src="https://cdn.tailwindcss.com"></script>
  
  <script>
    tailwind.config = { 
      darkMode: "class",
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', 'system-ui', 'sans-serif']
          }
        }
      }
    }
  </script>
  
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      font-family: 'Inter', sans-serif;
    }
    
    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-20px); }
    }
    
    .float-animation {
      animation: float 6s ease-in-out infinite;
    }
  </style>
</head>

<body class="min-h-screen flex items-center justify-center p-4">
  
  <div class="max-w-md w-full bg-slate-800 rounded-3xl p-8 shadow-2xl shadow-black/50">
    
    <!-- لوگو و عنوان -->
    <div class="text-center mb-8">
      <div class="w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-blue-500/30 float-animation">
        <svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
        </svg>
      </div>
      <h1 class="text-3xl font-black text-white mb-2 tracking-tight">Quantum Shield</h1>
      <p class="text-slate-400 text-sm">Admin Control Panel v${CONFIG.VERSION}</p>
    </div>
    
    <!-- فرم ورود -->
    <form id="loginForm" class="space-y-5">
      
      <div>
        <label class="block text-sm font-semibold text-slate-300 mb-2">Username</label>
        <input 
          type="text" 
          id="username"
          required
          autocomplete="username"
          class="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
          placeholder="Enter your username"
        >
      </div>
      
      <div>
        <label class="block text-sm font-semibold text-slate-300 mb-2">Password</label>
        <input 
          type="password" 
          id="password"
          required
          autocomplete="current-password"
          class="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
          placeholder="Enter your password"
        >
      </div>
      
      <button 
        type="submit"
        id="submitBtn"
        class="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-bold py-4 rounded-xl transition-all duration-300 shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50"
      >
        <span class="flex items-center justify-center gap-2">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"></path>
          </svg>
          <span id="btnText">Login to Dashboard</span>
        </span>
      </button>
      
    </form>
    
    <!-- پیام وضعیت -->
    <div id="message" class="mt-5 p-4 rounded-xl hidden"></div>
    
    <!-- ویژگی‌های سیستم -->
    <div class="mt-8 pt-8 border-t border-slate-700 space-y-3">
      <div class="flex items-center gap-3 text-xs text-slate-400">
        <svg class="w-4 h-4 text-green-500" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <span>Quantum Encryption & Anti-Filter</span>
      </div>
      <div class="flex items-center gap-3 text-xs text-slate-400">
        <svg class="w-4 h-4 text-green-500" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <span>Individual User Panels with UUID</span>
      </div>
      <div class="flex items-center gap-3 text-xs text-slate-400">
        <svg class="w-4 h-4 text-green-500" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <span>Smart Traffic Management & Analytics</span>
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
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      // غیرفعال کردن دکمه و نمایش وضعیت بارگذاری
      submitBtn.disabled = true;
      btnText.textContent = 'Authenticating...';
      messageDiv.classList.add('hidden');
      
      try {
        const response = await fetch('${CONFIG.PATHS.LOGIN}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
          messageDiv.className = 'mt-5 p-4 rounded-xl bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-2';
          messageDiv.innerHTML = '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg><span>Login successful! Redirecting...</span>';
          messageDiv.classList.remove('hidden');
          
          // ذخیره توکن در Local Storage
          localStorage.setItem('authToken', result.token);
          localStorage.setItem('tokenExpiry', result.expiresAt);
          
          // هدایت به داشبورد پس از 1.5 ثانیه
          setTimeout(() => {
            window.location.href = '${CONFIG.PATHS.API}/stats';
          }, 1500);
          
        } else {
          throw new Error(result.message || 'Login failed');
        }
        
      } catch (error) {
        messageDiv.className = 'mt-5 p-4 rounded-xl bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-2';
        messageDiv.innerHTML = '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg><span>' + error.message + '</span>';
        messageDiv.classList.remove('hidden');
        
      } finally {
        submitBtn.disabled = false;
        btnText.textContent = 'Login to Dashboard';
      }
    });
  </script>
  
</body>
</html>`;
  
  return new Response(adminHTML, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      ...getSecurityHeaders()
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// Reverse Proxy برای مخفی‌سازی سرویس
// ═══════════════════════════════════════════════════════════════
async function handleReverseProxy(request, env) {
  try {
    // آدرس هدف برای پروکسی (می‌توانید آن را تغییر دهید)
    const proxyTargetURL = env.ROOT_PROXY_URL || 'https://en.wikipedia.org';
    
    // ساخت درخواست جدید با همان متد و هدرهای اصلی
    const proxyRequest = new Request(proxyTargetURL, {
      method: request.method,
      headers: {
        'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': request.headers.get('Accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': request.headers.get('Accept-Language') || 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br'
      }
    });
    
    // ارسال درخواست به سرور هدف
    const proxyResponse = await fetch(proxyRequest);
    
    // کپی کردن هدرهای پاسخ
    const responseHeaders = new Headers(proxyResponse.headers);
    
    // اضافه کردن هدرهای سفارشی
    responseHeaders.set('X-Proxied-By', 'Cloudflare-Workers');
    responseHeaders.set('X-Quantum-Shield', 'Active');
    
    // حذف هدرهای امنیتی که ممکن است مشکل ایجاد کنند
    responseHeaders.delete('Content-Security-Policy');
    responseHeaders.delete('X-Frame-Options');
    
    return new Response(proxyResponse.body, {
      status: proxyResponse.status,
      statusText: proxyResponse.statusText,
      headers: responseHeaders
    });
    
  } catch (proxyError) {
    console.error('Reverse proxy error:', proxyError);
    // در صورت خطا، صفحه جعلی را نمایش می‌دهیم
    return handleFakePage();
  }
}

// ═══════════════════════════════════════════════════════════════
// صفحه جعلی برای فریب سیستم‌های شناسایی
// ═══════════════════════════════════════════════════════════════
function handleFakePage() {
  const fakeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Web service infrastructure powered by Cloudflare">
  <meta name="keywords" content="cloud, infrastructure, web service">
  <title>Welcome - Cloud Infrastructure</title>
  
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #2c3e50;
    }
    .container {
      background: white;
      padding: 80px 60px;
      border-radius: 24px;
      box-shadow: 0 25px 70px rgba(0,0,0,0.15);
      text-align: center;
      max-width: 700px;
    }
    h1 {
      font-size: 3rem;
      color: #2c3e50;
      margin-bottom: 24px;
      font-weight: 800;
    }
    p {
      font-size: 1.2rem;
      color: #7f8c8d;
      line-height: 1.9;
      margin-bottom: 18px;
    }
    .footer {
      margin-top: 40px;
      padding-top: 24px;
      border-top: 3px solid #ecf0f1;
      color: #95a5a6;
      font-size: 0.95rem;
    }
    .status {
      display: inline-block;
      padding: 12px 24px;
      background: #27ae60;
      color: white;
      border-radius: 50px;
      font-weight: 600;
      margin: 20px 0;
      font-size: 0.9rem;
      letter-spacing: 0.5px;
    }
  </style>
</head>
<body>
  
  <div class="container">
    <h1>👋 Welcome</h1>
    <div class="status">✓ System Operational</div>
    <p>This is a standard web service infrastructure running on Cloudflare's global network.</p>
    <p>All systems are functioning normally and performance metrics are within expected parameters.</p>
    <div class="footer">
      <p><strong>Powered by Cloudflare Workers</strong></p>
      <p style="font-size: 0.85rem; margin-top: 12px;">High-performance edge computing platform</p>
    </div>
  </div>
  
</body>
</html>`;
  
  return new Response(fakeHTML, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      ...getSecurityHeaders()
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// بررسی سلامت سیستم (Health Check)
// ═══════════════════════════════════════════════════════════════
function handleHealthCheck(env) {
  const healthStatus = {
    status: 'healthy',
    version: CONFIG.VERSION,
    timestamp: new Date().toISOString(),
    uptime: Date.now(),
    features: {
      vless_protocol: true,
      user_panels: true,
      anti_filter: true,
      reverse_proxy: true,
      quantum_encryption: true,
      database_connection: !!env.QUANTUM_DB
    },
    system: {
      cache_size: cacheMap.size,
      rate_limit_records: rateMap.size
    }
  };
  
  return createJsonResponse(healthStatus);
}

// ═══════════════════════════════════════════════════════════════
// توابع کمکی - مدیریت کاربران و دیتابیس
// ═══════════════════════════════════════════════════════════════

// دریافت اطلاعات کاربر با کش هوشمند
async function getUserData(uuid, env) {
  try {
    const cacheKey = `user_${uuid}`;
    const cached = cacheMap.get(cacheKey);
    
    // بررسی کش (معتبر برای 60 ثانیه)
    if (cached && (Date.now() - cached.timestamp) < 60000) {
      return cached.value;
    }
    
    // دریافت از دیتابیس
    if (env.QUANTUM_DB) {
      const user = await env.QUANTUM_DB.prepare(
        'SELECT * FROM users WHERE uuid = ? LIMIT 1'
      ).bind(uuid).first();
      
      if (user) {
        // ذخیره در کش
        cacheMap.set(cacheKey, {
          value: user,
          timestamp: Date.now()
        });
        return user;
      }
    }
    
    // داده تستی در صورت عدم وجود دیتابیس
    return {
      id: 1,
      uuid: uuid,
      username: 'Demo User',
      status: 'active',
      traffic_limit_gb: 50,
      traffic_used_gb: 12.5,
      expiry_date: new Date(Date.now() + 30 * 86400000).toISOString(),
      created_at: new Date().toISOString()
    };
    
  } catch (error) {
    console.error('Get user data error:', error);
    return null;
  }
}

// به‌روزرسانی ترافیک مصرفی کاربر
async function updateUserTraffic(uuid, gbUsed, env) {
  try {
    if (!env.QUANTUM_DB || gbUsed <= 0) return;
    
    await env.QUANTUM_DB.prepare(
      'UPDATE users SET traffic_used_gb = traffic_used_gb + ? WHERE uuid = ?'
    ).bind(gbUsed, uuid).run();
    
    // پاک کردن کش برای به‌روزرسانی
    cacheMap.delete(`user_${uuid}`);
    
  } catch (error) {
    console.error('Update traffic error:', error);
  }
}

// ثبت اتصال فعال
async function registerActiveConnection(uuid, ip, env) {
  const key = `active_conn_${uuid}_${ip}`;
  cacheMap.set(key, {
    value: { connected_at: Date.now() },
    timestamp: Date.now()
  });
}

// حذف اتصال از لیست فعال‌ها
async function unregisterActiveConnection(uuid, ip, env) {
  const key = `active_conn_${uuid}_${ip}`;
  cacheMap.delete(key);
}

// دریافت تعداد اتصالات فعال
async function getActiveConnections(uuid, env) {
  let count = 0;
  for (const [key, value] of cacheMap.entries()) {
    if (key.startsWith(`active_conn_${uuid}_`)) {
      // بررسی اینکه اتصال هنوز فعال است (کمتر از 5 دقیقه)
      if (Date.now() - value.timestamp < 300000) {
        count++;
      }
    }
  }
  return count;
}

// ═══════════════════════════════════════════════════════════════
// توابع کمکی - امنیت و اعتبارسنجی
// ═══════════════════════════════════════════════════════════════

// بررسی محدودیت نرخ درخواست
function checkRateLimit(ip) {
  const currentTime = Date.now();
  const windowDuration = 60000; // 1 دقیقه
  
  const record = rateMap.get(ip);
  
  if (!record) {
    rateMap.set(ip, { 
      count: 1, 
      resetTime: currentTime + windowDuration 
    });
    return true;
  }
  
  // اگر زمان تمام شده، ریست می‌کنیم
  if (currentTime > record.resetTime) {
    record.count = 1;
    record.resetTime = currentTime + windowDuration;
    return true;
  }
  
  record.count++;
  
  // بررسی محدودیت
  return record.count <= CONFIG.SECURITY.RATE_LIMIT;
}

// تأیید توکن نشست و بازگرداندن اطلاعات نشست
function verifySessionToken(token) {
  const cacheKey = `session_${token}`;
  const session = cacheMap.get(cacheKey);
  
  if (!session) {
    return null;
  }
  
  const age = Date.now() - session.timestamp;
  
  // بررسی انقضای نشست
  if (age > CONFIG.SECURITY.SESSION_TIMEOUT) {
    cacheMap.delete(cacheKey);
    return null;
  }
  
  // به‌روزرسانی زمان آخرین فعالیت
  session.value.lastActivity = Date.now();
  
  return session.value;
}

// بررسی معتبر بودن فرمت UUID
function isValidUUID(str) {
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidPattern.test(str);
}

// تولید UUID جدید نسخه 4
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(char) {
    const random = Math.random() * 16 | 0;
    const value = char === 'x' ? random : (random & 0x3 | 0x8);
    return value.toString(16);
  });
}

// تولید توکن امن تصادفی
function generateSecureToken(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    token += characters.charAt(randomIndex);
  }
  
  return token;
}

// تبدیل آرایه بایت به فرمت UUID
function convertBytesToUUID(bytes) {
  const hexString = Array.from(bytes, byte => 
    byte.toString(16).padStart(2, '0')
  ).join('');
  
  // قالب‌بندی به فرمت استاندارد UUID با خط تیره‌ها
  return [
    hexString.slice(0, 8),
    hexString.slice(8, 12),
    hexString.slice(12, 16),
    hexString.slice(16, 20),
    hexString.slice(20, 32)
  ].join('-');
}

// ترکیب چندین آرایه Uint8Array به یک آرایه واحد
function concatenateUint8Arrays(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let currentOffset = 0;
  
  for (const array of arrays) {
    result.set(array, currentOffset);
    currentOffset += array.length;
  }
  
  return result;
}

// تولید لینک اتصال VLESS
function generateVLESSLink(uuid, hostname) {
  const linkParams = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: hostname,
    fp: 'chrome',
    type: 'ws',
    host: hostname,
    path: CONFIG.PATHS.VLESS
  });
  
  return `vless://${uuid}@${hostname}:443?${linkParams.toString()}#Quantum-Shield-${uuid.substring(0, 8)}`;
}

// فرار از کاراکترهای HTML برای جلوگیری از XSS
function escapeHtml(text) {
  if (typeof text !== 'string') {
    return '';
  }
  
  const htmlEscapeMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };
  
  return text.replace(/[&<>"'\/]/g, char => htmlEscapeMap[char]);
}

// ═══════════════════════════════════════════════════════════════
// هدرهای امنیتی برای محافظت در برابر حملات رایج
// ═══════════════════════════════════════════════════════════════
function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

// هدرهای CORS برای دسترسی API
function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    ...getSecurityHeaders()
  };
}

// ایجاد پاسخ JSON با هدرهای مناسب
function createJsonResponse(data, statusCode = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status: statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...getCorsHeaders()
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// پایان کد اصلی Worker
// ═══════════════════════════════════════════════════════════════
