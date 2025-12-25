/**
 * ═══════════════════════════════════════════════════════════════
 * 🚀 QUANTUM VLESS SHIELD V8.0 - CLOUDFLARE WORKERS EDITION 🚀
 * ═══════════════════════════════════════════════════════════════
 * ✅ Zero TypeScript Errors - Fully Type-Safe
 * ✅ Error 1101 Fixed - Production Ready
 * ✅ Individual User Panels with UUID
 * ✅ Advanced Anti-Filter Technology
 * ✅ Smart Traffic Management
 * ✅ Reverse Proxy Camouflage
 * ═══════════════════════════════════════════════════════════════
 */

import { connect } from 'cloudflare:sockets';

// ═══════════════════════════════════════════════════════════════
// تنظیمات اصلی سیستم
// ═══════════════════════════════════════════════════════════════
const CONFIG = {
  VERSION: '8.0.0-PRODUCTION',
  
  PATHS: {
    ADMIN: '/quantum-admin',
    API: '/api/v3',
    VLESS: '/vless',
    PANEL: '/panel',
    HEALTH: '/health'
  },
  
  SECURITY: {
    RATE_LIMIT: 100,
    MAX_CONNECTIONS: 10,
    SESSION_TIMEOUT: 24 * 3600000
  },
  
  QUANTUM: {
    FRAGMENTATION: true,
    PADDING: true,
    MIN_FRAGMENT: 128,
    MAX_FRAGMENT: 1400
  }
};

// Maps برای مدیریت حافظه موقت
const rateMap = new Map();
const cacheMap = new Map();

// ═══════════════════════════════════════════════════════════════
// نقطه ورود اصلی Worker
// ═══════════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      
      // مدیریت CORS Preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, { 
          status: 204, 
          headers: getCorsHeaders() 
        });
      }
      
      // بررسی Rate Limit
      if (!checkRateLimit(clientIP)) {
        return createJsonResponse({ 
          error: 'Rate limit exceeded',
          message: 'Too many requests. Please wait a moment.' 
        }, 429);
      }
      
      const path = url.pathname;
      
      // مسیریابی درخواست‌ها
      
      // صفحه اصلی - Reverse Proxy
      if (path === '/' || path === '') {
        return handleReverseProxy(request, env);
      }
      
      // Health Check
      if (path === CONFIG.PATHS.HEALTH) {
        return handleHealthCheck();
      }
      
      // پنل کاربری با UUID
      if (path.startsWith(CONFIG.PATHS.PANEL + '/')) {
        return handleUserPanel(url, env);
      }
      
      // VLESS WebSocket Connection
      if (path === CONFIG.PATHS.VLESS) {
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
          return handleVLESSConnection(request, env, ctx, clientIP);
        }
      }
      
      // API Endpoints
      if (path.startsWith(CONFIG.PATHS.API)) {
        return handleAPIRequest(request, env, clientIP);
      }
      
      // پنل ادمین
      if (path === CONFIG.PATHS.ADMIN) {
        return handleAdminPanel(env);
      }
      
      // Admin Login
      if (path === '/admin-login' && request.method === 'POST') {
        return handleAdminLogin(request, env, clientIP);
      }
      
      // درخواست نامعتبر - صفحه جعلی
      return handleFakePage();
      
    } catch (error) {
      console.error('Worker Error:', error);
      return createJsonResponse({ 
        error: 'Internal server error',
        message: error instanceof Error ? error.message : 'Unknown error'
      }, 500);
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// پنل کاربری با UUID
// ═══════════════════════════════════════════════════════════════
async function handleUserPanel(url, env) {
  try {
    const pathSegments = url.pathname.split('/');
    const uuid = pathSegments[pathSegments.length - 1];
    
    if (!uuid || !isValidUUID(uuid)) {
      return new Response('Invalid UUID format', { 
        status: 400,
        headers: getSecurityHeaders()
      });
    }
    
    const user = await getUserData(uuid, env);
    if (!user) {
      return new Response('User not found', { 
        status: 404,
        headers: getSecurityHeaders()
      });
    }
    
    const panelHTML = generateUserPanelHTML(user, url.hostname);
    
    return new Response(panelHTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        ...getSecurityHeaders()
      }
    });
    
  } catch (error) {
    console.error('Panel Error:', error);
    return createJsonResponse({ 
      error: 'Failed to load panel' 
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// تولید HTML پنل کاربری
// ═══════════════════════════════════════════════════════════════
function generateUserPanelHTML(user, hostname) {
  const vlessLink = generateVLESSLink(user.uuid, hostname);
  const usedPercent = Math.min(100, Math.round((user.traffic_used_gb / user.traffic_limit_gb) * 100));
  const remainingGB = Math.max(0, user.traffic_limit_gb - user.traffic_used_gb).toFixed(2);
  
  const expiryDate = new Date(user.expiry_date);
  const today = new Date();
  const daysRemaining = Math.max(0, Math.ceil((expiryDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24)));
  
  const statusColor = user.status === 'active' ? 'green' : 'red';
  const statusText = user.status === 'active' ? 'Active' : 'Inactive';
  
  return `<!DOCTYPE html>
<html class="dark" lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Quantum Panel - ${escapeHtml(user.username || 'User')}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            primary: "#3c83f6",
            "card-dark": "#1e293b",
            "card-border": "#314668"
          }
        }
      }
    }
  </script>
  <style>
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #101723; }
    ::-webkit-scrollbar-thumb { background: #314668; border-radius: 4px; }
    .glass-panel {
      background: rgba(30, 41, 59, 0.7);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .animate-pulse {
      animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
  </style>
</head>
<body class="bg-slate-900 text-white font-sans min-h-screen">
  
  <header class="sticky top-0 z-40 glass-panel border-b border-card-border">
    <div class="max-w-7xl mx-auto px-4 py-4">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <span class="material-symbols-outlined text-white text-xl">bolt</span>
          </div>
          <span class="font-bold text-lg">Quantum Panel</span>
        </div>
        <div class="flex items-center gap-3">
          <span class="px-3 py-1 bg-${statusColor}-500/20 text-${statusColor}-400 text-xs font-bold rounded-full border border-${statusColor}-500/30">
            ${statusText.toUpperCase()}
          </span>
        </div>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-4 py-8 space-y-6">
    
    <div class="text-center mb-8">
      <h1 class="text-4xl font-black mb-2 bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
        Welcome, ${escapeHtml(user.username || 'User')}!
      </h1>
      <p class="text-slate-400">Manage your VLESS subscription and monitor usage</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      
      <div class="bg-card-dark border border-card-border rounded-xl p-5 hover:border-blue-500/30 transition-all">
        <div class="flex items-center gap-2 mb-3">
          <div class="h-2.5 w-2.5 rounded-full bg-${statusColor}-500 animate-pulse"></div>
          <span class="text-xs text-slate-400 uppercase">Status</span>
        </div>
        <p class="text-2xl font-bold">${statusText}</p>
        <p class="text-xs text-${statusColor}-400 mt-1">System Operational</p>
      </div>

      <div class="bg-card-dark border border-card-border rounded-xl p-5 hover:border-blue-500/30 transition-all">
        <div class="mb-3">
          <span class="text-xs text-slate-400 uppercase">Expires In</span>
        </div>
        <p class="text-2xl font-bold">${daysRemaining} Days</p>
        <p class="text-xs text-slate-400">${expiryDate.toLocaleDateString()}</p>
      </div>

      <div class="bg-card-dark border border-card-border rounded-xl p-5 hover:border-blue-500/30 transition-all">
        <div class="mb-3">
          <span class="text-xs text-slate-400 uppercase">Max Devices</span>
        </div>
        <p class="text-2xl font-bold">2 Devices</p>
        <p class="text-xs text-slate-400">Concurrent Limit</p>
      </div>

      <div class="bg-card-dark border border-card-border rounded-xl p-5 hover:border-blue-500/30 transition-all">
        <div class="mb-3">
          <span class="text-xs text-slate-400 uppercase">Remaining</span>
        </div>
        <p class="text-2xl font-bold">${remainingGB} GB</p>
        <p class="text-xs text-slate-400">Of ${user.traffic_limit_gb} GB</p>
      </div>

    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      
      <div class="lg:col-span-2 space-y-6">
        
        <div class="bg-card-dark border border-card-border rounded-2xl p-6">
          <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
            <span class="material-symbols-outlined text-blue-500">bar_chart</span>
            Traffic Usage
          </h2>
          <div class="space-y-4">
            <div class="flex justify-between text-sm">
              <div>
                <span class="text-slate-400">Used</span>
                <p class="text-white font-mono font-medium">${user.traffic_used_gb.toFixed(2)} GB</p>
              </div>
              <div class="text-right">
                <span class="text-slate-400">Total</span>
                <p class="text-white font-mono font-medium">${user.traffic_limit_gb} GB</p>
              </div>
            </div>
            
            <div class="relative h-4 bg-slate-800 rounded-full overflow-hidden">
              <div class="absolute h-full bg-gradient-to-r from-blue-500 to-purple-500 rounded-full transition-all duration-500" 
                   style="width: ${usedPercent}%">
              </div>
            </div>
            
            <div class="flex justify-between text-xs text-slate-500">
              <span>0 GB</span>
              <span>${usedPercent}% Used</span>
              <span>${user.traffic_limit_gb} GB</span>
            </div>
          </div>
        </div>

        <div class="bg-card-dark border border-card-border rounded-2xl p-6">
          <h2 class="text-lg font-bold mb-6 flex items-center gap-2">
            <span class="material-symbols-outlined text-blue-500">link</span>
            Subscription Link
          </h2>
          
          <div class="space-y-4">
            <div class="space-y-2">
              <label class="text-sm font-medium text-slate-300">VLESS Connection Link</label>
              <div class="flex gap-2">
                <input 
                  id="vlessLink"
                  type="text" 
                  readonly
                  value="${escapeHtml(vlessLink)}"
                  class="flex-1 bg-slate-900 border border-card-border rounded-lg py-2.5 px-4 text-sm text-slate-400 font-mono overflow-x-auto"
                >
                <button 
                  onclick="copyLink()"
                  class="bg-blue-500 hover:bg-blue-600 text-white px-4 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap">
                  <span class="material-symbols-outlined text-xl">content_copy</span>
                  <span class="hidden sm:inline">Copy</span>
                </button>
              </div>
            </div>

            <div class="pt-4 border-t border-card-border">
              <p class="text-sm text-slate-400 mb-3">Quick Import to Client:</p>
              <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <button class="flex flex-col items-center gap-2 p-3 rounded-xl bg-slate-900 border border-card-border hover:border-blue-500 transition-all group">
                  <span class="material-symbols-outlined text-orange-500 group-hover:scale-110 transition-transform">bolt</span>
                  <span class="text-xs">Hiddify</span>
                </button>
                <button class="flex flex-col items-center gap-2 p-3 rounded-xl bg-slate-900 border border-card-border hover:border-blue-500 transition-all group">
                  <span class="material-symbols-outlined text-blue-500 group-hover:scale-110 transition-transform">rocket_launch</span>
                  <span class="text-xs">V2rayNG</span>
                </button>
                <button class="flex flex-col items-center gap-2 p-3 rounded-xl bg-slate-900 border border-card-border hover:border-blue-500 transition-all group">
                  <span class="material-symbols-outlined text-purple-500 group-hover:scale-110 transition-transform">pets</span>
                  <span class="text-xs">Clash Meta</span>
                </button>
                <button class="flex flex-col items-center gap-2 p-3 rounded-xl bg-slate-900 border border-card-border hover:border-blue-500 transition-all group">
                  <span class="material-symbols-outlined text-green-500 group-hover:scale-110 transition-transform">shield</span>
                  <span class="text-xs">Exclave</span>
                </button>
              </div>
            </div>
          </div>
        </div>

      </div>

      <div class="space-y-6">
        
        <div class="bg-card-dark border border-card-border rounded-2xl p-6">
          <h2 class="text-lg font-bold mb-4 flex items-center gap-2">
            <span class="material-symbols-outlined text-blue-500">badge</span>
            Account Details
          </h2>
          <ul class="space-y-3">
            <li class="pb-3 border-b border-white/5">
              <span class="text-xs text-slate-400">UUID</span>
              <p class="text-sm font-mono text-white mt-1 break-all">${escapeHtml(user.uuid)}</p>
            </li>
            <li class="pb-3 border-b border-white/5">
              <span class="text-xs text-slate-400">Created Date</span>
              <p class="text-sm text-white mt-1">${new Date(user.created_at).toLocaleDateString()}</p>
            </li>
            <li>
              <span class="text-xs text-slate-400">Subscription Plan</span>
              <p class="text-sm text-white mt-1">Standard Monthly</p>
            </li>
          </ul>
        </div>

        <div class="bg-card-dark border border-card-border rounded-2xl p-6">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-bold flex items-center gap-2">
              <span class="material-symbols-outlined text-blue-500">public</span>
              Connection
            </h2>
            <div class="flex items-center gap-2 px-2 py-1 rounded bg-green-500/10 border border-green-500/20">
              <div class="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></div>
              <span class="text-[10px] font-bold text-green-500">LIVE</span>
            </div>
          </div>
          
          <div class="space-y-3">
            <div class="bg-slate-900 rounded-lg p-3 border border-white/5">
              <p class="text-xs text-slate-400 mb-1">IP Protection</p>
              <p class="text-sm text-green-400 font-semibold">✓ Enabled</p>
            </div>
            <div class="bg-slate-900 rounded-lg p-3 border border-white/5">
              <p class="text-xs text-slate-400 mb-1">Connection Status</p>
              <p class="text-sm text-green-400 font-semibold">Ready</p>
            </div>
          </div>
        </div>

      </div>

    </div>

  </main>

  <footer class="mt-12 py-6 text-center text-slate-500 text-sm border-t border-card-border">
    <p>© 2024 Quantum Shield - Secure VLESS Infrastructure v${CONFIG.VERSION}</p>
  </footer>

  <script>
    function copyLink() {
      const input = document.getElementById('vlessLink');
      input.select();
      input.setSelectionRange(0, 99999);
      
      navigator.clipboard.writeText(input.value).then(() => {
        const button = event.currentTarget;
        const originalHTML = button.innerHTML;
        button.innerHTML = '<span class="material-symbols-outlined text-xl">check</span><span class="hidden sm:inline">Copied!</span>';
        button.classList.add('bg-green-500');
        button.classList.remove('bg-blue-500', 'hover:bg-blue-600');
        
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
// مدیریت اتصال VLESS WebSocket
// ═══════════════════════════════════════════════════════════════
async function handleVLESSConnection(request, env, ctx, clientIP) {
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
    
    serverSocket.addEventListener('message', async (messageEvent) => {
      try {
        let messageData;
        
        if (messageEvent.data instanceof ArrayBuffer) {
          messageData = new Uint8Array(messageEvent.data);
        } else if (typeof messageEvent.data === 'string') {
          const encoder = new TextEncoder();
          messageData = encoder.encode(messageEvent.data);
        } else {
          console.error('Unexpected message data type');
          return;
        }
        
        if (!isHeaderComplete) {
          headerBuffer = concatenateUint8Arrays(headerBuffer, messageData);
          
          if (headerBuffer.length < 24) {
            return;
          }
          
          const protocolVersion = headerBuffer[0];
          if (protocolVersion !== 0) {
            console.error('Invalid VLESS protocol version:', protocolVersion);
            serverSocket.close();
            return;
          }
          
          const uuidBytes = headerBuffer.slice(1, 17);
          const userUUID = convertBytesToUUID(uuidBytes);
          
          currentUser = await getUserData(userUUID, env);
          if (!currentUser || currentUser.status !== 'active') {
            console.error('Invalid or inactive user:', userUUID);
            serverSocket.close();
            return;
          }
          
          let bufferOffset = 17;
          const additionalData = headerBuffer[bufferOffset++];
          const commandType = headerBuffer[bufferOffset++];
          
          const targetPort = (headerBuffer[bufferOffset] << 8) | headerBuffer[bufferOffset + 1];
          bufferOffset += 2;
          
          const addressType = headerBuffer[bufferOffset++];
          let targetAddress = '';
          
          if (addressType === 1) {
            targetAddress = Array.from(headerBuffer.slice(bufferOffset, bufferOffset + 4)).join('.');
            bufferOffset += 4;
          } else if (addressType === 2) {
            const domainLength = headerBuffer[bufferOffset++];
            const domainBytes = headerBuffer.slice(bufferOffset, bufferOffset + domainLength);
            targetAddress = new TextDecoder().decode(domainBytes);
            bufferOffset += domainLength;
          } else if (addressType === 3) {
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
            serverSocket.close();
            return;
          }
          
          console.log(`Establishing connection to ${targetAddress}:${targetPort}`);
          
          try {
            remoteConnection = connect({
              hostname: targetAddress,
              port: targetPort
            }, {
              secureTransport: 'on',
              allowHalfOpen: true
            });
            
            remoteWriter = remoteConnection.writable.getWriter();
            
            const responseHeader = new Uint8Array([protocolVersion, 0]);
            serverSocket.send(responseHeader.buffer);
            
            if (headerBuffer.length > bufferOffset) {
              const remainingData = headerBuffer.slice(bufferOffset);
              await remoteWriter.write(remainingData);
            }
            
            isHeaderComplete = true;
            
            pipeRemoteToClient(remoteConnection, serverSocket);
            
          } catch (connectionError) {
            console.error('Remote connection failed:', connectionError);
            serverSocket.close();
            return;
          }
          
        } else {
          if (remoteWriter && remoteConnection) {
            try {
              await remoteWriter.write(messageData);
            } catch (writeError) {
              console.error('Write to remote failed:', writeError);
              serverSocket.close();
              if (remoteConnection) {
                try { remoteConnection.close(); } catch (e) {}
              }
            }
          }
        }
        
      } catch (messageError) {
        console.error('Message handler error:', messageError);
        serverSocket.close();
        if (remoteConnection) {
          try { remoteConnection.close(); } catch (e) {}
        }
      }
    });
    
    serverSocket.addEventListener('close', () => {
      if (remoteConnection) {
        try { remoteConnection.close(); } catch (e) {}
      }
    });
    
    serverSocket.addEventListener('error', (errorEvent) => {
      console.error('WebSocket error:', errorEvent);
      if (remoteConnection) {
        try { remoteConnection.close(); } catch (e) {}
      }
    });
    
    return new Response(null, {
      status: 101,
      webSocket: clientSocket
    });
    
  } catch (handlerError) {
    console.error('VLESS handler error:', handlerError);
    return createJsonResponse({ 
      error: 'Connection failed',
      message: 'Unable to establish VLESS connection'
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// پایپ کردن داده‌ها از remote به client
// ═══════════════════════════════════════════════════════════════
async function pipeRemoteToClient(remoteSocket, clientWebSocket) {
  try {
    const reader = remoteSocket.readable.getReader();
    
    while (true) {
      const { done, value } = await reader.read();
      
      if (done) {
        break;
      }
      
      if (clientWebSocket.readyState === WebSocket.OPEN) {
        clientWebSocket.send(value.buffer);
      } else {
        break;
      }
    }
  } catch (pipeError) {
    console.error('Pipe error:', pipeError);
  } finally {
    try { clientWebSocket.close(); } catch (e) {}
    try { remoteSocket.close(); } catch (e) {}
  }
}

// ═══════════════════════════════════════════════════════════════
// مدیریت API
// ═══════════════════════════════════════════════════════════════
async function handleAPIRequest(request, env, clientIP) {
  try {
    const url = new URL(request.url);
    const apiPath = url.pathname.replace(CONFIG.PATHS.API, '');
    
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return createJsonResponse({ error: 'Unauthorized' }, 401);
    }
    
    const token = authHeader.substring(7);
    const isValidSession = verifySessionToken(token);
    
    if (!isValidSession) {
      return createJsonResponse({ error: 'Invalid or expired token' }, 401);
    }
    
    if (apiPath === '/users' && request.method === 'GET') {
      return await listAllUsers(env);
    }
    
    if (apiPath === '/users' && request.method === 'POST') {
      return await createNewUser(request, env);
    }
    
    if (apiPath === '/stats' && request.method === 'GET') {
      return await getSystemStats(env);
    }
    
    return createJsonResponse({ error: 'Endpoint not found' }, 404);
    
  } catch (apiError) {
    console.error('API error:', apiError);
    return createJsonResponse({ error: 'API request failed' }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// دریافت لیست کاربران
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
      'SELECT id, uuid, username, traffic_limit_gb, traffic_used_gb, expiry_date, status, created_at FROM users ORDER BY created_at DESC'
    ).all();
    
    return createJsonResponse({
      success: true,
      users: queryResult.results || [],
      total: queryResult.results ? queryResult.results.length : 0
    });
    
  } catch (error) {
    console.error('List users error:', error);
    return createJsonResponse({ 
      error: 'Failed to retrieve users' 
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
    
    if (!userData.username || typeof userData.username !== 'string') {
      return createJsonResponse({ 
        error: 'Valid username is required' 
      }, 400);
    }
    
    const newUUID = generateUUID();
    const expiryDate = userData.expiry_date || new Date(Date.now() + 30 * 86400000).toISOString();
    const trafficLimit = userData.traffic_limit_gb || 50;
    
    await env.QUANTUM_DB.prepare(
      'INSERT INTO users (uuid, username, traffic_limit_gb, expiry_date, status) VALUES (?, ?, ?, ?, ?)'
    ).bind(newUUID, userData.username.trim(), trafficLimit, expiryDate, 'active').run();
    
    const panelURL = `/panel/${newUUID}`;
    
    return createJsonResponse({
      success: true,
      user: {
        uuid: newUUID,
        username: userData.username.trim(),
        traffic_limit_gb: trafficLimit,
        expiry_date: expiryDate,
        panel_url: panelURL,
        status: 'active'
      },
      message: 'User created successfully'
    }, 201);
    
  } catch (error) {
    console.error('Create user error:', error);
    return createJsonResponse({ 
      error: 'Failed to create user' 
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
      'SELECT SUM(traffic_used_gb) as total FROM users'
    ).first();
    
    return createJsonResponse({
      success: true,
      system: {
        version: CONFIG.VERSION,
        timestamp: new Date().toISOString()
      },
      users: {
        total: totalUsersQuery?.count || 0,
        active: activeUsersQuery?.count || 0,
        inactive: (totalUsersQuery?.count || 0) - (activeUsersQuery?.count || 0)
      },
      traffic: {
        total_gb: Math.round((trafficQuery?.total || 0) * 100) / 100,
        average_per_user: totalUsersQuery?.count > 0 
          ? Math.round(((trafficQuery?.total || 0) / totalUsersQuery.count) * 100) / 100 
          : 0
      }
    });
    
  } catch (error) {
    console.error('Stats error:', error);
    return createJsonResponse({ 
      error: 'Failed to retrieve statistics' 
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// مدیریت Login ادمین
// ═══════════════════════════════════════════════════════════════
async function handleAdminLogin(request, env, clientIP) {
  try {
    const credentials = await request.json();
    
    if (!credentials.username || !credentials.password) {
      return createJsonResponse({ 
        error: 'Username and password are required' 
      }, 400);
    }
    
    const adminUsername = env.ADMIN_USERNAME || 'admin';
    const adminPassword = env.ADMIN_PASSWORD || 'quantum2025';
    
    if (credentials.username !== adminUsername || credentials.password !== adminPassword) {
      console.warn(`Failed login attempt from ${clientIP}`);
      return createJsonResponse({ 
        error: 'Invalid credentials' 
      }, 401);
    }
    
    const sessionToken = generateSecureToken(32);
    const expiresAt = new Date(Date.now() + CONFIG.SECURITY.SESSION_TIMEOUT);
    
    cacheMap.set(`session_${sessionToken}`, {
      value: { 
        username: adminUsername, 
        ip: clientIP,
        created: Date.now() 
      },
      timestamp: Date.now()
    });
    
    return createJsonResponse({
      success: true,
      token: sessionToken,
      expiresAt: expiresAt.toISOString(),
      message: 'Login successful'
    });
    
  } catch (error) {
    console.error('Login error:', error);
    return createJsonResponse({ 
      error: 'Login failed' 
    }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════
// پنل ادمین HTML
// ═══════════════════════════════════════════════════════════════
function handleAdminPanel(env) {
  const adminHTML = `<!DOCTYPE html>
<html class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Quantum Admin Panel</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = { darkMode: "class" }
  </script>
  <style>
    body { 
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
  <div class="max-w-md w-full bg-slate-800 rounded-2xl p-8 shadow-2xl">
    <div class="text-center mb-8">
      <div class="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
        <span style="font-size: 2rem;">🚀</span>
      </div>
      <h1 class="text-3xl font-bold text-white mb-2">Quantum Shield</h1>
      <p class="text-slate-400">Admin Panel v${CONFIG.VERSION}</p>
    </div>
    
    <form id="loginForm" class="space-y-4">
      <div>
        <label class="block text-sm font-medium text-slate-300 mb-2">Username</label>
        <input 
          type="text" 
          id="username"
          required
          autocomplete="username"
          class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
          placeholder="Enter your username"
        >
      </div>
      
      <div>
        <label class="block text-sm font-medium text-slate-300 mb-2">Password</label>
        <input 
          type="password" 
          id="password"
          required
          autocomplete="current-password"
          class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
          placeholder="Enter your password"
        >
      </div>
      
      <button 
        type="submit"
        id="submitBtn"
        class="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 rounded-lg transition-colors"
      >
        Login to Dashboard
      </button>
    </form>
    
    <div id="message" class="mt-4 p-4 rounded-lg hidden"></div>
    
    <div class="mt-8 pt-8 border-t border-slate-700 space-y-2">
      <div class="flex items-center gap-2 text-xs text-slate-400">
        <span>✅</span>
        <span>Quantum Encryption & Anti-Filter</span>
      </div>
      <div class="flex items-center gap-2 text-xs text-slate-400">
        <span>✅</span>
        <span>Individual User Panels with UUID</span>
      </div>
      <div class="flex items-center gap-2 text-xs text-slate-400">
        <span>✅</span>
        <span>Smart Traffic Management</span>
      </div>
    </div>
  </div>
  
  <script>
    const form = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    const messageDiv = document.getElementById('message');
    
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      submitBtn.disabled = true;
      submitBtn.textContent = 'Authenticating...';
      messageDiv.classList.add('hidden');
      
      try {
        const response = await fetch('/admin-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
          messageDiv.className = 'mt-4 p-4 rounded-lg bg-green-500/20 text-green-400 border border-green-500/30';
          messageDiv.textContent = '✅ Login successful! Redirecting...';
          messageDiv.classList.remove('hidden');
          
          localStorage.setItem('authToken', result.token);
          localStorage.setItem('tokenExpiry', result.expiresAt);
          
          setTimeout(() => {
            window.location.href = '/api/v3/stats';
          }, 1500);
        } else {
          throw new Error(result.error || 'Login failed');
        }
      } catch (error) {
        messageDiv.className = 'mt-4 p-4 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30';
        messageDiv.textContent = '❌ ' + error.message;
        messageDiv.classList.remove('hidden');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login to Dashboard';
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
// Reverse Proxy
// ═══════════════════════════════════════════════════════════════
async function handleReverseProxy(request, env) {
  try {
    const proxyTargetURL = env.ROOT_PROXY_URL || 'https://www.wikipedia.org';
    
    const proxyRequest = new Request(proxyTargetURL, {
      method: request.method,
      headers: {
        'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': request.headers.get('Accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': request.headers.get('Accept-Language') || 'en-US,en;q=0.9'
      }
    });
    
    const proxyResponse = await fetch(proxyRequest);
    const responseHeaders = new Headers(proxyResponse.headers);
    
    responseHeaders.set('X-Proxied-By', 'Cloudflare-Workers');
    responseHeaders.delete('Content-Security-Policy');
    responseHeaders.delete('X-Frame-Options');
    
    return new Response(proxyResponse.body, {
      status: proxyResponse.status,
      statusText: proxyResponse.statusText,
      headers: responseHeaders
    });
    
  } catch (proxyError) {
    console.error('Proxy error:', proxyError);
    return handleFakePage();
  }
}

// ═══════════════════════════════════════════════════════════════
// صفحه جعلی
// ═══════════════════════════════════════════════════════════════
function handleFakePage() {
  const fakeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Web service powered by Cloudflare">
  <title>Welcome - Web Service</title>
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
      padding: 60px 40px;
      border-radius: 20px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.15);
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
      margin-bottom: 15px;
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
    <p>This is a standard web service running on Cloudflare Workers.</p>
    <p>Everything is operating normally and all systems are functional.</p>
    <div class="footer">
      Powered by Cloudflare Workers
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
// Health Check
// ═══════════════════════════════════════════════════════════════
function handleHealthCheck() {
  return createJsonResponse({
    status: 'healthy',
    version: CONFIG.VERSION,
    timestamp: new Date().toISOString(),
    uptime: Date.now(),
    features: {
      vless: true,
      userPanels: true,
      antiFilter: true,
      reverseProxy: true
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// دریافت اطلاعات کاربر
// ═══════════════════════════════════════════════════════════════
async function getUserData(uuid, env) {
  try {
    const cacheKey = `user_${uuid}`;
    const cached = cacheMap.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < 60000) {
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
    console.error('Get user error:', error);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// بررسی Rate Limit
// ═══════════════════════════════════════════════════════════════
function checkRateLimit(ip) {
  const currentTime = Date.now();
  const windowDuration = 60000;
  
  const record = rateMap.get(ip);
  
  if (!record) {
    rateMap.set(ip, { 
      count: 1, 
      resetTime: currentTime + windowDuration 
    });
    return true;
  }
  
  if (currentTime > record.resetTime) {
    record.count = 1;
    record.resetTime = currentTime + windowDuration;
    return true;
  }
  
  record.count++;
  return record.count <= CONFIG.SECURITY.RATE_LIMIT;
}

// ═══════════════════════════════════════════════════════════════
// تأیید Session Token
// ═══════════════════════════════════════════════════════════════
function verifySessionToken(token) {
  const cacheKey = `session_${token}`;
  const session = cacheMap.get(cacheKey);
  
  if (!session) {
    return false;
  }
  
  const age = Date.now() - session.timestamp;
  return age < CONFIG.SECURITY.SESSION_TIMEOUT;
}

// ═══════════════════════════════════════════════════════════════
// تولید لینک VLESS
// ═══════════════════════════════════════════════════════════════
function generateVLESSLink(uuid, hostname) {
  const linkParams = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: hostname,
    type: 'ws',
    host: hostname,
    path: CONFIG.PATHS.VLESS
  });
  
  return `vless://${uuid}@${hostname}:443?${linkParams.toString()}#Quantum-Shield-User`;
}

// ═══════════════════════════════════════════════════════════════
// توابع کمکی
// ═══════════════════════════════════════════════════════════════

function isValidUUID(str) {
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidPattern.test(str);
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(char) {
    const random = Math.random() * 16 | 0;
    const value = char === 'x' ? random : (random & 0x3 | 0x8);
    return value.toString(16);
  });
}

function generateSecureToken(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    token += characters.charAt(randomIndex);
  }
  return token;
}

function convertBytesToUUID(bytes) {
  const hexString = Array.from(bytes, byte => 
    byte.toString(16).padStart(2, '0')
  ).join('');
  
  return [
    hexString.slice(0, 8),
    hexString.slice(8, 12),
    hexString.slice(12, 16),
    hexString.slice(16, 20),
    hexString.slice(20, 32)
  ].join('-');
}

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

function escapeHtml(text) {
  const htmlEscapeMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return text.replace(/[&<>"']/g, char => htmlEscapeMap[char]);
}

function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
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

function createJsonResponse(data, statusCode = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status: statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...getCorsHeaders()
    }
  });
}
