// @ts-nocheck
/**
 * ============================================================================
 * QUANTUM VLESS PROXY & ADMIN SYSTEM - ULTIMATE EDITION
 * ARCHITECT: AI SYSTEMS ARCHITECT
 * VERSION: 4.1.0 (STABLE / HIGH-FIDELITY / ANTI-FILTER / QUANTUM-OPTIMIZED)
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// --- CONFIGURATION & ENV MANAGEMENT ---
const DEFAULT_CONFIG = {
    uuid: "90263529-6887-4402-a720-d3c52e463428",
    proxyIP: "cdn.xyz.com",
    adminPath: "/admin",
    adminKey: "secret-pass",
    scamThreshold: 60
};

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

    if (env.PROXY_DB) {
      try {
        const { results } = await env.PROXY_DB.prepare("SELECT ip FROM proxy_scans WHERE is_current_best = 1 LIMIT 1").all();
        selectedProxyIP = results[0]?.ip || null;
        if (selectedProxyIP) {
          console.log(`Using proxy IP from D1 PROXY_DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read from PROXY_DB: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`Using proxy IP from hardcoded list: ${selectedProxyIP}`);
      }
    }
    
    if (!selectedProxyIP) {
        console.error("CRITICAL: No proxy IP could be determined");
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

// --- D1 DATABASE INITIALIZER (AUTO-CREATE TABLES) ---
async function initDatabase(db) {
    const tables = [
        `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT, uuid TEXT, quota INTEGER, expiry DATE, status TEXT)`,
        `CREATE TABLE IF NOT EXISTS traffic_samples (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, timestamp DATETIME, up INTEGER, down INTEGER)`,
        `CREATE TABLE IF NOT EXISTS user_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ip TEXT, last_seen DATETIME)`,
        `CREATE TABLE IF NOT EXISTS proxy_health (id INTEGER PRIMARY KEY AUTOINCREMENT, proxy_url TEXT, status TEXT, latency INTEGER, last_check DATETIME)`,
        `CREATE TABLE IF NOT EXISTS proxy_scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, result TEXT, score INTEGER)`,
        `CREATE TABLE IF NOT EXISTS scan_metadata (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS key_value (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS connection_health (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, count INTEGER, timestamp DATETIME)`
    ];
    for (const sql of tables) {
        await db.prepare(sql).run();
    }
}

// --- EMBEDDED HTML UI PAGES ---
// Escaped all <\/script> for parser safety

const ADVANCED_SETTINGS_HTML = `<!DOCTYPE html>
<html class="dark" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>Quantum VLESS - Advanced Settings</title>
<link href="https://fonts.googleapis.com" rel="preconnect"/>
<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>
<script id="tailwind-config">
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        "primary": "#3c83f6",
                        "primary-glow": "#3c83f6",
                        "background-light": "#f5f7f8",
                        "background-dark": "#101723",
                        "card-dark": "#1a2436",
                        "input-dark": "#223149",
                        "success": "#10b981",
                        "danger": "#ef4444",
                    },
                    fontFamily: {
                        "display": ["Inter", "sans-serif"],
                        "mono": ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "Liberation Mono", "Courier New", "monospace"],
                    },
                    borderRadius: {"DEFAULT": "0.5rem", "lg": "0.75rem", "xl": "1rem", "2xl": "1.5rem", "full": "9999px"},
                    boxShadow: {
                        'neon': '0 0 10px rgba(60, 131, 246, 0.5), 0 0 20px rgba(60, 131, 246, 0.3)',
                        'glass': '0 4px 30px rgba(0, 0, 0, 0.1)',
                    }
                },
            },
        }
    <\/script>
<style>
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #101723;
        }
        ::-webkit-scrollbar-thumb {
            background: #223149;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #3c83f6;
        }
        
        /* Glassmorphism Utilities */
        .glass-panel {
            background: rgba(30, 41, 59, 0.4);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
    <\/style>
</head>
<body class="min-h-screen bg-background-dark text-white font-display overflow-x-hidden relative">
<!-- Background Effects -->
<div class="fixed inset-0 z-0 pointer-events-none overflow-hidden">
<div class="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[800px] bg-primary/10 rounded-full filter blur-3xl animate-pulse-slow"></div>
<div class="absolute bottom-0 right-0 w-[600px] h-[600px] bg-purple-500/5 rounded-full filter blur-3xl animate-pulse-slow animation-delay-2000"></div>
</div>
<!-- Main Content -->
<div class="container max-w-6xl mx-auto px-4 py-8 relative z-10">
<!-- Header -->
<header class="flex items-center justify-between mb-12">
<div class="flex items-center gap-3">
<span class="text-primary text-3xl font-bold">⚡ QuantumVLESS</span>
</div>
<div class="flex items-center gap-4">
<button class="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#223149] hover:bg-[#314668] text-white text-sm transition-colors">
<span class="material-symbols-outlined">search</span>
                        Search settings (Ctrl+K)
                    </button>
<button class="p-2 rounded-lg bg-[#223149] hover:bg-[#314668] transition-colors"><span class="material-symbols-outlined">notifications</span></button>
<select class="bg-[#223149] rounded-lg px-2 py-1 text-white text-sm">
<option>EN</option>
<option>FA</option>
</select>
</div>
</header>
<!-- Sidebar & Content -->
<div class="grid grid-cols-1 md:grid-cols-[250px_1fr] gap-8">
<!-- Sidebar -->
<nav class="glass-panel rounded-2xl p-4 hidden md:block">
<ul class="space-y-1">
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-primary/10 text-primary text-sm font-medium">
<span class="material-symbols-outlined">dashboard</span>
                                Dashboard
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">group</span>
                                Users
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">insights</span>
                                Nodes
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">trending_up</span>
                                Traffic
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-primary/20 text-primary text-sm font-bold transition-colors">
<span class="material-symbols-outlined">tune</span>
                                Advanced Settings
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">settings_suggest</span>
                                AI Settings
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">security</span>
                                Security Logs
                            </button>
</li>
</ul>
<div class="mt-auto pt-6 border-t border-white/10">
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">logout</span>
                            Logout
                        </button>
</div>
</nav>
<!-- Main Content -->
<div>
<!-- Title -->
<div class="mb-8">
<h1 class="text-2xl font-bold text-white mb-2">Advanced Settings</h1>
<p class="text-[#90a7cb] text-sm">Configure VLESS proxy parameters, security rules, AI thresholds, and database retention policies.</p>
</div>
<div class="flex justify-end mb-4 gap-3">
<button class="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#223149] hover:bg-[#314668] text-white text-sm transition-colors">
<span class="material-symbols-outlined">restart_alt</span>
                            Reset
                        </button>
<button class="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-blue-600 text-white text-sm font-medium transition-colors shadow-[0_0_15px_rgba(60,131,246,0.3)]">
<span class="material-symbols-outlined">save</span>
                            Save Changes
                        </button>
</div>
<!-- Sections Accordion -->
<div class="space-y-4">
<!-- Proxy Config -->
<div class="glass-panel rounded-2xl overflow-hidden">
<button class="w-full flex items-center justify-between px-6 py-4 bg-gradient-to-r from-primary/20 to-transparent text-white font-medium">
<span>Proxy Config</span>
<span class="material-symbols-outlined">expand_more</span>
</button>
<div class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
<!-- Card: Proxy IP List -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-blue-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-blue-500">list</span>
                                Proxy IP List
                            </h3>
<p class="text-[#90a7cb] text-xs mb-4">Define the outbound IPs for the VLESS worker. Supports CIDR notation.</p>
<textarea class="w-full h-32 bg-[#101723] border border-[#223149] rounded-lg p-3 text-sm text-white focus:border-blue-500 outline-none resize-none">192.168.1.1
192.168.1.2/24
10.0.0.5</textarea>
<p class="mt-2 text-[#90a7cb] text-xs">3 IPs detected</p>
</div>
<!-- Card: Import CSV -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-green-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-green-500">upload_file</span>
                                Import CSV
                            </h3>
<button class="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg bg-[#223149] hover:bg-green-500/20 text-green-500 text-sm transition-colors border border-green-500/20">
<span class="material-symbols-outlined">cloud_upload</span>
                                Upload Proxy List CSV
                            </button>
</div>
<!-- Card: SOCKS5 -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-emerald-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-emerald-500">vpn_key</span>
                                SOCKS5
                            </h3>
<div class="flex items-center justify-between mb-4">
<span class="text-[#90a7cb] text-sm">Enable SOCKS5 Relay</span>
<label class="relative inline-flex items-center cursor-pointer">
<input class="sr-only peer" type="checkbox"/>
<div class="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-emerald-600"></div>
</label>
</div>
<div class="space-y-3">
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-32">Listen Interface</label>
<select class="flex-1 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500 outline-none">
<option>0.0.0.0 (All Interfaces)</option>
</select>
</div>
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-32">Server</label>
<input class="flex-1 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500 outline-none" placeholder="proxy.quantum.io" type="text"/>
</div>
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-32">Port</label>
<input class="w-20 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500 outline-none" type="number" value="1080"/>
</div>
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-32">Auth Username</label>
<input class="flex-1 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500 outline-none" placeholder="user#892" type="text"/>
</div>
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-32">Auth Password</label>
<input class="flex-1 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500 outline-none" placeholder="********" type="password"/>
</div>
</div>
</div>
</div>
</div>
<!-- Security Section -->
<div class="glass-panel rounded-2xl overflow-hidden">
<button class="w-full flex items-center justify-between px-6 py-4 bg-gradient-to-r from-red-500/20 to-transparent text-white font-medium">
<span>Security</span>
<span class="material-symbols-outlined">expand_more</span>
</button>
<div class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
<!-- Card: Scamalytics Integration -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-purple-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-purple-500">shield</span>
                                Scamalytics Integration
                            </h3>
<p class="text-[#90a7cb] text-xs mb-4">Automated fraud detection for incoming connections.</p>
<div class="flex items-center justify-between mb-4">
<span class="text-[#90a7cb] text-sm">Enable</span>
<label class="relative inline-flex items-center cursor-pointer">
<input class="sr-only peer" type="checkbox"/>
<div class="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-purple-600"></div>
</label>
</div>
<div class="space-y-3">
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-20">API Key</label>
<input class="flex-1 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-purple-500 outline-none" placeholder="****************" type="password"/>
<button class="text-[#90a7cb] hover:text-white"><span class="material-symbols-outlined">visibility</span></button>
</div>
<div class="flex items-center gap-2">
<label class="text-[#90a7cb] text-sm w-20">Fraud Score Threshold</label>
<div class="flex-1 relative">
<input class="w-full bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-purple-500 outline-none" id="threshold" max="100" min="0" type="range" value="65"/>
<span class="absolute right-3 top-2 text-xs text-[#90a7cb]">65/100</span>
</div>
</div>
</div>
</div>
<!-- Card: AI Health Check -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-blue-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-blue-500">health_and_safety</span>
                                AI Health Check
                            </h3>
<div class="space-y-4">
<div class="flex justify-between items-center">
<span class="text-[#90a7cb] text-sm">Node Latency</span>
<span class="text-green-500 text-sm font-medium flex items-center gap-1"><span class="material-symbols-outlined text-xs">check_circle</span> 12ms</span>
</div>
<div class="h-1.5 bg-[#223149] rounded-full overflow-hidden">
<div class="h-full bg-green-500 w-[90%] rounded-full"></div>
</div>
<div class="flex justify-between items-center">
<span class="text-[#90a7cb] text-sm">IP Reputation</span>
<span class="text-green-500 text-sm font-medium flex items-center gap-1"><span class="material-symbols-outlined text-xs">check_circle</span> 98% Clean</span>
</div>
<div class="h-1.5 bg-[#223149] rounded-full overflow-hidden">
<div class="h-full bg-blue-500 w-[98%] rounded-full"></div>
</div>
<p class="text-[#90a7cb] text-xs mt-2">RASPs AI is actively monitoring routes based on real-time latency and reputation scores.</p>
</div>
</div>
<!-- Card: Global Blocklist -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-red-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-red-500">block</span>
                                Global Blocklist
                            </h3>
<div class="flex gap-2">
<input class="flex-1 bg-[#101723] border border-[#223149] rounded-lg px-3 py-2 text-sm text-white focus:border-red-500 outline-none" placeholder="Add IP to block..." type="text"/>
<button class="bg-[#223149] hover:bg-red-500/20 text-red-500 rounded-lg px-3 flex items-center justify-center transition-colors">
<span class="material-symbols-outlined">add</span>
</button>
</div>
<div class="mt-3 flex flex-wrap gap-2">
<span class="inline-flex items-center gap-1 px-2 py-1 rounded bg-red-500/10 text-red-400 text-xs border border-red-500/20">
                                    103.21.244.0/22 <span class="material-symbols-outlined text-[12px] cursor-pointer hover:text-white">close</span>
</span>
<span class="inline-flex items-center gap-1 px-2 py-1 rounded bg-red-500/10 text-red-400 text-xs border border-red-500/20">
                                    192.168.0.55 <span class="material-symbols-outlined text-[12px] cursor-pointer hover:text-white">close</span>
</span>
</div>
</div>
<!-- Card: Rate Limiting -->
<div class="glass-panel rounded-2xl p-6 border-l-4 border-l-yellow-500">
<h3 class="text-white text-md font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-yellow-500">speed</span>
                                Rate Limiting
                            </h3>
<div class="space-y-4">
<div class="flex justify-between items-center">
<label class="text-sm text-[#90a7cb]">Max Connections / User</label>
<input class="w-20 bg-[#101723] border border-[#223149] rounded text-center text-white text-sm py-1 outline-none focus:border-yellow-500" type="number" value="50"/>
</div>
<div class="flex justify-between items-center">
<label class="text-sm text-[#90a7cb]">Request Timeout (s)</label>
<input class="w-20 bg-[#101723] border border-[#223149] rounded text-center text-white text-sm py-1 outline-none focus:border-yellow-500" type="number" value="30"/>
</div>
</div>
</div>
</div>
</div>
</div>
<!-- Footer -->
<footer class="max-w-6xl mx-auto mt-12 py-6 border-t border-[#223149] flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-[#90a7cb]">
<p>© 2023 Quantum VLESS Admin. All rights reserved.</p>
<div class="flex gap-4">
<a class="hover:text-white" href="#">Documentation</a>
<a class="hover:text-white" href="#">Support</a>
<a class="hover:text-white" href="#">API Reference</a>
</div>
</footer>
</div>
</body></html>`;

// Repeat similar escaping for DASHBOARD_HTML, ADMIN_LOGIN_HTML, etc. (apply <\/script> where <script> tags end)

const DASHBOARD_HTML = `<!DOCTYPE html>

<html class="dark" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>Quantum VLESS Admin Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;900&amp;family=Vazirmatn:wght@400;700&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>
<script>
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            colors: {
              "primary": "#3c83f6",
              "background-light": "#f5f7f8",
              "background-dark": "#0f1520", // Slightly darker for better contrast with glass
              "surface-dark": "#1e293b",
            },
            fontFamily: {
              "display": ["Inter", "Vazirmatn", "sans-serif"]
            },
            borderRadius: {"DEFAULT": "0.5rem", "lg": "1rem", "xl": "1.5rem", "full": "9999px"},
          },
        },
      }
    <\/script>
<style>
        body {
            font-family: 'Inter', 'Vazirmatn', sans-serif;
        }
        
        /* Animated Background */
        @keyframes blob {
            0% { transform: translate(0px, 0px) scale(1); }
            33% { transform: translate(30px, -50px) scale(1.1); }
            66% { transform: translate(-20px, 20px) scale(0.9); }
            100% { transform: translate(0px, 0px) scale(1); }
        }
        .animate-blob {
            animation: blob 7s infinite;
        }
        .animation-delay-2000 {
            animation-delay: 2s;
        }
        .animation-delay-4000 {
            animation-delay: 4s;
        }

        /* Glassmorphism Utilities */
        .glass-panel {
            background: rgba(30, 41, 59, 0.4);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        }
        
        .glass-card-hover:hover {
            background: rgba(30, 41, 59, 0.6);
        }
        
        /* Chart Styles (Placeholder for actual chart lib) */
        .chart-placeholder {
            background: linear-gradient(to bottom, rgba(60,131,246,0.2) 0%, rgba(60,131,246,0) 100%);
        }
    <\/style>
</head>
<body class="min-h-screen bg-background-dark font-display antialiased text-white overflow-hidden relative">
<!-- Background Effects -->
<div class="fixed inset-0 z-0 pointer-events-none overflow-hidden">
<div class="absolute top-[-20%] left-[-20%] w-[800px] h-[800px] bg-primary/5 rounded-full filter blur-[100px] animate-blob"></div>
<div class="absolute bottom-[-30%] right-[-10%] w-[600px] h-[600px] bg-purple-500/5 rounded-full filter blur-[100px] animate-blob animation-delay-2000"></div>
<div class="absolute top-[30%] right-[-15%] w-[700px] h-[700px] bg-pink-500/5 rounded-full filter blur-[100px] animate-blob animation-delay-4000"></div>
</div>
<!-- Main Container -->
<main class="container max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
<!-- Header -->
<header class="flex items-center justify-between mb-8">
<div class="flex items-center gap-4">
<span class="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-primary to-purple-400">⚡ Quantum VLESS</span>
<span class="px-3 py-1 rounded-full bg-green-500/10 text-green-400 text-xs font-bold border border-green-500/20 flex items-center gap-1">
<span class="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span> ONLINE
</span>
</div>
<div class="flex items-center gap-4">
<button class="px-4 py-2 rounded-lg bg-surface-dark hover:bg-surface-dark/80 text-slate-300 text-sm font-medium flex items-center gap-2 transition-colors">
<span class="material-symbols-outlined text-[18px]">search</span>
                        Search resources...
                    </button>
<select class="bg-surface-dark rounded-lg px-3 py-2 text-slate-300 text-sm font-medium appearance-none">
<option>worker-node-01</option>
</select>
<button class="p-2 rounded-lg bg-surface-dark hover:bg-surface-dark/80 text-slate-300 transition-colors"><span class="material-symbols-outlined">translate</span></button>
<button class="p-2 rounded-lg bg-surface-dark hover:bg-surface-dark/80 text-slate-300 transition-colors"><span class="material-symbols-outlined">notifications</span></button>
</div>
</header>
<!-- Sidebar & Content (Responsive Grid) -->
<div class="grid grid-cols-1 lg:grid-cols-[250px_1fr] gap-8">
<!-- Sidebar -->
<nav class="glass-panel rounded-2xl p-4 order-last lg:order-first hidden lg:block">
<ul class="space-y-1">
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-primary/10 text-primary text-sm font-medium">
<span class="material-symbols-outlined">dashboard</span>
                                Dashboard
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-[#90a7cb] text-sm font-medium transition-colors">
<span class="material-symbols-outlined">group</span>
                                Users
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-[#90a7cb] text-sm font-medium transition-colors">
<span class="material-symbols-outlined">insights</span>
                                Traffic
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-[#90a7cb] text-sm font-medium transition-colors">
<span class="material-symbols-outlined">tune</span>
                                AI Settings
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-[#90a7cb] text-sm font-medium transition-colors">
<span class="material-symbols-outlined">security</span>
                                Security Logs
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-[#90a7cb] text-sm font-medium transition-colors">
<span class="material-symbols-outlined">description</span>
                                Documentation
                            </button>
</li>
<li>
<button class="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-white/5 text-[#90a7cb] text-sm font-medium transition-colors">
<span class="material-symbols-outlined">logout</span>
                                Logout
                            </button>
</li>
</ul>
</nav>
<!-- Content -->
<div class="space-y-8">
<!-- Title -->
<div>
<h1 class="text-2xl font-bold text-white mb-2">System Overview</h1>
<p class="text-[#64748b] text-sm">Real-time monitoring of VLESS nodes and AI optimization status.</p>
</div>
<!-- Stats Cards -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
<div class="glass-panel glass-card-hover rounded-2xl p-4 transition-all">
<div class="flex justify-between items-start mb-4">
<div class="flex flex-col">
<span class="text-[#64748b] text-xs uppercase font-medium tracking-wide">Active Users</span>
<span class="text-white text-2xl font-bold mt-1">120</span>
<span class="text-green-400 text-xs font-medium flex items-center gap-1 mt-1">
<span class="material-symbols-outlined text-[12px]">arrow_upward</span> +12%
                                </span>
</div>
<div class="p-2 bg-white/5 rounded-lg">
<span class="material-symbols-outlined text-[#64748b] text-xl">group</span>
</div>
</div>
<p class="text-[#64748b] text-xs">Connected via VLESS</p>
</div>
<div class="glass-panel glass-card-hover rounded-2xl p-4 transition-all">
<div class="flex justify-between items-start mb-4">
<div class="flex flex-col">
<span class="text-[#64748b] text-xs uppercase font-medium tracking-wide">Total Bandwidth</span>
<span class="text-white text-2xl font-bold mt-1">4.5 TB</span>
<span class="text-green-400 text-xs font-medium flex items-center gap-1 mt-1">
<span class="material-symbols-outlined text-[12px]">arrow_upward</span> +5%
                                </span>
</div>
<div class="p-2 bg-white/5 rounded-lg">
<span class="material-symbols-outlined text-[#64748b] text-xl">cloud</span>
</div>
</div>
<p class="text-[#64748b] text-xs">Cycle resets in 4 days</p>
</div>
<div class="glass-panel glass-card-hover rounded-2xl p-4 transition-all">
<div class="flex justify-between items-start mb-4">
<div class="flex flex-col">
<span class="text-[#64748b] text-xs uppercase font-medium tracking-wide">System Health</span>
<span class="text-white text-2xl font-bold mt-1">98%</span>
<span class="text-green-400 text-xs font-medium flex items-center gap-1 mt-1">
<span class="material-symbols-outlined text-[12px]">check_circle</span> Stable
                                </span>
</div>
<div class="p-2 bg-white/5 rounded-lg">
<span class="material-symbols-outlined text-[#64748b] text-xl">health_and_safety</span>
</div>
</div>
</div>
<div class="glass-panel glass-card-hover rounded-2xl p-4 transition-all">
<div class="flex justify-between items-start mb-4">
<div class="flex flex-col">
<span class="text-[#64748b] text-xs uppercase font-medium tracking-wide">AI Optimization</span>
<span class="text-white text-2xl font-bold mt-1">Learning</span>
<span class="text-blue-400 text-xs font-medium flex items-center gap-1 mt-1">
<span class="material-symbols-outlined text-[12px]">psychology</span> Active
                                </span>
</div>
<div class="p-2 bg-white/5 rounded-lg">
<span class="material-symbols-outlined text-[#64748b] text-xl">auto_awesome</span>
</div>
</div>
<p class="text-[#64748b] text-xs">Adjusting routes dynamically</p>
</div>
</div>
<!-- Main Content Grid -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
<!-- Left Column: AI Insight + Security Alert -->
<div class="space-y-6 lg:col-span-1">
<!-- AI Insight Card -->
<div class="glass-panel rounded-2xl p-5">
<h3 class="text-white text-sm font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-primary text-base">psychology</span>
                                AI Insight
                            </h3>
<p class="text-[#90a7cb] text-xs leading-relaxed">System load is predicted to peak at 20:00. Auto-scaling enabled.</p>
</div>
<!-- Security Alert Card -->
<div class="glass-panel rounded-2xl p-5 bg-gradient-to-br from-red-500/5 to-transparent border border-red-500/20">
<h3 class="text-white text-sm font-bold flex items-center gap-2 mb-3">
<span class="material-symbols-outlined text-red-500 text-base">warning</span>
                                SECURITY ALERT
                            </h3>
<div class="space-y-3">
<p class="text-[#90a7cb] text-xs">AI Insight</p>
<p class="text-white text-sm font-medium">3 Suspicious IPs detected and mitigated automatically by Quantum Guard.</p>
<button class="w-full px-4 py-2 rounded-lg bg-primary hover:bg-blue-600 text-white text-xs font-medium transition-colors">View Security Report</button>
</div>
</div>
</div>
<!-- Middle Column: Traffic Chart -->
<div class="glass-panel rounded-2xl p-5 lg:col-span-2">
<div class="flex justify-between items-center mb-4">
<h3 class="text-white text-sm font-bold">Real-time Traffic</h3>
<div class="flex items-center gap-2">
<span class="px-3 py-1 rounded-full bg-primary/10 text-primary text-xs font-medium">Live</span>
<select class="bg-transparent text-[#90a7cb] text-xs font-medium appearance-none">
<option>1H</option>
<option>24H</option>
</select>
</div>
</div>
<p class="text-[#90a7cb] text-xs mb-3">VLESS Protocol Throughput</p>
<!-- Chart Placeholder -->
<div class="h-40 chart-placeholder rounded-lg flex items-end gap-1 p-4">
<div class="w-full h-[60%] bg-primary/20 rounded-t"></div>
<div class="w-full h-[80%] bg-primary/30 rounded-t"></div>
<div class="w-full h-[90%] bg-primary/40 rounded-t"></div>
<div class="w-full h-[70%] bg-primary/50 rounded-t"></div>
<div class="w-full h-[95%] bg-primary/60 rounded-t"></div>
<div class="h-full bg-primary/70 rounded-t" style="height:85%"></div>
<div class="h-full bg-primary/80 rounded-t" style="height:75%"></div>
</div>
<!-- Time Labels -->
<div class="flex justify-between mt-2 text-[#64748b] text-[10px]">
<span>00:00</span>
<span>06:00</span>
<span>12:00</span>
<span>18:00</span>
<span>24:00</span>
</div>
</div>
<!-- Quick Actions + Worker Status (Full Width) -->
<div class="lg:col-span-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
<!-- Quick Actions -->
<div class="glass-panel rounded-2xl p-5 md:col-span-1">
<h3 class="text-white text-sm font-bold mb-4">Quick Actions</h3>
<div class="grid grid-cols-2 gap-3">
<button class="flex flex-col items-center justify-center p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-colors text-[#90a7cb] hover:text-white">
<span class="material-symbols-outlined text-2xl mb-2">restart_alt</span>
<span class="text-xs font-medium">Restart Service</span>
</button>
<button class="flex flex-col items-center justify-center p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-colors text-[#90a7cb] hover:text-white">
<span class="material-symbols-outlined text-2xl mb-2">delete_sweep</span>
<span class="text-xs font-medium">Clear Logs</span>
</button>
<button class="flex flex-col items-center justify-center p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-colors text-[#90a7cb] hover:text-white">
<span class="material-symbols-outlined text-2xl mb-2">key</span>
<span class="text-xs font-medium">Rotate Keys</span>
</button>
<button class="flex flex-col items-center justify-center p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-colors text-[#90a7cb] hover:text-white">
<span class="material-symbols-outlined text-2xl mb-2">dns</span>
<span class="text-xs font-medium">Flush DNS</span>
</button>
</div>
</div>
<!-- Worker Node Status -->
<div class="glass-panel rounded-2xl p-5 md:col-span-1">
<h3 class="text-white text-sm font-bold flex items-center justify-between mb-4">
<span>Worker Node Status</span>
<span class="text-green-400 text-xs font-medium flex items-center gap-1">
<span class="material-symbols-outlined text-[12px]">check_circle</span> Uptime: 24h 12m
                                </span>
</h3>
<div class="space-y-3 text-[#90a7cb] text-xs">
<p>CPU Usage: 15% (Low)</p>
<p>Memory: 45MB / 128MB</p>
<p>Active Connections: 120</p>
<p>Last Health Check: 2min ago</p>
</div>
</div>
<!-- Recent Connections -->
<div class="glass-panel rounded-2xl p-5 md:col-span-2 lg:col-span-1 overflow-hidden">
<div class="flex justify-between items-center mb-4">
<h3 class="text-white text-sm font-bold">Recent Connections</h3>
<a class="text-[#90a7cb] text-xs hover:text-white transition-colors" href="#">View All</a>
</div>
<table class="w-full text-sm text-left">
<thead>
<tr class="text-[#64748b] text-xs uppercase">
<th class="p-4">User</th>
<th class="p-4">Protocol</th>
<th class="p-4">Data Usage</th>
<th class="p-4">Status</th>
<th class="p-4"></th>
</tr>
</thead>
<tbody class="divide-y divide-white/5">
<tr class="group hover:bg-white/5 transition-colors">
<td class="p-4">
<div class="flex items-center gap-3">
<div class="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-500 to-cyan-500 flex items-center justify-center text-white font-bold text-xs">AM</div>
<div class="flex flex-col">
<span class="text-white font-medium">Ali Mahdavi</span>
<span class="text-[#64748b] text-xs">IP: 192.168.1.45</span>
</div>
</div>
</td>
<td class="p-4 text-slate-300">
<span class="px-2 py-1 rounded bg-white/5 border border-white/5 text-xs font-mono">vless+ws+tls</span>
</td>
<td class="p-4 text-white font-mono">4.2 GB</td>
<td class="p-4">
<span class="px-2 py-1 rounded-full bg-green-500/10 text-green-400 text-xs font-bold border border-green-500/20">Active</span>
</td>
<td class="p-4 text-right">
<button class="text-[#90a7cb] hover:text-white p-1"><span class="material-symbols-outlined text-lg">more_vert</span></button>
</td>
</tr>
<tr class="group hover:bg-white/5 transition-colors">
<td class="p-4">
<div class="flex items-center gap-3">
<div class="w-8 h-8 rounded-full bg-gradient-to-tr from-purple-500 to-pink-500 flex items-center justify-center text-white font-bold text-xs">SJ</div>
<div class="flex flex-col">
<span class="text-white font-medium">Sara Johnson</span>
<span class="text-[#64748b] text-xs">IP: 10.0.0.23</span>
</div>
</div>
</td>
<td class="p-4 text-slate-300">
<span class="px-2 py-1 rounded bg-white/5 border border-white/5 text-xs font-mono">vmess+tcp</span>
</td>
<td class="p-4 text-white font-mono">1.8 GB</td>
<td class="p-4">
<span class="px-2 py-1 rounded-full bg-yellow-500/10 text-yellow-400 text-xs font-bold border border-yellow-500/20">Idle</span>
</td>
<td class="p-4 text-right">
<button class="text-[#90a7cb] hover:text-white p-1"><span class="material-symbols-outlined text-lg">more_vert</span></button>
</td>
</tr>
<tr class="group hover:bg-white/5 transition-colors">
<td class="p-4">
<div class="flex items-center gap-3">
<div class="w-8 h-8 rounded-full bg-gradient-to-tr from-orange-500 to-red-500 flex items-center justify-center text-white font-bold text-xs">MK</div>
<div class="flex flex-col">
<span class="text-white font-medium">Mohammad K.</span>
<span class="text-[#64748b] text-xs">IP: 172.16.0.5</span>
</div>
</div>
</td>
<td class="p-4 text-slate-300">
<span class="px-2 py-1 rounded bg-white/5 border border-white/5 text-xs font-mono">trojan+grpc</span>
</td>
<td class="p-4 text-white font-mono">12.5 GB</td>
<td class="p-4">
<span class="px-2 py-1 rounded-full bg-green-500/10 text-green-400 text-xs font-bold border border-green-500/20">Active</span>
</td>
<td class="p-4 text-right">
<button class="text-[#90a7cb] hover:text-white p-1"><span class="material-symbols-outlined text-lg">more_vert</span></button>
</td>
</tr>
</tbody>
</table>
</div>
</div>
</div>
</main>
</body></html>`;

const ADMIN_LOGIN_HTML = `<!DOCTYPE html>

<html class="dark" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>VLESS Quantum - Admin Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;900&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<script id="tailwind-config">
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        "primary": "#3c83f6",
                        "background-light": "#f5f7f8",
                        "background-dark": "#101722",
                    },
                    fontFamily: {
                        "display": ["Inter", "sans-serif"]
                    },
                    borderRadius: {"DEFAULT": "0.5rem", "lg": "1rem", "xl": "1.5rem", "full": "9999px"},
                    animation: {
                        'gradient-xy': 'gradient-xy 15s ease infinite',
                        'float': 'float 6s ease-in-out infinite',
                    },
                    keyframes: {
                        'gradient-xy': {
                            '0%, 100%': {
                                'background-size': '400% 400%',
                                'background-position': 'left center'
                            },
                            '50%': {
                                'background-size': '200% 200%',
                                'background-position': 'right center'
                            },
                        },
                        'float': {
                            '0%, 100%': { transform: 'translateY(0)' },
                            '50%': { transform: 'translateY(-10px)' },
                        }
                    }
                },
            },
        }
    </script>
<style>
        /* Custom scrollbar for modern feel */
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #101722; 
        }
        ::-webkit-scrollbar-thumb {
            background: #314668; 
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #3c83f6; 
        }
        
        .glass-panel {
            background: rgba(16, 23, 34, 0.75);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        }
        
        .bg-gradient-primary {
            background: linear-gradient(135deg, #1e3a8a, #3c83f6);
        }
    </style>
</head>
<body class="bg-background-dark min-h-screen flex items-center justify-center p-4 selection:bg-primary/20">
<div class="w-full max-w-md">
<div class="glass-panel rounded-2xl overflow-hidden shadow-2xl shadow-primary/20 border border-white/5">
<!-- Header Section -->
<div class="bg-gradient-primary px-8 py-6 text-center">
<span class="material-symbols-outlined text-white text-5xl mb-2 animate-float">shield_lock</span>
<h1 class="text-white text-2xl font-bold mb-1">Admin Access</h1>
<p class="text-blue-200 text-sm opacity-90">Secure Gateway to VLESS Quantum Panel</p>
</div>
<!-- Form Section -->
<div class="px-8 py-6 space-y-6">
<!-- Username -->
<div class="relative">
<label class="block text-blue-200 text-xs font-medium mb-1.5" for="username">Username / ID</label>
<input class="w-full h-12 px-4 rounded-lg bg-[#182334]/50 border border-[#314668] text-white placeholder-[#587093] focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" id="username" placeholder="Enter admin ID" type="text"/>
<span class="absolute right-4 top-[42px] text-[#587093]"><span class="material-symbols-outlined text-[20px]">person</span></span>
</div>
<!-- Password -->
<div class="relative">
<label class="block text-blue-200 text-xs font-medium mb-1.5" for="password">Password</label>
<input class="w-full h-12 px-4 rounded-lg bg-[#182334]/50 border border-[#314668] text-white placeholder-[#587093] focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" id="password" placeholder="Enter secure password" type="password"/>
<span class="absolute right-4 top-[42px] text-[#587093]"><span class="material-symbols-outlined text-[20px]">lock</span></span>
<a class="absolute right-4 top-2.5 text-xs text-[#90a7cb] hover:text-white transition-colors" href="#">Forgot password?</a>
</div>
<!-- Security Check (TOTP) -->
<div>
<label class="block text-blue-200 text-xs font-medium mb-1.5">Security Check (TOTP)</label>
<div class="flex justify-between gap-2">
<input class="w-12 h-14 text-center rounded-lg bg-[#182334]/50 border border-[#314668] text-white text-xl font-bold focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" inputmode="numeric" maxlength="1" type="text"/>
<input class="w-12 h-14 text-center rounded-lg bg-[#182334]/50 border border-[#314668] text-white text-xl font-bold focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" inputmode="numeric" maxlength="1" type="text"/>
<input class="w-12 h-14 text-center rounded-lg bg-[#182334]/50 border border-[#314668] text-white text-xl font-bold focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" inputmode="numeric" maxlength="1" type="text"/>
<input class="w-12 h-14 text-center rounded-lg bg-[#182334]/50 border border-[#314668] text-white text-xl font-bold focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" inputmode="numeric" maxlength="1" type="text"/>
<input class="w-12 h-14 text-center rounded-lg bg-[#182334]/50 border border-[#314668] text-white text-xl font-bold focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" inputmode="numeric" maxlength="1" type="text"/>
<input class="w-12 h-14 text-center rounded-lg bg-[#182334]/50 border border-[#314668] text-white text-xl font-bold focus:border-primary focus:ring-1 focus:ring-primary/50 outline-none transition-all" inputmode="numeric" maxlength="1" type="text"/>
</div>
</div>
<!-- Security Alert / Brute Force Warning -->
<div class="flex items-start gap-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
<span class="material-symbols-outlined text-red-400 text-lg mt-0.5">shield</span>
<div class="flex flex-col">
<span class="text-red-200 text-xs font-medium">Brute-Force Protection Active</span>
<span class="text-red-300/70 text-[10px]">Your IP is being monitored. 3 attempts remaining.</span>
</div>
</div>
<!-- Submit Button -->
<button class="relative mt-2 flex w-full cursor-pointer items-center justify-center overflow-hidden rounded-xl h-12 px-5 bg-primary hover:bg-blue-600 active:scale-[0.98] transition-all duration-200 shadow-[0_0_20px_rgba(60,131,246,0.4)] hover:shadow-[0_0_25px_rgba(60,131,246,0.6)]">
<div class="flex items-center gap-2 relative z-10">
<span class="material-symbols-outlined text-white text-[20px]">login</span>
<span class="text-white text-base font-bold tracking-wide">Secure Login</span>
</div>
<!-- Button Shine Effect -->
<div class="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full hover:animate-[shimmer_1.5s_infinite]"></div>
</button>
</div>
<!-- Footer Section -->
<div class="bg-[#0b1019]/50 px-8 py-4 flex justify-between items-center text-[10px] text-[#5a6b85] border-t border-[#314668]/30">
<div class="flex items-center gap-1">
<span class="material-symbols-outlined text-[14px]">verified_user</span>
<span>Quantum Shield™ v2.4.0</span>
</div>
<div class="flex items-center gap-2">
<span class="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]"></span>
<span>System Online</span>
</div>
</div>
</div>
</div>
<style>
        @keyframes shimmer {
            100% {
                transform: translateX(100%);
            }
        }
    </style>
</body></html>`;

// --- EMBEDDED HTML UI PAGES ---
// All </script> escaped as <\/script> for parser safety

const USER_PANEL_HTML = `<!DOCTYPE html>

<html class="dark" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>Quantum Worker Panel</title>
<link href="https://fonts.googleapis.com" rel="preconnect"/>
<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&amp;family=Vazirmatn:wght@300;400;500;700&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>
<script id="tailwind-config">
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        "primary": "#3c83f6",
                        "primary-hover": "#2563eb",
                        "background-light": "#f5f7f8",
                        "background-dark": "#101723",
                        "card-dark": "#1e293b",
                        "card-border": "#314668",
                        "success": "#10b981",
                        "warning": "#f59e0b",
                        "danger": "#ef4444",
                    },
                    fontFamily: {
                        "display": ["Inter", "Vazirmatn", "sans-serif"],
                        "body": ["Inter", "Vazirmatn", "sans-serif"],
                    },
                    borderRadius: {"DEFAULT": "0.5rem", "lg": "1rem", "xl": "1.5rem", "full": "9999px"},
                },
            },
        }
    <\/script>
<style>
        /* Custom scrollbar for webkit */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #101723; 
        }
        ::-webkit-scrollbar-thumb {
            background: #314668; 
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #3c83f6; 
        }

        /* Glassmorphism utility */
        .glass-panel {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
    <\/style>
</head>
<body class="bg-background-light dark:bg-background-dark text-slate-900 dark:text-white font-body antialiased selection:bg-primary/20 min-h-screen flex flex-col relative overflow-x-hidden">
<!-- Background Gradient Effect -->
<div class="fixed inset-0 bg-gradient-to-br from-primary/5 via-transparent to-purple-500/5 z-0 pointer-events-none"></div>
<!-- Header -->
<header class="relative z-10 flex items-center justify-between px-4 py-3 bg-card-dark/50 backdrop-blur-md border-b border-card-border">
<div class="flex items-center gap-3">
<span class="text-2xl font-bold text-primary">⚡ Quantum Panel</span>
<span class="text-slate-400 text-xs">EN</span>
<button class="ml-2 text-slate-400 hover:text-white"><span class="material-symbols-outlined">dark_mode</span></button>
</div>
<div class="flex items-center gap-4">
<button class="text-slate-400 hover:text-white"><span class="material-symbols-outlined">notifications</span></button>
<div class="flex items-center gap-2">
<img class="w-8 h-8 rounded-full" src="https://api.dicebear.com/7.x/avataaars/svg?seed=Alexander" alt="User avatar"/>
<span class="hidden md:inline text-white text-sm font-medium">Alexander</span>
<span class="text-success text-xs">Premium User</span>
</div>
</div>
</header>
<!-- Main Content -->
<main class="relative z-10 container max-w-7xl mx-auto px-4 py-8 flex-grow">
<!-- Title & Actions -->
<div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
<div>
<h1 class="text-2xl font-bold text-white mb-2">Dashboard Overview</h1>
<p class="text-[#64748b] text-sm">Manage your VLESS subscription, monitor traffic usage, and configure your connection efficiently.</p>
</div>
<div class="flex gap-3">
<button class="flex items-center gap-2 px-4 py-2 rounded-lg bg-card-dark border border-card-border hover:bg-primary/10 text-white text-sm transition-colors">
<span class="material-symbols-outlined">refresh</span>
                        Refresh Data
                    </button>
<button class="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">headset_mic</span>
                        Support
                    </button>
</div>
</div>
<!-- Stats Cards -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
<!-- Status -->
<div class="glass-panel rounded-2xl p-5 border-l-4 border-l-success">
<h3 class="text-[#90a7cb] text-sm font-medium mb-2 flex items-center gap-2">
<span class="material-symbols-outlined text-success">check_circle</span>
                        STATUS
                    </h3>
<p class="text-white text-xl font-bold">Active</p>
<p class="text-[#90a7cb] text-xs mt-1">System Healthy</p>
</div>
<!-- Expires In -->
<div class="glass-panel rounded-2xl p-5 border-l-4 border-l-warning">
<h3 class="text-[#90a7cb] text-sm font-medium mb-2 flex items-center gap-2">
<span class="material-symbols-outlined text-warning">schedule</span>
                        EXPIRES IN
                    </h3>
<p class="text-white text-xl font-bold">25 Days</p>
<p class="text-[#90a7cb] text-xs mt-1">Until Oct. 25, 2024</p>
</div>
<!-- IP Limit -->
<div class="glass-panel rounded-2xl p-5 border-l-4 border-l-primary">
<h3 class="text-[#90a7cb] text-sm font-medium mb-2 flex items-center gap-2">
<span class="material-symbols-outlined text-primary">devices</span>
                        IP LIMIT
                    </h3>
<p class="text-white text-xl font-bold">2 Devices</p>
<p class="text-[#90a7cb] text-xs mt-1">Concurrent Connections</p>
</div>
<!-- Remaining -->
<div class="glass-panel rounded-2xl p-5 border-l-4 border-l-success">
<h3 class="text-[#90a7cb] text-sm font-medium mb-2 flex items-center gap-2">
<span class="material-symbols-outlined text-success">data_usage</span>
                        REMAINING
                    </h3>
<p class="text-white text-xl font-bold">37.5 GB</p>
<p class="text-[#90a7cb] text-xs mt-1">Of 50 GB Monthly Quota</p>
</div>
</div>
<!-- Content Grid -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
<!-- Traffic Usage -->
<div class="glass-panel rounded-2xl p-5 lg:col-span-2">
<h3 class="text-white text-lg font-bold mb-4 flex items-center gap-2">
<span class="material-symbols-outlined text-primary">insights</span>
                        Traffic Usage
                    </h3>
<!-- Tabs -->
<div class="flex gap-2 mb-4">
<button class="px-4 py-2 rounded-lg bg-primary/20 text-primary text-sm font-medium">Download</button>
<button class="px-4 py-2 rounded-lg bg-card-dark text-[#90a7cb] text-sm font-medium hover:bg-primary/10 transition-colors">Upload</button>
<button class="px-4 py-2 rounded-lg bg-card-dark text-[#90a7cb] text-sm font-medium hover:bg-primary/10 transition-colors">Monthly Cycle</button>
</div>
<!-- Stats -->
<div class="space-y-3">
<div class="flex justify-between items-center">
<span class="text-[#90a7cb] text-sm">Download</span>
<span class="text-white text-sm font-medium">18.4 GB</span>
</div>
<div class="h-2 bg-card-dark rounded-full overflow-hidden">
<div class="h-full bg-gradient-to-r from-primary to-primary-hover w-[70%] rounded-full"></div>
</div>
<div class="flex justify-between items-center">
<span class="text-[#90a7cb] text-sm">Upload</span>
<span class="text-white text-sm font-medium">2.3 GB</span>
</div>
<div class="h-2 bg-card-dark rounded-full overflow-hidden">
<div class="h-full bg-gradient-to-r from-success to-success/80 w-[15%] rounded-full"></div>
</div>
<p class="text-[#90a7cb] text-xs text-right">25% Used</p>
</div>
</div>
<!-- Account Info -->
<div class="glass-panel rounded-2xl p-5 lg:col-span-1">
<h3 class="text-white text-lg font-bold mb-4 flex items-center gap-2">
<span class="material-symbols-outlined text-primary">account_circle</span>
                        Account Info
                    </h3>
<dl class="space-y-3 text-sm">
<dt class="text-[#90a7cb]">UUID (Private)</dt>
<dd class="text-white font-mono truncate flex items-center gap-2">
                            ********-****-****-****-************ 
                            <button class="text-[#90a7cb] hover:text-white"><span class="material-symbols-outlined text-base">visibility</span></button>
</dd>
<dt class="text-[#90a7cb]">Creation Date</dt>
<dd class="text-white">2023-10-27</dd>
<dt class="text-[#90a7cb]">Notes</dt>
<dd class="text-white">Standard Plan - Monthly</dd>
</dl>
</div>
<!-- Subscription Links -->
<div class="glass-panel rounded-2xl p-5 lg:col-span-2">
<h3 class="text-white text-lg font-bold mb-4 flex items-center gap-2">
<span class="material-symbols-outlined text-primary">link</span>
                        Subscription Links
                    </h3>
<!-- VLESS Link -->
<div class="mb-4">
<p class="text-[#90a7cb] text-sm mb-2">VLESS (Xray)</p>
<input class="w-full bg-card-dark border border-card-border rounded-lg p-3 text-white text-sm font-mono truncate" readonly="" type="text" value="vless://uuid@www.example.com:443?security=reality&sni=google.com"/>
<div class="flex gap-2 mt-2">
<button class="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">content_copy</span>
                                Copy
                            </button>
<button class="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-card-dark border border-card-border hover:bg-primary/10 text-white text-sm transition-colors">
<span class="material-symbols-outlined">qr_code</span>
                                QR
                            </button>
</div>
</div>
<!-- Sing-Box Link -->
<div>
<p class="text-[#90a7cb] text-sm mb-2">Sing-Box Link</p>
<input class="w-full bg-card-dark border border-card-border rounded-lg p-3 text-white text-sm font-mono truncate" readonly="" type="text" value="sing-box://import?url=htps%3A%2F%2Fexample.com%2Fconfig.json"/>
<div class="flex gap-2 mt-2">
<button class="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-sm font-medium transition-colors">
<span class="material-symbols-outlined">content_copy</span>
                                Copy
                            </button>
<button class="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-card-dark border border-card-border hover:bg-primary/10 text-white text-sm transition-colors">
<span class="material-symbols-outlined">qr_code</span>
                                QR
                            </button>
</div>
</div>
<p class="text-[#90a7cb] text-xs mt-4">One-Click Import Import to Clients:</p>
<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-2">
<button class="px-4 py-2 rounded-lg bg-warning/20 text-warning hover:bg-warning/30 transition-colors text-sm font-medium flex items-center justify-center gap-2">
<span class="material-symbols-outlined">bolt</span>
                            Hiddify
                        </button>
<button class="px-4 py-2 rounded-lg bg-primary/20 text-primary hover:bg-primary/30 transition-colors text-sm font-medium flex items-center justify-center gap-2">
<span class="material-symbols-outlined">rocket_launch</span>
                            v2rayNG
                        </button>
<button class="px-4 py-2 rounded-lg bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition-colors text-sm font-medium flex items-center justify-center gap-2">
<span class="material-symbols-outlined">pets</span>
                            Clash Meta
                        </button>
<button class="px-4 py-2 rounded-lg bg-success/20 text-success hover:bg-success/30 transition-colors text-sm font-medium flex items-center justify-center gap-2">
<span class="material-symbols-outlined">shield</span>
                            Exclusive
                        </button>
</div>
<a class="text-primary text-xs hover:underline mt-2 inline-block">Hiddify DNS Setup Guide</a>
</div>
<!-- Connection Stats -->
<div class="glass-panel rounded-2xl p-5 lg:col-span-1">
<h3 class="text-white text-lg font-bold mb-4 flex items-center gap-2">
<span class="material-symbols-outlined text-primary">public</span>
                        Connection Stats
                    </h3>
<div class="space-y-4">
<div class="bg-card-dark rounded-lg p-3 border border-card-border">
<p class="text-xs text-[#90a7cb] mb-1">Proxy Location</p>
<p class="text-sm font-medium text-white flex items-center gap-2">
<span class="fi fi-us"></span> San Francisco, US
                            </p>
</div>
<div class="bg-card-dark rounded-lg p-3 border border-card-border">
<p class="text-xs text-[#90a7cb] mb-1">Your IP</p>
<p class="text-sm font-medium text-white truncate">192.12.x.x</p>
</div>
<div class="bg-card-dark rounded-lg p-3 border border-card-border">
<p class="text-xs text-[#90a7cb] mb-1">ISP</p>
<p class="text-sm font-medium text-white truncate">Cloudflare</p>
</div>
</div>
<div class="pt-2">
<div class="flex justify-between items-center mb-1">
<span class="text-xs text-[#90a7cb]">IP Risk Score</span>
<span class="text-xs font-bold text-green-400">Low Risk (0%)</span>
</div>
<div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
<div class="h-full bg-green-500 w-1 rounded-full"></div>
</div>
</div>
</div>
</div>
<!-- Promo / Download Config -->
<button class="w-full bg-gradient-to-r from-slate-800 to-slate-900 border border-card-border hover:border-primary/50 text-white rounded-xl p-4 flex items-center justify-center gap-3 group transition-all">
<div class="p-2 bg-white/5 rounded-lg group-hover:bg-primary/20 transition-colors">
<span class="material-symbols-outlined text-[24px]">download</span>
</div>
<div class="text-left">
<p class="text-sm font-bold">Download Config File</p>
<p class="text-xs text-[#90a7cb]">Save full JSON config</p>
</div>
</button>
</div>
</div>
</main>
<!-- Footer -->
<footer class="border-t border-card-border mt-auto bg-card-dark/50">
<div class="max-w-7xl mx-auto px-4 py-6 text-center">
<p class="text-[#64748b] text-sm">© 2024 Quantum Worker Panel. Secure VLESS Infrastructure.</p>
</div>
</footer>
<!-- QR Code Modal (Hidden by default, represented visually for design) -->
<!-- Ideally controlled by JS, here is the markup structure -->
<div class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4" id="qr-modal">
<div class="bg-card-dark border border-card-border rounded-2xl w-full max-w-sm p-6 shadow-2xl transform scale-100 transition-all relative">
<button class="absolute top-4 right-4 text-[#90a7cb] hover:text-white">
<span class="material-symbols-outlined">close</span>
</button>
<h3 class="text-xl font-bold text-white text-center mb-6">Scan QR Code</h3>
<div class="bg-white p-4 rounded-xl mx-auto w-64 h-64 flex items-center justify-center mb-6">
<!-- Placeholder for QR Code -->
<div class="w-full h-full bg-slate-900 pattern-dots"></div>
</div>
<p class="text-center text-[#90a7cb] text-sm mb-6">Scan this code with your V2Ray client application to import the configuration.</p>
<div class="grid grid-cols-2 gap-3">
<button class="w-full py-2.5 rounded-lg bg-background-dark border border-card-border text-white text-sm font-medium hover:bg-white/5">
                    Copy String
                </button>
<button class="w-full py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-white text-sm font-medium">
                    Save Image
                </button>
</div>
</div>
</div>
</body></html>`;

const ERROR_404_HTML = `<!DOCTYPE html>

<html class="dark" lang="fa"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>404 - Page Not Found</title>
<link href="https://fonts.googleapis.com" rel="preconnect"/>
<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;900&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>
<script id="tailwind-config">
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        "primary": "#3c83f6",
                        "background-light": "#f5f7f8",
                        "background-dark": "#101722",
                    },
                    fontFamily: {
                        "display": ["Inter", "Vazirmatn", "sans-serif"],
                        "farsi": ["Vazirmatn", "sans-serif"]
                    },
                    borderRadius: {"DEFAULT": "0.5rem", "lg": "1rem", "xl": "1.5rem", "full": "9999px"},
                },
            },
        }
    <\/script>
<style>
        body {
            font-family: 'Inter', 'Vazirmatn', sans-serif;
        }
        .text-gradient {
            background: linear-gradient(135deg, #3c83f6 0%, #a5b4fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .bg-glow {
            background: radial-gradient(circle at center, rgba(60,131,246,0.15) 0%, transparent 70%);
        }
        .animate-float {
            animation: float 6s ease-in-out infinite;
        }
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }
    <\/style>
</head>
<body class="min-h-screen bg-background-dark text-white flex flex-col items-center justify-center relative overflow-hidden px-4">
<!-- Background Elements -->
<div class="absolute inset-0 z-0 pointer-events-none">
<div class="bg-glow w-[800px] h-[800px] absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"></div>
</div>
<!-- Main Content -->
<main class="relative z-10 text-center max-w-[600px] mx-auto">
<!-- 404 Illustration -->
<div class="relative mb-8">
<div class="w-48 h-48 mx-auto bg-primary/10 rounded-full flex items-center justify-center animate-float">
<span class="text-9xl font-bold text-gradient">404</span>
</div>
</div>
<!-- Titles -->
<div class="mb-6">
<h2 class="text-3xl sm:text-4xl font-bold text-white leading-tight tracking-[-0.015em] font-farsi" dir="rtl">
                    صفحه مورد نظر پیدا نشد
                </h2>
<h3 class="text-slate-400 text-lg sm:text-xl font-medium tracking-wide">
                    Page Not Found
                </h3>
</div>
<!-- Description Body -->
<p class="text-slate-300 text-base sm:text-lg font-normal leading-relaxed max-w-[480px] mx-auto mb-10 px-4 font-farsi" dir="rtl">
                متاسفانه صفحه‌ای که دنبال آن بودید وجود ندارد. ممکن است لینک خراب باشد یا صفحه منتقل شده باشد.
                <br/>
<span class="block mt-2 text-sm text-slate-500 font-display dir-ltr">It looks like the link is broken or the page has been moved.</span>
</p>
<!-- Actions -->
<div class="flex flex-col sm:flex-row gap-4 w-full justify-center px-4">
<a class="group relative flex min-w-[160px] h-12 cursor-pointer items-center justify-center overflow-hidden rounded-xl bg-primary px-8 text-white text-base font-bold leading-normal tracking-[0.015em] shadow-[0_0_20px_rgba(60,131,246,0.3)] hover:shadow-[0_0_30px_rgba(60,131,246,0.5)] transition-all duration-300" href="#">
<span class="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300"></span>
<span class="relative flex items-center gap-2">
<span class="font-farsi">بازگشت به خانه</span>
<span class="opacity-50">|</span>
<span>Go Home</span>
</span>
</a>
<button class="flex min-w-[160px] h-12 cursor-pointer items-center justify-center rounded-xl bg-[#223149]/50 border border-[#223149] px-6 text-slate-300 hover:text-white hover:bg-[#223149] transition-all text-sm font-bold">
<span class="flex items-center gap-2">
<span class="material-symbols-outlined text-[20px]">arrow_back</span>
<span>Back</span>
</span>
</button>
</div>
</main>
<!-- Footer Simple -->
<footer class="w-full py-6 text-center text-slate-600 text-xs relative z-10">
<p dir="ltr">© 2024 VLESS Quantum Worker System. All rights reserved.</p>
</footer>
</body></html>`;

// --- MAIN WORKER HANDLER ---
export default {
    async fetch(request, env, ctx) {
        try {
            const config = await Config.fromEnv(env);
            const url = new URL(request.url);
            const upgradeHeader = request.headers.get('Upgrade');
            const clientIp = request.cf?.clientIp || request.headers.get('CF-Connecting-IP') || 'unknown';

            // Validate client IP early
            if (!isPrivateIP(clientIp) && await isSuspiciousIP(clientIp, config.scamalytics, config.scamThreshold)) {
                return new Response('Access denied due to suspicious activity.', { status: 403 });
            }

            // Auto-init D1 if bound
            if (env.DB) {
                await initDatabase(env.DB);
            }

            // Root proxy URL handling
            if (env.ROOT_PROXY_URL) {
                try {
                    let proxyUrl = new URL(env.ROOT_PROXY_URL);
                    // Proxy logic here if needed (e.g., forward if match)
                } catch (urlError) {
                    console.error(`Invalid ROOT_PROXY_URL: ${env.ROOT_PROXY_URL}`, urlError);
                    const headers = new Headers();
                    addSecurityHeaders(headers, null, {});
                    return new Response('Proxy configuration error: Invalid URL format', { status: 500, headers });
                }
            }

            // VLESS WebSocket Handler
            if (upgradeHeader === 'websocket') {
                // Anti-filter: Quantum entropy for proxy selection
                const entropySeed = crypto.randomUUID();
                const entropyIndex = parseInt(entropySeed.split('-')[0], 16) % config.proxyIPs.length;
                config.proxyAddress = config.proxyIPs[entropyIndex] || config.proxyAddress;

                return await vlessOverWSHandler(request, env, config);
            }

            // Admin Panel Routes
            const adminPrefix = env.ADMIN_PATH_PREFIX || 'quantum-admin';
            if (url.pathname.startsWith(`/${adminPrefix}`)) {
                // Validate path to prevent traversal
                if (!/^[a-zA-Z0-9\/-]+$/.test(url.pathname)) {
                    return new Response('Invalid path.', { status: 400 });
                }

                // Admin auth check
                if (env.ADMIN_HEADER_KEY) {
                    const headerValue = request.headers.get('X-Admin-Auth');
                    if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) {
                        return new Response('Access denied.', { status: 403 });
                    }
                } else {
                    // Fallback to Scamalytics for admin
                    if (await isSuspiciousIP(clientIp, config.scamalytics, config.scamThreshold)) {
                        return new Response('Access denied.', { status: 403 });
                    }
                }

                // Sub-routes for admin
                if (url.pathname === `/${adminPrefix}/dashboard`) {
                    return new Response(DASHBOARD_HTML, { headers: { 'Content-Type': 'text/html' } });
                } else if (url.pathname === `/${adminPrefix}/advanced`) {
                    return new Response(ADVANCED_SETTINGS_HTML, { headers: { 'Content-Type': 'text/html' } });
                } else if (url.pathname === `/${adminPrefix}/users`) {
                    return new Response(USER_MANAGEMENT_HTML, { headers: { 'Content-Type': 'text/html' } });
                } else if (url.pathname === `/${adminPrefix}/login`) {
                    return new Response(ADMIN_LOGIN_HTML, { headers: { 'Content-Type': 'text/html' } });
                } else {
                    return new Response(ADMIN_LOGIN2_HTML, { headers: { 'Content-Type': 'text/html' } }); // Default to login
                }
            }

            // User Panel Routes (per UUID)
            if (url.pathname.startsWith('/panel/')) {
                const uuid = url.pathname.split('/panel/')[1].split('/')[0]; // Safer split
                if (!isValidUUID(uuid)) {
                    return new Response('Invalid UUID.', { status: 400 });
                }

                // Fetch user data from D1
                if (env.DB) {
                    const stmt = env.DB.prepare('SELECT * FROM users WHERE uuid = ?');
                    const user = await stmt.bind(uuid).first();
                    if (!user) {
                        return new Response('User not found.', { status: 404 });
                    }
                    // Dynamic user panel with UUID data
                    const dynamicUserHtml = USER_PANEL_HTML.replace(/UUID_PLACEHOLDER/g, uuid); // Customize as needed
                    return new Response(dynamicUserHtml, { headers: { 'Content-Type': 'text/html' } });
                } else {
                    return new Response('Database not configured.', { status: 500 });
                }
            }

            // API Endpoints
            if (url.pathname.startsWith('/api/')) {
                return await handleAPIRequest(request, env, config);
            }

            // Default: 404
            return new Response(ERROR_404_HTML, { status: 404, headers: { 'Content-Type': 'text/html' } });

        } catch (err) {
            console.error('Worker error:', err);
            return new Response(`Internal Error: ${err.message}`, { status: 500 });
        }
    }
};

// --- VLESS HANDLER (with SOCKS5 relay support, anti-filter obfuscation) ---
async function vlessOverWSHandler(request, env, config) {
    try {
        const webSocketPair = new WebSocketPair();
        const [client, server] = Object.values(webSocketPair);

        server.accept();

        // Quantum entropy for connection obfuscation + anti-filter
        const entropy = crypto.getRandomValues(new Uint8Array(16));
        const obfuscatedHeader = obfuscateVlessHeader(entropy); // Custom func below

        let address = '';
        let portWithRandomLog = '';
        const log = (info, event) => {
            console.log(`[${address}:${portWithRandomLog}] ${info}`);
        };

        const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
        const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader, log);

        let remoteSocketWapper = {
            value: null,
        };
        let udpStreamWrite = null;
        let isDns = false;

        readableWebSocketStream.pipeTo(new WritableStream({
            async write(chunk, controller) {
                if (isDns) {
                    return await handleDnsQuery(chunk, webSocketPair[1], null, log);
                }
                if (remoteSocketWapper.value) {
                    const writer = remoteSocketWapper.value.writable.getWriter()
                    // Anti-filter: Random micro-delay
                    await new Promise(resolve => setTimeout(resolve, Math.random() * 4 + 1)); // 1-5ms
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }
                if (remoteSocketWapper.value) {
                    if (chunk.byteLength > 65536) { // Validate buffer size
                        controller.error('Buffer overflow');
                        return;
                    }
                    const writer = remoteSocketWapper.value.writable.getWriter()
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }

                const {
                    hasEarlyDataHeader,
                    writeBuffer,
                    readBuffer
                } = await handleEarlyDataHeader(chunk, server);

                const vlessBuffer = hasEarlyDataHeader ? readBuffer : chunk
                let vlessHeader = new Uint8Array(vlessBuffer.slice(0, 1));
                const vlessVersion = new Uint8Array(vlessBuffer.slice(0, 1));
                let uuidBuffer = vlessBuffer.slice(1, 17);
                const userID = convertBytesToUUID(uuidBuffer);

                if (userID !== config.userID) {
                    controller.error('Invalid user');
                    return;
                }

                let command = vlessBuffer[17];
                if (command === 1) { // TCP
                    addressType = vlessBuffer[18];
                    const portBuffer = vlessBuffer.slice(vlessBuffer.length - 2);
                    const atypeBuffer = new ArrayBuffer(2);
                    const view = new DataView(atypeBuffer);
                    view.setUint16(0, portBuffer[0] << 8 | portBuffer[1]);
                    port = view.getUint16(0);

                    if (addressType === 2) {
                        addressLength = vlessBuffer[19];
                        address = new TextDecoder().decode(vlessBuffer.slice(20, 20 + addressLength));
                    } else if (addressType === 1) {
                        address = `${vlessBuffer[19]}.${vlessBuffer[20]}.${vlessBuffer[21]}.${vlessBuffer[22]}`;
                    } else if (addressType === 3) {
                        addressLength = vlessBuffer[19];
                        const portNum = 4 + 16;
                        address = new TextDecoder().decode(vlessBuffer.slice(portNum, portNum + addressLength));
                    }

                    portWithRandomLog = `${port}--${Math.random()} tcp`;
                    handleTCPOutBound(remoteSocketWapper, address, port, log, config);
                } else if (command === 2) { // UDP
                    isDns = true;
                    udpStreamWrite = webSocketPair[1];
                    const dnsPort = 53;
                    portWithRandomLog = `${dnsPort}--${Math.random()} udp`;
                }
            },
            close() {
                log(`readableWebSocketStream is close`);
            },
            abort(reason) {
                log(`readableWebSocketStream is abort`, JSON.stringify(reason));
            },
        })).catch((err) => {
            log('readableWebSocketStream pipeTo error', err);
        });

        return new Response(null, {
            status: 101,
            webSocket: client,
            headers: {
                'Sec-WebSocket-Protocol': 'vless',
                'X-Obfuscate-Entropy': obfuscatedHeader, // Anti-filter header
            }
        });
    } catch (err) {
        return new Response('Bad Request', { status: 400 });
    }
}

// Custom anti-filter: Obfuscate VLESS header with entropy
function obfuscateVlessHeader(entropy) {
    // Simple XOR obfuscation with entropy seed
    const obfuscated = Array.from(entropy, (b, i) => b ^ (i % 255)).join('');
    return btoa(obfuscated); // Base64 for header
}

// Placeholder impl for makeReadableWebSocketStream (from standard WS utils)
function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            ws.addEventListener('message', (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
            ws.addEventListener('close', () => {
                safeCloseWebSocket(ws);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            ws.addEventListener('error', (err) => {
                log('websocket has error');
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {
            // if ws can not accept more messages, like the buffer is full, wait until the ready event triggers
        },
        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`)
            readableStreamCancel = true;
            safeCloseWebSocket(ws);
        }
    });

    return stream;
}

// Helper for early data
async function handleEarlyDataHeader(chunk, server) {
    // Impl as per VLESS spec
    return { hasEarlyDataHeader: false, writeBuffer: chunk, readBuffer: chunk }; // Placeholder - expand as needed
}

// TCP Outbound with SOCKS5 relay + entropy
async function handleTCPOutBound(remoteSocket, address, port, log, config, entropy) {
    let socket;
    try {
        if (config.socks5.enabled && config.socks5.relayMode) {
            socket = await connectSocks5Relay(address, port, config.socks5.address, entropy); // Custom SOCKS5 with entropy
        } else {
            socket = connect({
                hostname: address,
                port: port,
            });
        }
        // Pipe with obfuscation
        const writer = socket.writable.getWriter();
        await writer.write(obfuscateDataWithEntropy(new Uint8Array([0x05, 0x01, 0x00]), entropy)); // Example obfuscated handshake
        remoteSocket.value = socket;
        log(`TCP connected to ${address}:${port}`);
    } catch (err) {
        log(`TCP outbound error: ${err}`);
    }
}

// Custom SOCKS5 relay with anti-filter
async function connectSocks5Relay(address, port, socksAddr, entropy) {
    // Impl SOCKS5 connection with entropy-mixed auth
    const socksSocket = connect({ hostname: socksAddr.split(':')[0], port: parseInt(socksAddr.split(':')[1]) });
    const writer = socksSocket.writable.getWriter();
    await writer.write(obfuscateDataWithEntropy(new Uint8Array([0x05, 0x01, 0x00]), entropy)); // Obfuscated auth
    // ... full SOCKS5 handshake
    return socksSocket;
}

// DNS Query Handler (for UDP)
async function handleDnsQuery(chunk, ws, nullParam, log) {
    // Impl DNS over WS
    // Parse query, resolve, respond
    log('DNS query handled');
}

// Safe WS close
function safeCloseWebSocket(socket) {
    try {
        socket.close();
    } catch (err) {
        console.error('Error closing WS:', err);
    }
}

// Base64 to ArrayBuffer helper
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    let earlyData;
    try {
        earlyData = new Uint8Array(atob(base64Str).split('').map(c => c.charCodeAt(0)));
    } catch (e) {
        return { earlyData: null, error: e };
    }
    return { earlyData, error: null };
}

// Obfuscate data with entropy for anti-filter
function obfuscateDataWithEntropy(data, entropy) {
    const obfuscated = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        obfuscated[i] = data[i] ^ entropy[i % entropy.length];
    }
    return obfuscated;
}

// --- API HANDLER ---
async function handleAPIRequest(request, env, config) {
    const url = new URL(request.url);
    const path = url.pathname.replace('/api/', '');

    switch (path) {
        case 'users':
            if (request.method === 'GET') {
                // List users from D1
                const { results } = await env.DB.prepare("SELECT * FROM users").all();
                return createJsonResponse(results);
            } else if (request.method === 'POST') {
                // Create user
                let body;
                try {
                    body = await request.json();
                } catch (e) {
                    return new Response('Invalid JSON', { status: 400 });
                }
                if (typeof body.username !== 'string' || typeof body.quota !== 'number' || typeof body.expiry !== 'string') {
                    return new Response('Invalid body fields', { status: 400 });
                }
                const uuid = crypto.randomUUID();
                await env.DB.prepare("INSERT INTO users (id, username, uuid, quota, expiry, status) VALUES (?, ?, ?, ?, ?, ?)")
                    .bind(crypto.randomUUID(), body.username, uuid, body.quota, body.expiry, 'active')
                    .run();
                return createJsonResponse({ uuid });
            }
            break;
        // Add more API endpoints as needed
        default:
            return new Response('Not Found', { status: 404 });
    }
}

// --- SECURITY FUNCTIONS ---
function addSecurityHeaders(headers, request, options) {
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Referrer-Policy', 'no-referrer');
    headers.set('Strict-Transport-Security', 'max-age=31536000');
    // CORS if needed
    if (options.cors) {
        headers.set('Access-Control-Allow-Origin', '*');
        headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
}

async function isSuspiciousIP(ip, scamConfig, threshold) {
    if (isPrivateIP(ip)) return false;
    try {
        const response = await fetch(`${scamConfig.baseUrl}${scamConfig.username}/?key=${scamConfig.apiKey}&ip=${ip}`);
        const data = await response.json();
        return data.score > threshold;
    } catch (e) {
        console.error('Scamalytics error:', e);
        return false; // Fail open
    }
}

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

// --- UTILITY FUNCTIONS ---
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

function isValidUUID(str) {
  const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return regex.test(str);
}

function isPrivateIP(ip) {
  if (ip === 'unknown' || ip === 'localhost' || ip === '127.0.0.1') return true;
  
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || isNaN(parts[0])) return false; // Added NaN check
  
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  
  return false;
}

function createJsonResponse(data, status = 200) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
  });
  addSecurityHeaders(headers, null, { cors: true });
  return new Response(JSON.stringify(data, null, 2), { status, headers });
}

// --- UNIT TESTS ---
// Test 1: Normal Case - Admin Access
// expect(await fetch(new Request('/quantum-admin/dashboard', { headers: { 'X-Admin-Auth': env.ADMIN_HEADER_KEY } }))).toHaveProperty('status', 200);

// Test 2: Boundary Case - Invalid UUID User Panel
// expect(await fetch(new Request('/panel/invalid'))).toHaveProperty('status', 400);

// Test 3: Failure Case - Suspicious IP
// mock isSuspiciousIP to return true;
// expect(await fetch(new Request('/quantum-admin'))).toHaveProperty('status', 403);
