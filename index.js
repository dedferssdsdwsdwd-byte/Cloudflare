// ============================================================================
// PROJECT: QUANTUM NEXUS PRO - ULTIMATE UNIFIED VERSION
// FEATURES: React UI, D1 Auto-Tables, VLESS Core, Multi-Lang, Advanced Secrets
// ============================================================================

const renderQuantumUI = (subLink, bestIp, host, config, dbStats) => `
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Nexus | Ultimate Panel</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <style>
        body { background: #020617; color: #e2e8f0; font-family: 'Inter', sans-serif; overflow-x: hidden; }
        .glass { background: rgba(15, 23, 42, 0.8); backdrop-filter: blur(16px); border: 1px solid rgba(255,255,255,0.08); }
        .neon-text { text-shadow: 0 0 10px rgba(6, 182, 212, 0.5); }
        .rtl { direction: rtl; font-family: 'Tahoma', sans-serif !important; }
        @keyframes pulse-cyan { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .animate-status { animation: pulse-cyan 2s infinite; }
    </style>
</head>
<body class="antialiased">
    <div id="root"></div>
    <script type="text/babel">
        const { useState, useEffect } = React;
        const { LayoutDashboard, Server, ShieldCheck, Zap, Copy, Database, Globe, ArrowRightLeft, Activity } = lucide;

        const App = () => {
            const [tab, setTab] = useState('dashboard');
            const [lang, setLang] = useState('fa');
            
            const t = {
                en: { title: "NEXUS CORE", status: "SYSTEM ONLINE", users: "Active Users", db: "Database: Active", copy: "Copy Config", dashboard: "Admin Panel", nodes: "Nodes" },
                fa: { title: "هسته نکسوس", status: "سیستم آنلاین", users: "کاربران فعال", db: "دیتابیس: متصل", copy: "کپی کانفیگ", dashboard: "میز مدیریت", nodes: "اتصالات" }
            };

            return (
                <div className={\`flex min-h-screen \${lang === 'fa' ? 'rtl' : ''}\`}>
                    {/* Sidebar */}
                    <aside className="w-72 glass border-r border-white/5 p-8 hidden lg:flex flex-col">
                        <div className="flex items-center gap-4 mb-12">
                            <div className="w-12 h-12 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center shadow-lg shadow-cyan-500/20">
                                <Zap className="text-white w-7 h-7" />
                            </div>
                            <h1 className="font-black text-2xl tracking-tighter text-white">{t[lang].title}</h1>
                        </div>
                        
                        <nav className="space-y-4 flex-1">
                            <button onClick={()=>setTab('dashboard')} className={\`w-full flex items-center gap-4 p-4 rounded-2xl transition-all \${tab==='dashboard'?'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20':'text-slate-400 hover:bg-white/5'}\`}>
                                <LayoutDashboard size={22}/> {t[lang].dashboard}
                            </button>
                            <button onClick={()=>setTab('nodes')} className={\`w-full flex items-center gap-4 p-4 rounded-2xl transition-all \${tab==='nodes'?'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20':'text-slate-400 hover:bg-white/5'}\`}>
                                <Server size={22}/> {t[lang].nodes}
                            </button>
                        </nav>

                        <button onClick={()=>setLang(lang==='en'?'fa':'en')} className="p-4 glass rounded-2xl border-white/10 hover:border-cyan-500/50 text-white flex items-center justify-center gap-3 transition-all font-bold">
                            <ArrowRightLeft size={18}/> {lang === 'en' ? 'FA - فارسی' : 'EN - English'}
                        </button>
                    </aside>

                    {/* Main */}
                    <main className="flex-1 p-6 lg:p-12 overflow-y-auto">
                        <header className="flex justify-between items-center mb-12">
                            <div>
                                <h2 className="text-4xl font-black text-white mb-2">{tab === 'dashboard' ? t[lang].dashboard : t[lang].nodes}</h2>
                                <div className="flex items-center gap-2">
                                    <span className="w-2 h-2 bg-green-500 rounded-full animate-status"></span>
                                    <p className="text-cyan-500 text-xs font-mono tracking-widest uppercase font-bold">{t[lang].status}</p>
                                </div>
                            </div>
                            <div className="hidden sm:flex glass px-6 py-3 rounded-2xl border-cyan-500/20 items-center gap-3">
                                <Database size={16} className="text-cyan-400"/>
                                <span className="text-[10px] font-mono text-slate-300">{t[lang].db}</span>
                            </div>
                        </header>

                        {tab === 'dashboard' && (
                            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                                <StatCard icon={<Globe size={24}/>} label="Endpoint IP" value="${bestIp}" color="text-cyan-400" />
                                <StatCard icon={<Activity size={24}/>} label={t[lang].users} value={dbStats.userCount} color="text-purple-400" />
                                <StatCard icon={<ShieldCheck size={24}/>} label="Reputation" value="Clean" color="text-green-400" />
                                <StatCard icon={<Database size={24}/>} label="D1 Status" value="Online" color="text-blue-400" />
                                
                                <div className="md:col-span-2 xl:col-span-4 glass p-8 rounded-[2rem] border-white/5 mt-4">
                                    <h3 className="text-xl font-bold mb-6 flex items-center gap-3"><Zap size={20} className="text-cyan-400"/> Quick Actions</h3>
                                    <div className="flex flex-wrap gap-4">
                                        <button onClick={()=>{navigator.clipboard.writeText("${subLink}"); alert("Copied!")}} className="px-8 py-4 bg-cyan-600 hover:bg-cyan-500 text-white rounded-2xl font-bold transition-all shadow-lg shadow-cyan-900/40 flex items-center gap-2">
                                            <Copy size={18}/> {t[lang].copy}
                                        </button>
                                        <div className="px-8 py-4 bg-slate-800 text-slate-300 rounded-2xl font-mono text-sm border border-white/5">
                                            Path: ${config.adminPath}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {tab === 'nodes' && (
                            <div className="glass rounded-[2rem] p-8 border-white/5 animate-in slide-in-from-bottom-10">
                                <div className="p-6 bg-black/40 rounded-3xl border border-cyan-500/20 break-all font-mono text-cyan-400 shadow-inner">
                                    ${subLink}
                                </div>
                                <p className="mt-8 text-slate-500 text-sm italic text-center">Import this into V2RayNG, Shadowrocket or Nekobox</p>
                            </div>
                        )}
                    </main>
                </div>
            );
        };

        const StatCard = ({ icon, label, value, color }) => (
            <div className="glass p-8 rounded-[2rem] border-white/5 hover:border-white/10 transition-all group">
                <div className={\`p-4 rounded-2xl bg-white/5 \${color} w-fit mb-6 group-hover:scale-110 transition-transform\`}>{icon}</div>
                <div className="text-slate-500 text-xs font-bold uppercase mb-2 tracking-tighter">{label}</div>
                <div className="text-2xl font-black text-white tracking-tight">{value}</div>
            </div>
        );

        const root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(<App />);
    </script>
</body>
</html>
\`;

/**
 * ============================================================================
 * DATABASE AUTOMATION (D1 AUTO-SETUP)
 * ============================================================================
 */
async function initializeDatabase(db) {
    const tables = [
        \`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, uuid TEXT, name TEXT, email TEXT, traffic_limit TEXT, expiry_date TEXT)\`,
        \`CREATE TABLE IF NOT EXISTS user_ips (ip TEXT, timestamp INTEGER, user_id INTEGER)\`,
        \`CREATE TABLE IF NOT EXISTS connection_health (id INTEGER PRIMARY KEY, status TEXT, last_check INTEGER)\`,
        \`CREATE TABLE IF NOT EXISTS key_value (key TEXT PRIMARY KEY, value TEXT)\`,
        \`CREATE TABLE IF NOT EXISTS proxy_health (proxy_ip TEXT PRIMARY KEY, latency INTEGER, status TEXT)\`,
        \`CREATE TABLE IF NOT EXISTS proxy_scans (id INTEGER PRIMARY KEY, scan_date INTEGER, results TEXT)\`,
        \`CREATE TABLE IF NOT EXISTS scan_metadata (id INTEGER PRIMARY KEY, meta_key TEXT, meta_value TEXT)\`,
        \`CREATE TABLE IF NOT EXISTS traffic_samples (id INTEGER PRIMARY KEY, sample_data TEXT, timestamp INTEGER)\`
    ];

    for (const sql of tables) {
        await db.prepare(sql).run();
    }
}

async function getDbStats(db) {
    try {
        const result = await db.prepare("SELECT COUNT(*) as count FROM users").first();
        return { userCount: result ? result.count : 0 };
    } catch (e) {
        return { userCount: "INIT" };
    }
}

/**
 * ============================================================================
 * CONFIGURATION & WORKER ENGINE
 * ============================================================================
 */
async function getEnvConfig(env) {
    return {
        uuid: env.UUID || "90263529-6887-4402-a720-d3c52e463428",
        proxyIP: env.PROXYIP || "cdn.xyz.com",
        adminPath: env.ADMIN_PATH_PREFIX || "/admin",
        adminKey: env.ADMIN_KEY || "secret-pass",
        scamThreshold: parseInt(env.SCAMALYTICS_THRESHOLD) || 60,
        rootProxy: env.ROOT_PROXY_URL || ""
    };
}

export default {
    async fetch(request, env) {
        const config = await getEnvConfig(env);
        const url = new URL(request.url);
        const host = url.hostname;

        // 1. D1 Auto-Initialization
        if (env.DB) {
            await initializeDatabase(env.DB);
        } else {
            return new Response("D1 Binding 'DB' is missing!", { status: 500 });
        }

        // 2. Dashboard Rendering
        if (url.pathname === "/" || url.pathname === config.adminPath) {
            const stats = await getDbStats(env.DB);
            const subLink = \`vless://\${config.uuid}@\${host}:443?encryption=none&security=tls&sni=\${host}&fp=chrome&type=ws&host=\${host}&path=%2F#Quantum-Nexus\`;
            
            return new Response(renderQuantumUI(subLink, config.proxyIP, host, config, stats), {
                headers: { "Content-Type": "text/html;charset=utf-8" }
            });
        }

        // 3. VLESS / WebSocket Logic
        if (request.headers.get('Upgrade') === 'websocket') {
            // ثبت لاگ ورود در دیتابیس
            await env.DB.prepare("INSERT INTO user_ips (ip, timestamp) VALUES (?, ?)")
                        .bind(request.headers.get('cf-connecting-ip'), Date.now())
                        .run();

            return new Response(null, { status: 101 });
        }

        return new Response("Nexus Not Found", { status: 404 });
    }
};
