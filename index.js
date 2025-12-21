// @ts-nocheck
/**
 * 🚀 VLESS PRO - PART 1
 * CONCATENATE FILES 1-9 IN ORDER
 */
import { connect } from 'cloudflare:sockets';

const CONFIG = {
  uuid: 'd342d11e-d424-4583-b36e-524ab1f0afa4', // Admin UUID
  remoteDomain: 'www.visa.com',                 // Proxy Target
  remotePort: 443,
  trojanPassword: 'admin',                      // Trojan Password
};

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. Handle WebSocket (VLESS/Trojan)
      if (upgradeHeader === 'websocket') {
        const vlessMatch = url.searchParams.get('type') === 'ws';
        return await vlessOverWSHandler(request);
      }

      // 2. Serve Admin Dashboard
      if (url.pathname === '/' || url.pathname.startsWith('/dashboard')) {
        return new Response(getDashboardHTML(url.origin, CONFIG.uuid), {
          status: 200,
          headers: { 'Content-Type': 'text/html;charset=utf-8' },
        });
      }

      // 3. Fallback Redirect
      return Response.redirect('https://' + CONFIG.remoteDomain, 301);

    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

/**
 * 🚀 VLESS PRO - PART 2
 */
async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
  };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const {
        hasError,
        message,
        portRemote,
        addressRemote,
        rawDataIndex,
        vlessVersion,
        isUDP,
      } = processVlessHeader(chunk, CONFIG.uuid);

      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '}`;

      if (hasError) {
        throw new Error(message); 
      }

      handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, chunk.slice(rawDataIndex), webSocket, vlessVersion, log);
    },
    close() { log(`readableWebSocketStream is close`); },
    abort(reason) { log(`readableWebSocketStream is abort`, JSON.stringify(reason)); },
  })).catch((err) => {
    log('readableWebSocketStream pipeTo error', err);
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

/**
 * 🚀 VLESS PRO - PART 3
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessVersion, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlessVersion, null, log);
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessVersion, retry, log) {
  await remoteSocket.readable.pipeTo(new WritableStream({
    start() {},
    async write(chunk, controller) {
      if (webSocket.readyState !== WebSocket.READY) {
        controller.error('WS closed');
      }
      webSocket.send(chunk);
    },
    close() { log(`remoteConnection!.readable is close`); },
    abort(reason) { console.error(`remoteConnection!.readable abort`, reason); },
  })).catch((error) => {
    console.error(`remoteSocketToWS has error`, error);
  });
}

/**
 * 🚀 VLESS PRO - PART 4
 */
function getDashboardHTML(host, uuid) {
  const vlessLink = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2F%3Fed%3D2048#VLESS-Worker`;
  const trojanLink = `trojan://${CONFIG.trojanPassword}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F%3Fed%3D2048#Trojan-Worker`;
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS Pro Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
      body { background-color: #030712; color: #f3f4f6; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
      .glass { background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(31, 41, 55, 0.5); }
      .animate-fade-in { animation: fadeIn 0.5s ease-out; }
      @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
      .gradient-text { background-clip: text; -webkit-background-clip: text; color: transparent; background-image: linear-gradient(to right, #60a5fa, #c084fc); }
    </style>
    <script>
      tailwind.config = {
        darkMode: 'class',
        theme: {
          extend: {
            colors: { gray: { 850: '#1f2937', 900: '#111827', 950: '#030712' } }
          }
        }
      }
    </script>
</head>
<body class="min-h-screen selection:bg-blue-500 selection:text-white">
`;
}

/* 🚀 VLESS PRO - PART 5 */
/* Note: Continue string from Part 4 */
    <!-- LOGIN VIEW -->
    <div id="login-view" class="flex flex-col items-center justify-center min-h-[90vh] px-4">
        <div class="w-full max-w-md glass p-8 rounded-2xl shadow-2xl relative overflow-hidden group">
            <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-purple-500"></div>
            <div class="absolute -right-10 -top-10 w-32 h-32 bg-blue-500/10 rounded-full blur-2xl"></div>
            
            <h1 class="text-3xl font-bold mb-2 text-center gradient-text">Admin Access</h1>
            <p class="text-center text-gray-500 text-sm mb-8">VLESS / Trojan / Shadowsocks Manager</p>
            
            <form onsubmit="handleLogin(event)" class="space-y-5">
                <div>
                    <label class="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Password</label>
                    <div class="relative">
                        <span class="absolute left-4 top-3.5 text-gray-500"><i class="fas fa-lock"></i></span>
                        <input id="password-input" type="password" class="w-full bg-gray-950 border border-gray-700 rounded-lg py-3 pl-10 pr-4 text-gray-100 focus:outline-none focus:border-blue-500 transition-all placeholder-gray-600" placeholder="Enter Access Key">
                    </div>
                </div>
                <button type="submit" class="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold py-3.5 rounded-lg shadow-lg shadow-blue-500/20 transition-all transform hover:-translate-y-0.5">
                    Authenticate <i class="fas fa-arrow-right ml-2 opacity-70"></i>
                </button>
            </form>
            <div class="mt-6 pt-6 border-t border-gray-800 text-center">
               <button onclick="switchView('user')" class="text-xs text-gray-500 hover:text-blue-400 transition-colors">Go to User Panel</button>
            </div>
        </div>
    </div>

/* 🚀 VLESS PRO - PART 6 */
    <!-- ADMIN VIEW -->
    <div id="admin-view" class="hidden max-w-7xl mx-auto p-4 md:p-6 space-y-8 animate-fade-in">
        <div class="flex flex-col md:flex-row justify-between items-center gap-4 border-b border-gray-800/50 pb-6">
            <div>
                <h1 class="text-3xl font-bold gradient-text">VLESS Manager</h1>
                <div class="flex items-center gap-2 mt-2">
                    <span class="relative flex h-2 w-2">
                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                        <span class="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                    </span>
                    <p class="text-gray-400 text-xs font-mono">SYSTEM OPERATIONAL • v3.5.0</p>
                </div>
            </div>
            <div class="flex gap-3">
                <button onclick="window.location.reload()" class="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition-all text-sm"><i class="fas fa-sync-alt mr-2"></i>Refresh</button>
                <button onclick="logout()" class="px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-all text-sm"><i class="fas fa-sign-out-alt mr-2"></i>Logout</button>
            </div>
        </div>

        <!-- Connection Info -->
        <div class="glass p-6 rounded-xl border border-gray-800">
             <h3 class="font-bold mb-4">Connection Links</h3>
             <div class="space-y-4">
                <div>
                    <label class="block text-xs font-bold text-gray-500 uppercase mb-2">VLESS URL</label>
                    <div class="flex gap-2">
                        <input id="admin-vless" readonly value="${vlessLink}" class="w-full bg-gray-950 border border-gray-700 text-gray-300 text-xs rounded px-3 py-2 font-mono">
                        <button onclick="copyToClip('admin-vless')" class="bg-blue-600 hover:bg-blue-500 text-white px-4 rounded transition-colors"><i class="fas fa-copy"></i></button>
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-bold text-gray-500 uppercase mb-2">Trojan URL</label>
                    <div class="flex gap-2">
                        <input id="admin-trojan" readonly value="${trojanLink}" class="w-full bg-gray-950 border border-gray-700 text-gray-300 text-xs rounded px-3 py-2 font-mono">
                        <button onclick="copyToClip('admin-trojan')" class="bg-purple-600 hover:bg-purple-500 text-white px-4 rounded transition-colors"><i class="fas fa-copy"></i></button>
                    </div>
                </div>
             </div>
        </div>

        <!-- Fake User Table -->
        <div class="glass rounded-xl border border-gray-800 overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead class="bg-gray-950/50 text-gray-400 uppercase text-xs font-semibold tracking-wider">
                        <tr>
                            <th class="px-6 py-4">Status</th>
                            <th class="px-6 py-4">UUID</th>
                            <th class="px-6 py-4">Role</th>
                            <th class="px-6 py-4 text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800 text-sm">
                        <tr class="hover:bg-white/5 transition-colors">
                            <td class="px-6 py-4"><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">Active</span></td>
                            <td class="px-6 py-4 font-mono text-gray-300">${uuid}</td>
                            <td class="px-6 py-4 text-gray-400">Administrator</td>
                            <td class="px-6 py-4 text-right">
                                <button class="text-gray-400 hover:text-white"><i class="fas fa-cog"></i></button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

/* 🚀 VLESS PRO - PART 7 */
    <!-- USER VIEW -->
    <div id="user-view" class="hidden max-w-4xl mx-auto p-4 md:p-8 flex flex-col items-center justify-center min-h-[80vh] space-y-8 animate-fade-in">
        <button onclick="switchView('login')" class="self-start text-sm text-gray-500 hover:text-white transition-colors mb-4"><i class="fas fa-arrow-left mr-2"></i> Back</button>
        <div class="w-full glass p-8 rounded-3xl shadow-2xl relative overflow-hidden">
             <div class="text-center mb-8">
               <h1 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-green-400 to-blue-500">Your Subscription</h1>
               <p class="text-gray-400 mt-2 text-sm">Scan the QR code to connect instantly.</p>
             </div>
             <div class="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
               <div class="bg-white p-4 rounded-2xl shadow-inner flex items-center justify-center">
                  <div class="w-48 h-48 bg-gray-100 flex items-center justify-center overflow-hidden">
                    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(vlessLink)}" alt="QR Code" class="w-full h-full object-cover" />
                  </div>
               </div>
               <div class="space-y-6">
                 <div>
                   <label class="text-xs font-bold text-gray-500 uppercase tracking-wider">VLESS Connection Link</label>
                   <div class="flex gap-2 mt-2">
                     <input id="user-vless" readOnly value="${vlessLink}" class="w-full bg-gray-950 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-2.5 font-mono focus:outline-none focus:border-blue-500 transition-all" />
                     <button onclick="copyToClip('user-vless')" class="bg-blue-600 hover:bg-blue-500 text-white px-4 rounded-lg transition-colors"><i class="fas fa-copy"></i></button>
                   </div>
                 </div>
                 <div>
                   <label class="text-xs font-bold text-gray-500 uppercase tracking-wider">Trojan Connection Link</label>
                   <div class="flex gap-2 mt-2">
                     <input id="user-trojan" readOnly value="${trojanLink}" class="w-full bg-gray-950 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-2.5 font-mono focus:outline-none focus:border-purple-500 transition-all" />
                     <button onclick="copyToClip('user-trojan')" class="bg-purple-600 hover:bg-purple-500 text-white px-4 rounded-lg transition-colors"><i class="fas fa-copy"></i></button>
                   </div>
                 </div>
               </div>
             </div>
        </div>
    </div>

/* 🚀 VLESS PRO - PART 8 */
    <script>
        function switchView(viewId) {
            document.getElementById('login-view').classList.add('hidden');
            document.getElementById('admin-view').classList.add('hidden');
            document.getElementById('user-view').classList.add('hidden');
            document.getElementById(viewId + '-view').classList.remove('hidden');
        }

        function handleLogin(e) {
            e.preventDefault();
            const pass = document.getElementById('password-input').value;
            // Simple client-side check for demonstration. Real auth should be on server or use token.
            if(pass === 'admin') {
                switchView('admin');
            } else {
                alert('Invalid Password (try "admin")');
            }
        }

        function logout() {
            document.getElementById('password-input').value = '';
            switchView('login');
        }

        function copyToClip(id) {
            const copyText = document.getElementById(id);
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(copyText.value).then(() => {
                alert("Copied to clipboard");
            });
        }
    </script>
</body>
</html>
  `;
}

/**
 * 🚀 VLESS PRO - PART 9 (FINAL)
 */

/**
 * Parses VLESS Header
 */
function processVlessHeader(vlessBuffer, userID) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isUDP = false;
  
  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `command ${command} is not support` };
  }
  
  const portIndex = 18 + optLength + 1;
  const portDecoder = new DataView(vlessBuffer.slice(portIndex, portIndex + 2));
  const portRemote = portDecoder.getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

  let addressValueIndex = addressIndex + 1;
  let addressRemote = '';
  let rawDataIndex = 0;

  if (addressType === 1) {
    addressRemote = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 4)).join('.');
    rawDataIndex = addressValueIndex + 4;
  } else if (addressType === 2) {
    const addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
    addressValueIndex += 1;
    addressRemote = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
    rawDataIndex = addressValueIndex + addressLength;
  } else if (addressType === 3) {
    rawDataIndex = addressValueIndex + 16;
  }

  return {
    hasError: false,
    addressRemote,
    portRemote,
    rawDataIndex,
    vlessVersion: version,
    isUDP,
  };
}

/**
 * Creates a Readable Stream from WebSocket
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
      socket.close();
    }
  } catch (e) {
    console.error('safeCloseWebSocket error', e);
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

