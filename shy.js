process.env.UV_THREADPOOL_SIZE = 4096;
try {
  process.setpriority(process.pid, -20);
  require('child_process').execSync(`powershell "Get-Process -Id ${process.pid} | ForEach-Object { $_.PriorityClass = 'RealTime' }"`);
} catch {}

const tls = require('tls');
const WebSocket = require('ws');
const fs = require('fs');
const extractJsonFromString = require('extract-json-from-string');
require("dns").setDefaultResultOrder("ipv4first");

const TOKEN = ""; // token gir
const TARGET_GUILD_ID = "1420089029441093796";
const MFA_PATH = "mfa.txt";
const TLS_POOL_SIZE = 3;

let mfaToken = null;
let lastMfaToken = null;
let vanity = null;
const guilds = {};
const sessionCache = new Map();
const vanityRequestCache = new Map();

const tlsPool = new Array(TLS_POOL_SIZE);

const HOST_HEADER = Buffer.from('Host: canary.discord.com\r\n');
const AUTH_HEADER = Buffer.from(`Authorization: ${TOKEN}\r\n`);
const CONTENT_TYPE = Buffer.from('Content-Type: application/json\r\n');
const USER_AGENT = Buffer.from('User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\r\n');
const SUPER_PROPS = Buffer.from('X-Super-Properties: eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3gifQ==\r\n');
const PATCH_PREFIX = Buffer.from(`PATCH /api/v9/guilds/${TARGET_GUILD_ID}/vanity-url HTTP/1.1\r\n`);
const KEEP_ALIVE = Buffer.from('Connection: keep-alive\r\n');
const CRLF = Buffer.from('\r\n');
const KEEP_ALIVE_REQUEST = Buffer.from('GET / HTTP/1.1\r\nHost: canary.discord.com\r\nConnection: keep-alive\r\n\r\n');

const TLS_OPTIONS = {
  host: "canary.discord.com",
  port: 443,
  minVersion: "TLSv1.3",
  maxVersion: "TLSv1.3",
  servername: "canary.discord.com",
  rejectUnauthorized: false,
  ALPNProtocols: ["http/1.1"],
  ciphers: "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
  ecdhCurve: "X25519",
  honorCipherOrder: true,
  keepAlive: true,
  keepAliveInitialDelay: 0,
  handshakeTimeout: 500,
  highWaterMark: 1024 * 1024
};

class BufferPool {
  constructor(size, bufferSize) {
    this.pool = new Array(size);
    this.index = 0;
    
    for (let i = 0; i < size; i++) {
      this.pool[i] = Buffer.allocUnsafe(bufferSize);
    }
  }
  
  get() {
    const buf = this.pool[this.index];
    this.index = (this.index + 1) % this.pool.length;
    return buf;
  }
}

const requestPool = new BufferPool(100, 4096);

function buildVanityRequest(code) {
  if (vanityRequestCache.has(code)) {
    return vanityRequestCache.get(code);
  }
  
  const payload = JSON.stringify({ code });
  const payloadLength = Buffer.byteLength(payload);
  
  const buf = requestPool.get();
  let offset = 0;
  
  PATCH_PREFIX.copy(buf, offset); offset += PATCH_PREFIX.length;
  HOST_HEADER.copy(buf, offset); offset += HOST_HEADER.length;
  AUTH_HEADER.copy(buf, offset); offset += AUTH_HEADER.length;
  
  if (mfaToken) {
    const mfaHeader = `X-Discord-MFA-Authorization: ${mfaToken}\r\n`;
    offset += buf.write(mfaHeader, offset);
  }
  
  USER_AGENT.copy(buf, offset); offset += USER_AGENT.length;
  SUPER_PROPS.copy(buf, offset); offset += SUPER_PROPS.length;
  CONTENT_TYPE.copy(buf, offset); offset += CONTENT_TYPE.length;
  KEEP_ALIVE.copy(buf, offset); offset += KEEP_ALIVE.length;
  
  const contentLength = `Content-Length: ${payloadLength}\r\n`;
  offset += buf.write(contentLength, offset);
  
  CRLF.copy(buf, offset); offset += CRLF.length;
  offset += buf.write(payload, offset);
  
  const request = buf.slice(0, offset);
  vanityRequestCache.set(code, request);
  
  return request;
}

function createTlsConnection(index) {
  const options = { ...TLS_OPTIONS };
  if (sessionCache.has('canary.discord.com')) {
    options.session = sessionCache.get('canary.discord.com');
  }
  
  const conn = tls.connect(options);
  
  conn.setNoDelay(true);
  conn.setKeepAlive(true, 0);
  if (conn.setPriority) conn.setPriority(0);
  
  if (conn.socket) {
    conn.socket.setNoDelay(true);
    conn.socket.setKeepAlive(true, 0);
    if (conn.socket.setRecvBufferSize) conn.socket.setRecvBufferSize(32 * 1024 * 1024);
    if (conn.socket.setSendBufferSize) conn.socket.setSendBufferSize(32 * 1024 * 1024);
  }
  
  conn.on("data", (data) => {
    try {
      const ext = extractJsonFromString(data.toString());
      if (!Array.isArray(ext)) return;
      
      const find = ext.find(e => e.code || e.message);
      if (find) {
        console.log(`[TLS] Response for ${vanity}: ${JSON.stringify(find)}`);
      }
    } catch (e) {}
  });
  
  const cleanup = () => {
    if (tlsPool[index] === conn) {
      tlsPool[index] = null;
      setTimeout(() => {
        tlsPool[index] = createTlsConnection(index);
      }, 100);
    }
  };
  
  conn.on("error", cleanup);
  conn.on("close", cleanup);
  
  conn.on("secureConnect", () => {
    console.log(`[TLS] Connection ${index} ready`);
    conn.write(KEEP_ALIVE_REQUEST);
  });
  
  conn.on("session", (session) => {
    sessionCache.set('canary.discord.com', session);
  });
  
  return conn;
}

function initializeConnectionPools() {
  for (let i = 0; i < TLS_POOL_SIZE; i++) {
    tlsPool[i] = createTlsConnection(i);
  }
}

function keepConnectionsAlive() {
  for (let i = 0; i < TLS_POOL_SIZE; i++) {
    const conn = tlsPool[i];
    if (conn && conn.writable) {
      conn.write(KEEP_ALIVE_REQUEST);
    }
  }
}

async function loadMfaToken() {
  try {
    const token = await fs.promises.readFile(MFA_PATH, 'utf8');
    const trimmedToken = token.trim();
    
    if (trimmedToken && trimmedToken !== lastMfaToken) {
      lastMfaToken = trimmedToken;
      mfaToken = trimmedToken;
      console.log("mfa");
      vanityRequestCache.clear();
    }
  } catch (e) {}
}

function extremeSnipe(code) {
  vanity = code;
  
  const tlsRequest = buildVanityRequest(code);
  for (let i = 0; i < TLS_POOL_SIZE; i++) {
    const conn = tlsPool[i];
    if (conn && conn.writable) {
      if (conn.setPriority) conn.setPriority(0);
      try {
        conn.write(tlsRequest);
      } catch (e) {}
    }
  }
}

function connectWebSocket() {
  const ws = new WebSocket("wss://gateway-us-east1-b.discord.gg", {
    perMessageDeflate: false,
    autoPong: true,
    skipUTF8Validation: true,
    followRedirects: false,
    rejectUnauthorized: false,
    maxRedirects: 0,
    handshakeTimeout: 30000,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
    }
  });
  
  ws.on('open', () => {
    console.log("[WS] Connected");
    ws.send(JSON.stringify({
      op: 2,
      d: {
        token: TOKEN,
        intents: 1,
        properties: {
          os: "linux",
          browser: "Discord Android",
          device: "Android"
        },
        guild_subscriptions: false,
        large_threshold: 0
      }
    }));
  });
  
  ws.on('message', (data) => {
    try {
      const payload = JSON.parse(data);
      const { op, t, d } = payload;
      
      if (op === 10) {
        const heartbeatInterval = d.heartbeat_interval;
        setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ op: 1, d: null }));
          }
        }, heartbeatInterval);
      } 
      else if (op === 0) {
        if (t === "READY") {
          if (d && d.guilds) {
            const vanityGuilds = d.guilds.filter(g => g.vanity_url_code);
            for (const guild of vanityGuilds) {
              guilds[guild.id] = guild.vanity_url_code;
            }
          }
        }
        else if (t === "GUILD_UPDATE") {
          const find = guilds[d.guild_id];
          if (find && find !== d.vanity_url_code) {
            vanity = find;
            extremeSnipe(find);
            
            if (d.vanity_url_code) {
              guilds[d.guild_id] = d.vanity_url_code;
            } else {
              delete guilds[d.guild_id];
            }
          }
        }
      }
    } catch (e) {}
  });
  
  ws.on('close', () => {
    console.log("[WS] Disconnected, reconnecting");
    setTimeout(connectWebSocket, 2000);
  });
  
  ws.on('error', (err) => {
    console.error("[WS] Error:", err.message);
    ws.close();
  });
}

async function initialize() {
  await loadMfaToken();
  initializeConnectionPools();
  connectWebSocket();
  
  setInterval(keepConnectionsAlive, 1500);
  setInterval(loadMfaToken, 10000);
}

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

initialize();
