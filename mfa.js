"use strict";
// Coded By Shy
const tls = require("tls");
const http2 = require("http2");
const fs = require('fs');
const path = require('path');

// Configuration
const config = {
    discordHost: "canary.discord.com",
    discordToken: "",
    password: "."
};

// Variables
let mfaToken = null;
let savedTicket = null;

// HTTP headers
const headers = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ravi/1.0.9164 Chrome/124.0.6367.243 Electron/30.2.0 Safari/537.36",
  "Authorization": config.discordToken,
  "Content-Type": "application/json",
  "X-Super-Properties": "eyJvcyI6IkFuZHJvaWQiLCJicm93c2VyIjoiQW5kcm9pZCBDaHJvbWUiLCJkZXZpY2UiOiJBbmRyb2lkIiwic3lzdGVtX2xvY2FsZSI6InRyLVRSIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKExpbnV4OyBBbmRyb2lkIDYuMDsgTmV4dXMgNSBCdWlsZC9NUkE1OE4pIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMzEuMC4wLjAgTW9iaWxlIFNhZmFyaS81MzcuMzYiLCJicm93c2VyX3ZlcnNpb24iOiIxMzEuMC4wLjAiLCJvc192ZXJzaW9uIjoiNi4wIiwicmVmZXJyZXIiOiJodHRwczovL2Rpc2NvcmQuY29tL2NoYW5uZWxzL0BtZS8xMzAzMDQ1MDIyNjQzNTIzNjU1IiwicmVmZXJyaW5nX2RvbWFpbiI6ImRpc2NvcmQuY29tIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjM1NTYyNCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiaGFzX2NsaWVudF9tb2RzIjpmYWxzZX0="
};

// HTTP/2 session management
const sessions = new Map();
const MAX_SESSIONS = 1;
const SESSION_SETTINGS = {
    settings: {
        enablePush: false
    }
};

const TLS_OPTIONS = {
    rejectUnauthorized: false,
    secureContext: tls.createSecureContext({
        secureProtocol: 'TLSv1_2_method'
    }),
    ALPNProtocols: ['h2']
};

// Create HTTP/2 session
function createSession(index) {
    const session = http2.connect("https://canary.discord.com", {
        ...SESSION_SETTINGS,
        createConnection: () => tls.connect(443, 'canary.discord.com', TLS_OPTIONS)
    });
    
    session.on('error', (err) => {
        console.log(`Session ${index} error: ${err.message}`);
        sessions.delete(index);
        setTimeout(() => createSession(index), 1000);
    });
    
    sessions.set(index, session);
    console.log(`Session ${index} created`);
    return session;
}

let sessionIndex = 0;

// HTTP/2 request function
async function fastHttp2Request(method, path, customHeaders = {}, body = null) {
    return new Promise((resolve, reject) => {
        const session = sessions.get(sessionIndex);
        sessionIndex = (sessionIndex + 1) % MAX_SESSIONS;
        
        if (!session || session.closed || session.destroyed) {
            reject(new Error("No valid session available"));
            return;
        }
        
        const requestHeaders = {
            ...headers,
            ...customHeaders,
            ":method": method,
            ":path": path,
            ":authority": "canary.discord.com",
            ":scheme": "https"
        };
        
        const stream = session.request(requestHeaders, { endStream: !body });
        const chunks = [];
        
        stream.on("data", chunk => chunks.push(chunk));
        
        stream.on("end", () => {
            resolve(Buffer.concat(chunks).toString());
        });
        
        stream.on("error", (err) => {
            console.log(`Stream error: ${err.message}`);
            stream.destroy();
            reject(err);
        });

        if (body) {
            stream.end(Buffer.from(body));
        }
    });
}

// Save MFA token to file
function saveMfaToken(token) {
    const filePath = path.join(__dirname, 'mfa.txt');
    fs.writeFileSync(filePath, token, 'utf8');
    console.log(`MFA token saved to ${filePath} at ${new Date().toISOString()}`);
}

// Get and refresh MFA token
async function getMfaToken() {
    try {
        // Trigger MFA challenge
        console.log("Requesting MFA challenge...");
        const response = await fastHttp2Request("PATCH", `/api/v9/guilds/0/vanity-url`);
        const data = JSON.parse(response);
        
        if (data.code === 60003 && data.mfa && data.mfa.ticket) {
            savedTicket = data.mfa.ticket;
            console.log("MFA challenge received, submitting password...");
            
            // Complete MFA challenge with password
            const mfaResponse = await fastHttp2Request(
                "POST",
                "/api/v9/mfa/finish",
                { "Content-Type": "application/json" },
                JSON.stringify({
                    ticket: savedTicket,
                    mfa_type: "password",
                    data: config.password,
                })
            );
            
            const mfaData = JSON.parse(mfaResponse);
            if (mfaData.token) {
                mfaToken = mfaData.token;
                console.log(`New MFA token obtained: ${mfaToken.substring(0, 10)}...`);
                saveMfaToken(mfaToken);
                return true;
            } else {
                console.log("Failed to get MFA token:", mfaData);
                return false;
            }
        } else {
            console.log("Unexpected response:", data);
            return false;
        }
    } catch (error) {
        console.error('MFA token error:', error?.message || 'Unknown error');
        return false;
    }
}

// Initialize sessions and start the process
async function initialize() {
    // Create HTTP/2 sessions
    for (let i = 0; i < MAX_SESSIONS; i++) {
        createSession(i);
    }
    
    console.log('Starting MFA token refresher...');
    
    // Get initial MFA token
    const success = await getMfaToken();
    if (!success) {
        console.log('Failed to get initial MFA token, retrying in 5 seconds...');
        setTimeout(initialize, 5000);
        return;
    }
    
    // Set up MFA token refresh every 4 minutes
    const REFRESH_INTERVAL = 4 * 60 * 1000; // 4 minutes in milliseconds
    setInterval(async () => {
        console.log('Refreshing MFA token...');
        await getMfaToken();
    }, REFRESH_INTERVAL);
}

// Handle errors
process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
});

process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
});

// Start the program
initialize();