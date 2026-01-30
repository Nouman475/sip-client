/**
 * SIP Registration Client - VoiceInfra-style
 * Matches backend/sip-client.service.js: raw UDP, same REGISTER format,
 * so the extension shows Registered/Active in Yeastar admin.
 */
const dgram = require("dgram");
const crypto = require("crypto");
const os = require("os");

// Configuration (VoiceInfra-style, same as backend sip.config.js)
const config = {
  displayName: "dsd",
  extension: "207",
  sipDomain: "m.sgycm.yeastarcloud.com",
  sipUsername: "207",
  sipPassword: "475909rmnK",
  sipPort: 5060, // Yeastar SIP server port
  // localPort: 5060  // set to bind to a specific port; omit to use ephemeral (like backend)
};

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address;
      }
    }
  }
  return "127.0.0.1";
}

function generateCallId() {
  return crypto.randomBytes(16).toString("hex") + "@" + getLocalIP();
}
function generateTag() {
  return crypto.randomBytes(8).toString("hex");
}
function generateBranch() {
  return crypto.randomBytes(8).toString("hex");
}

function parseAuthParams(authValue) {
  const params = {};
  const regex = /(\w+)=(?:"([^"]+)"|([^,\s]+))/g;
  let m;
  while ((m = regex.exec(authValue)) !== null) {
    params[m[1]] = m[2] || m[3];
  }
  return params;
}

function calculateDigestResponse(username, password, realm, nonce, method, uri) {
  const ha1 = crypto
    .createHash("md5")
    .update(`${username}:${realm}:${password}`)
    .digest("hex");
  const ha2 = crypto.createHash("md5").update(`${method}:${uri}`).digest("hex");
  return crypto
    .createHash("md5")
    .update(`${ha1}:${nonce}:${ha2}`)
    .digest("hex");
}

// --- State ---
const localIP = getLocalIP();
let socket = null;
let localPort = null;
let cseq = 0;
let fromTag = generateTag();
let callId = generateCallId();
let registered = false;
let lastAuthParams = null; // for re-register and unregister
let registrationInterval = null;
let retryTimeout = null;
let registerTimeout = null;

function setRegisterTimeout() {
  if (registerTimeout) clearTimeout(registerTimeout);
  registerTimeout = setTimeout(() => {
    registerTimeout = null;
    console.error("✗ No response (timeout) — will retry");
    scheduleRetry();
  }, 15000);
}

function clearRegisterTimeout() {
  if (registerTimeout) {
    clearTimeout(registerTimeout);
    registerTimeout = null;
  }
}

// Request-URI and Digest URI (no ;transport=udp — match backend)
const REGISTER_URI = `sip:${config.sipDomain}`;

function buildRegister(withAuth = false, authParams = null, expires = 3600) {
  const branch = generateBranch();
  const tag = withAuth ? generateTag() : fromTag;
  const msg = [
    `REGISTER ${REGISTER_URI} SIP/2.0`,
    `Via: SIP/2.0/UDP ${localIP}:${localPort};rport;branch=z9hG4bK${branch}`,
    `Max-Forwards: 70`,
    `From: <sip:${config.sipUsername}@${config.sipDomain}>;tag=${tag}`,
    `To: <sip:${config.sipUsername}@${config.sipDomain}>`,
    `Call-ID: ${callId}`,
    `CSeq: ${cseq} REGISTER`,
    `Contact: <sip:${config.sipUsername}@${localIP}:${localPort}>;expires=${expires}`,
    `Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE`,
    `Expires: ${expires}`,
    `User-Agent: Yeastar-Compatible/1.0`,
    `Content-Length: 0`,
    ``,
    ``,
  ];

  if (withAuth && authParams && authParams.realm && authParams.nonce) {
    const resp = calculateDigestResponse(
      config.sipUsername,
      config.sipPassword,
      authParams.realm,
      authParams.nonce,
      "REGISTER",
      REGISTER_URI
    );
    const authHeader =
      authParams.is407 ? "Proxy-Authorization" : "Authorization";
    const authLine = `${authHeader}: Digest username="${config.sipUsername}",realm="${authParams.realm}",nonce="${authParams.nonce}",uri="${REGISTER_URI}",response="${resp}"`;
    const idx = msg.findIndex((l) => l.startsWith("Expires:"));
    msg.splice(idx, 0, authLine);
  }

  return msg.join("\r\n");
}

function sendToServer(message) {
  const port = config.sipPort || 5060;
  socket.send(message, port, config.sipDomain, (err) => {
    if (err) console.error("❌ Send error:", err.message);
  });
}

function sendResponse(statusLine, req, rinfo, extraHeaders = []) {
  const via = (req.match(/Via: (.+)/i) || [])[1];
  const from = (req.match(/From: (.+)/i) || [])[1];
  const to = (req.match(/To: ([^\r\n]+)/i) || [])[1];
  const cid = (req.match(/Call-ID: (.+)/i) || [])[1];
  const cseqH = (req.match(/CSeq: (.+)/i) || [])[1];
  if (!via || !from || !to || !cid || !cseqH) return;

  const toTag = to.includes("tag=") ? to.trim() : to.trim() + ";tag=" + generateTag();
  const lines = [
    `SIP/2.0 ${statusLine}`,
    `Via: ${via.trim()}`,
    `From: ${from.trim()}`,
    `To: ${toTag}`,
    `Call-ID: ${cid.trim()}`,
    `CSeq: ${cseqH.trim()}`,
    `User-Agent: Yeastar-Compatible/1.0`,
    ...extraHeaders,
    `Content-Length: 0`,
    ``,
    ``,
  ];
  socket.send(lines.join("\r\n"), rinfo.port, rinfo.address, (err) => {
    if (err) console.error("❌ Response send error:", err.message);
  });
}

function handleMessage(msg, rinfo) {
  const s = msg.toString();
  const first = s.split("\r\n")[0];

  // OPTIONS keepalive → 200 OK (so Yeastar sees us as active)
  if (s.startsWith("OPTIONS ")) {
    console.log("✓ OPTIONS from Yeastar, replying 200 OK");
    sendResponse("200 OK", s, rinfo, ["Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO"]);
    return;
  }

  // 401 / 407 → resend REGISTER with Digest
  if (s.includes("401 Unauthorized") || s.includes("407 Proxy Authentication Required")) {
    clearRegisterTimeout();
    const is407 = s.includes("407");
    const authMatch = s.match(/(?:WWW-Authenticate|Proxy-Authenticate): Digest ([^\r\n]+)/i);
    if (!authMatch) {
      console.error("❌ 401/407 without Digest header");
      scheduleRetry();
      return;
    }
    const authParams = parseAuthParams(authMatch[1]);
    authParams.is407 = is407;
    lastAuthParams = authParams;
    console.log("🔐 401/407 → resending REGISTER with Digest");
    cseq += 1;
    sendToServer(buildRegister(true, authParams, 3600));
    setRegisterTimeout();
    return;
  }

  // 200 OK (REGISTER)
  if (s.includes("200 OK") && s.includes("REGISTER")) {
    clearRegisterTimeout();
    registered = true;
    console.log("✓ Registration successful");
    console.log("✓ Extension " + config.extension + " is now Registered/Active in Yeastar");

    let expires = 3600;
    const exp = s.match(/Expires:\s*(\d+)/i) || s.match(/expires=(\d+)/i);
    if (exp) expires = parseInt(exp[1], 10);

    if (registrationInterval) clearInterval(registrationInterval);
    const ms = Math.floor((expires * 0.9) * 1000);
    console.log("✓ Re-register in " + Math.floor(ms / 1000) + "s");
    registrationInterval = setInterval(doRegister, ms);
    return;
  }

  // 4xx/5xx
  if (s.includes("403") || s.includes("404") || s.includes("480")) {
    clearRegisterTimeout();
    console.error("✗ Registration failed: " + first);
    scheduleRetry();
    return;
  }

  if (s.includes("408") || s.includes("5")) {
    clearRegisterTimeout();
    console.error("✗ " + first + " — will retry");
    scheduleRetry();
    return;
  }

  if (first) console.log("ℹ " + first);
}

function scheduleRetry() {
  if (retryTimeout) return;
  console.log("Will retry in 30s…");
  retryTimeout = setTimeout(() => {
    retryTimeout = null;
    doRegister();
  }, 30000);
}

function doRegister() {
  cseq += 1;
  callId = generateCallId();
  const useAuth = !!(lastAuthParams && lastAuthParams.realm);
  console.log("\n=== Sending REGISTER " + (useAuth ? "(with auth)" : "(initial)") + " ===");
  sendToServer(buildRegister(useAuth, lastAuthParams, 3600));
  setRegisterTimeout();
}

function doUnregister() {
  const hasAuth = !!(lastAuthParams && lastAuthParams.realm);
  sendToServer(buildRegister(hasAuth, lastAuthParams, 0));
}

// --- Main ---
console.log("=== SIP Registration Client (VoiceInfra-style) ===");
console.log("Display Name: " + config.displayName);
console.log("Extension: " + config.extension);
console.log("SIP Domain: " + config.sipDomain);
console.log("SIP Port: " + (config.sipPort || 5060));
console.log("================================\n");

socket = dgram.createSocket("udp4");
const bindPort = config.localPort != null ? config.localPort : 0;

socket.on("message", (msg, rinfo) => handleMessage(msg, rinfo));
socket.on("error", (err) => console.error("❌ Socket error:", err.message));

socket.bind(bindPort, () => {
  localPort = socket.address().port;
  console.log("Listening on " + localIP + ":" + localPort + "\n");
  setTimeout(doRegister, 500);
});

// Shutdown
process.on("SIGINT", () => {
  console.log("\n=== Shutting down ===");
  clearRegisterTimeout();
  if (registrationInterval) clearInterval(registrationInterval);
  if (retryTimeout) clearTimeout(retryTimeout);
  if (registered) {
    console.log("Unregistering…");
    doUnregister();
    setTimeout(() => {
      console.log("Goodbye.");
      process.exit(0);
    }, 2000);
  } else {
    process.exit(0);
  }
});
