const sip = require("sip");
const crypto = require("crypto");
const config = require("./config");

// Utility functions
function generateCallId() {
  return crypto.randomBytes(16).toString("hex");
}

function generateTag() {
  return crypto.randomBytes(8).toString("hex");
}

function calculateDigest(user, realm, pass, method, uri, nonce, qop, nc, cnonce) {
  const cleanRealm = realm.replace(/^["']|["']$/g, "");
  const cleanNonce = nonce.replace(/^["']|["']$/g, "");
  
  const ha1 = crypto.createHash("md5").update(`${user}:${cleanRealm}:${pass}`).digest("hex");
  const ha2 = crypto.createHash("md5").update(`${method}:${uri}`).digest("hex");

  if (qop && qop.replace(/"/g, '').toLowerCase() === 'auth') {
    return crypto.createHash("md5")
      .update(`${ha1}:${cleanNonce}:${nc}:${cnonce}:auth:${ha2}`)
      .digest("hex");
  }
  return crypto.createHash("md5").update(`${ha1}:${cleanNonce}:${ha2}`).digest("hex");
}

class SIPClient {
  constructor(config) {
    this.config = config;
    this.callId = generateCallId();
    this.fromTag = generateTag();
    this.cseq = 1;
    this.registrationInterval = null;
    this.registered = false;
  }

  getLocalIp() {
    const os = require("os");
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === "IPv4" && !iface.internal) return iface.address;
      }
    }
    return "127.0.0.1";
  }

  start() {
    console.log("=== SIP Registration Client ===");
    console.log(`Extension: ${this.config.extension} @ ${this.config.sipDomain}`);

    const sipConfig = {
      port: this.config.localPort,
      address: this.config.localIp,
      publicAddress: this.config.publicAddress,
      logger: {
        send: (msg, address) => console.log(`>>> Sending to ${address.address}:${address.port}`),
        recv: (msg, address) => console.log(`<<< Received from ${address.address}:${address.port}`),
        error: (err) => console.error("!!! SIP Stack Error:", err)
      },
    };

    try {
      // Start the SIP stack
      sip.start(sipConfig, (request) => this.handleIncomingRequest(request));
      console.log(`Local stack listening on: ${sipConfig.address}:${sipConfig.port}\n`);

      // Initial Register
      this.register();
    } catch (error) {
      console.error("Failed to start SIP stack:", error.message);
      process.exit(1);
    }

    process.on("SIGINT", () => this.shutdown());
  }

  register(authPacket = null) {
    const uri = `sip:${this.config.sipDomain}`;
    // const localIp = this.config.localIp === "0.0.0.0" ? this.getLocalIp() : this.config.localIp;
    const localIp = this.config.publicAddress
    
    const request = {
      method: "REGISTER",
      uri: uri,
      headers: {
        to: { uri: `sip:${this.config.sipUsername}@${this.config.sipDomain}` },
        from: { 
          uri: `sip:${this.config.sipUsername}@${this.config.sipDomain}`, 
          params: { tag: this.fromTag },
          name: this.config.displayName 
        },
        "call-id": this.callId,
        cseq: { method: "REGISTER", seq: this.cseq++ },
        via: [],
        contact: [{ uri: `sip:${this.config.sipUsername}@${this.config.publicAddress}:${this.config.localPort}` }],
        expires: this.config.registerExpires,
        "max-forwards": 70,
        "user-agent": "NodeJS-SIP-Client"
      },
    };

    if (authPacket) {
      const nc = "00000001";
      const cnonce = generateTag();
      const response = calculateDigest(
        this.config.sipUsername,
        authPacket.realm,
        this.config.sipPassword,
        "REGISTER",
        uri,
        authPacket.nonce,
        authPacket.qop,
        nc,
        cnonce
      );

      const authHeader = {
        scheme: "Digest",
        username: this.config.sipUsername,
        realm: authPacket.realm.replace(/"/g, ''),
        nonce: authPacket.nonce.replace(/"/g, ''),
        uri: uri,
        response: response,
        algorithm: "MD5"
      };

      if (authPacket.qop) {
        authHeader.qop = "auth";
        authHeader.nc = nc;
        authHeader.cnonce = cnonce;
      }
      
      request.headers.authorization = [authHeader];
    }

    sip.send(request, (response) => {
      this.handleResponse(response);
    });
  }

  handleResponse(response) {
    if (response.status === 401 || response.status === 407) {
      const challenge = response.headers["www-authenticate"] || response.headers["proxy-authenticate"];
      if (challenge) {
        console.log("Received Auth Challenge. Retrying with credentials...");
        this.register(challenge[0]);
      }
    } else if (response.status === 200) {
      this.registered = true;
      console.log("✓ Registration Successful!");
      
      // Schedule re-registration
      const expires = response.headers.expires || (response.headers.contact && response.headers.contact[0].params.expires) || this.config.registerExpires;
      const interval = expires * this.config.reRegisterMultiplier * 1000;
      
      if (this.registrationInterval) clearInterval(this.registrationInterval);
      this.registrationInterval = setInterval(() => this.register(), interval);
    } else {
      console.log(`! Response: ${response.status} ${response.reason}`);
    }
  }

  handleIncomingRequest(request) {
    if (request.method === "OPTIONS") {
      sip.send(sip.makeResponse(request, 200, "OK"));
    }
  }

  shutdown() {
    console.log("\nUnregistering and exiting...");
    // To unregister, we send REGISTER with expires: 0
    this.config.registerExpires = 0;
    this.register();
    setTimeout(() => process.exit(0), 1000);
  }
}

const client = new SIPClient(config);
client.start();