const sip = require("sip");
const crypto = require("crypto");

// Render environment or fallback config
const config = {
  displayName: process.env.DISPLAY_NAME || "dsd",
  extension: process.env.EXTENSION || "207",
  sipDomain: process.env.SIP_DOMAIN || "m.sgycm.yeastarcloud.com",
  sipUsername: process.env.SIP_USERNAME || "207",
  sipPassword: process.env.SIP_PASSWORD || "Smart@0500",
  localIp: "0.0.0.0",
  localPort: process.env.PORT || 5060, // Render assigns PORT
  registerExpires: 3600,
  reRegisterMultiplier: 0.9,
};

console.log("=== SIP Client on Render ===");
console.log(`Extension: ${config.extension}`);
console.log(`Domain: ${config.sipDomain}`);
console.log(`Port: ${config.localPort}`);
console.log("============================\n");

// Utility functions
function generateCallId() {
  return crypto.randomBytes(16).toString("hex");
}

function generateTag() {
  return crypto.randomBytes(8).toString("hex");
}

function getLocalIp() {
  const os = require("os");
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

const callId = generateCallId();
const fromTag = generateTag();
let cseq = 1;

// Start SIP stack
const sipConfig = {
  port: config.localPort,
  address: config.localIp,
  logger: {
    send: (message, address) => {
      console.log(`>>> SEND to ${address.address}:${address.port} >>>`);
      console.log(message);
      console.log(">>> END SEND >>>\n");
    },
    recv: (message, address) => {
      console.log(`<<< RECV from ${address.address}:${address.port} <<<`);
      console.log(message);
      console.log("<<< END RECV <<<\n");
    },
    error: (error) => {
      console.error("SIP ERROR:", error);
    }
  }
};

try {
  sip.start(sipConfig, (request) => {
    console.log(`Incoming ${request.method} request`);
    
    // Respond to OPTIONS (keepalive)
    if (request.method === "OPTIONS") {
      sip.send(sip.makeResponse(request, 200, "OK", {
        headers: {
          allow: "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER",
          accept: "application/sdp",
        },
      }));
    }
  });

  console.log(`SIP server started on ${config.localIp}:${config.localPort}`);
  
  // Send REGISTER
  setTimeout(() => {
    const localIp = getLocalIp();
    const request = {
      method: "REGISTER",
      uri: `sip:${config.sipDomain}`,
      version: "2.0",
      headers: {
        to: { uri: `sip:${config.sipUsername}@${config.sipDomain}` },
        from: { 
          uri: `sip:${config.sipUsername}@${config.sipDomain}`,
          params: { tag: fromTag }
        },
        "call-id": callId,
        cseq: { method: "REGISTER", seq: cseq++ },
        via: [{
          version: "2.0",
          protocol: "UDP",
          host: localIp,
          port: config.localPort,
          params: { branch: `z9hG4bK${generateTag()}` }
        }],
        "max-forwards": 70,
        contact: [{ 
          uri: `sip:${config.sipUsername}@${localIp}:${config.localPort}`,
          params: { expires: config.registerExpires }
        }],
        expires: config.registerExpires,
        "user-agent": "Render SIP Client v1.0"
      }
    };

    console.log("Sending REGISTER request...");
    sip.send(request, (response) => {
      console.log(`Response: ${response.status} ${response.reason}`);
      
      if (response.status === 401 || response.status === 407) {
        console.log("✓ Auth challenge received - server is reachable!");
      } else if (response.status === 200) {
        console.log("✓ Registration successful!");
      } else {
        console.log(`Server response: ${response.status} ${response.reason}`);
      }
    });
  }, 2000);

  // Keep alive
  setInterval(() => {
    console.log("SIP client running...");
  }, 30000);

} catch (error) {
  console.error("Failed to start SIP client:", error);
  process.exit(1);
}

// Handle shutdown
process.on("SIGINT", () => {
  console.log("Shutting down...");
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("Shutting down...");
  process.exit(0);
});