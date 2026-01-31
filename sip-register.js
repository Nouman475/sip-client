const sip = require("sip");
const crypto = require("crypto");
const net = require("net");
const config = require("./config");

// Utility functions
function generateCallId() {
  return crypto.randomBytes(16).toString("hex");
}

function generateTag() {
  return crypto.randomBytes(8).toString("hex");
}

function generateBranch() {
  return `z9hG4bK${crypto.randomBytes(8).toString("hex")}`;
}

function calculateDigest(
  username,
  realm,
  password,
  method,
  uri,
  nonce,
  qop,
  nc,
  cnonce,
) {
  // Clean the realm and nonce of any quotes
  const cleanRealm = realm.replace(/^["']|["']$/g, "");
  const cleanNonce = nonce.replace(/^["']|["']$/g, "");
  
  console.log(`Digest calculation:`);
  console.log(`  Username: ${username}`);
  console.log(`  Realm: ${cleanRealm}`);
  console.log(`  Method: ${method}`);
  console.log(`  URI: ${uri}`);
  console.log(`  Nonce: ${cleanNonce}`);
  
  const ha1 = crypto
    .createHash("md5")
    .update(`${username}:${cleanRealm}:${password}`)
    .digest("hex");

  const ha2 = crypto.createHash("md5").update(`${method}:${uri}`).digest("hex");

  console.log(`  HA1: ${ha1}`);
  console.log(`  HA2: ${ha2}`);

  let response;
  if (qop && (qop.toLowerCase() === 'auth' || qop.replace(/"/g, '').toLowerCase() === 'auth')) {
    const digestString = `${ha1}:${cleanNonce}:${nc}:${cnonce}:auth:${ha2}`;
    console.log(`  Digest string (with qop): ${digestString}`);
    response = crypto
      .createHash("md5")
      .update(digestString)
      .digest("hex");
  } else {
    const digestString = `${ha1}:${cleanNonce}:${ha2}`;
    console.log(`  Digest string (no qop): ${digestString}`);
    response = crypto
      .createHash("md5")
      .update(digestString)
      .digest("hex");
  }

  console.log(`  Response: ${response}`);
  return response;
}

class SIPClient {
  constructor(config) {
    this.config = config;
    this.callId = generateCallId();
    this.fromTag = generateTag();
    this.toTag = null;
    this.cseq = 1;
    this.registrationInterval = null;
    this.sipStack = null;
    this.registered = false;
    this.viaBranch = generateBranch();
    this.udpSocket = null;
    this.tcpSocket = null;
    this.sipServerAddress = null;
  }

  getLocalIp() {
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

  start() {
    console.log("=== SIP Registration Client ===");
    console.log(`Display Name: ${this.config.displayName}`);
    console.log(`Extension: ${this.config.extension}`);
    console.log(`SIP Domain: ${this.config.sipDomain}`);
    console.log(`SIP Username: ${this.config.sipUsername}`);
    console.log("================================\n");

    // Create TCP socket for raw SIP message sending
    this.tcpSocket = new net.Socket();
    this.tcpSocket.on("error", (err) => {
      console.error("TCP Socket Error:", err);
    });
    this.tcpSocket.on("data", (data) => {
      console.log("=== RECEIVED TCP DATA ===");
      console.log(data.toString());
      console.log("========================\n");
    });

    // Create SIP stack with TCP
    const sipConfig = {
      port: this.config.localPort,
      address: this.config.localIp,
      publicAddress: this.config.localIp,
      hostname: require("os").hostname(),
      tcp: true, // Enable TCP
      logger: {
        send: (message, address) => {
          this.sipServerAddress = address; // Store server address for later use
          console.log("=== SENDING SIP MESSAGE ===");
          console.log(`To: ${address.address}:${address.port}`);
          console.log(message);
          console.log("===========================\n");
        },
        recv: (message, address) => {
          console.log("=== RECEIVED SIP MESSAGE ===");
          console.log(`From: ${address.address}:${address.port}`);
          console.log(message);
          console.log("============================\n");
        },
        error: (error) => {
          console.error("=== SIP ERROR ===");
          console.error(error);
          console.error("=================\n");
        },
      },
    };

    try {
      // sip.start() starts the SIP server and handles incoming requests
      sip.start(sipConfig, (request) => this.handleIncomingRequest(request));

      // The sip module itself is used for sending messages
      this.sipStack = sip;

      console.log(`Local: ${sipConfig.address}:${sipConfig.port}\n`);

      // Start registration after stack is ready
      setTimeout(() => {
        this.register();
      }, 2000);
    } catch (error) {
      console.error("Failed to start SIP stack:", error.message);
      process.exit(1);
    }

    // Handle process termination
    process.on("SIGINT", () => this.shutdown());
    process.on("SIGTERM", () => this.shutdown());
  }

  handleIncomingRequest(request) {
    console.log(`\n=== Incoming ${request.method} ===`);

    if (!this.sipStack) {
      console.error("SIP stack not available to handle incoming request");
      return;
    }

    // Extract to-tag from incoming requests for proper dialog handling
    if (
      request.headers.to &&
      request.headers.to.params &&
      request.headers.to.params.tag
    ) {
      this.toTag = request.headers.to.params.tag;
    }

    switch (request.method) {
      case "OPTIONS":
        // Respond to OPTIONS ping (keepalive)
        this.sipStack.send(
          sip.makeResponse(request, 200, "OK", {
            headers: {
              allow: "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER",
              accept: "application/sdp",
            },
          }),
        );
        console.log("Responded to OPTIONS keepalive");
        break;

      case "NOTIFY":
        // Acknowledge NOTIFY
        this.sipStack.send(sip.makeResponse(request, 200, "OK"));
        console.log("Acknowledged NOTIFY");
        break;

      default:
        console.log(`Unhandled method: ${request.method}`);
    }
  }

  buildSIPMessage(headers, method, uri) {
    let message = `${method} ${uri} SIP/2.0\r\n`;

    // Via header with TCP
    message += `Via: SIP/2.0/TCP ${headers.via[0].host}:${headers.via[0].port};branch=${headers.via[0].params.branch}\r\n`;

    // From header
    message += `From: "${headers.from.name}" <${headers.from.uri}>;tag=${headers.from.params.tag}\r\n`;

    // To header
    message += `To: <${headers.to.uri}>\r\n`;

    // Call-ID
    message += `Call-ID: ${headers["call-id"]}\r\n`;

    // CSeq
    message += `CSeq: ${headers.cseq.seq} ${headers.cseq.method}\r\n`;

    // Max-Forwards
    message += `Max-Forwards: ${headers["max-forwards"]}\r\n`;

    // Contact
    if (headers.contact && headers.contact[0]) {
      message += `Contact: <${headers.contact[0].uri}>;expires=${headers.contact[0].params.expires}\r\n`;
    }

    // Expires
    message += `Expires: ${headers.expires}\r\n`;

    // User-Agent
    message += `User-Agent: ${headers["user-agent"]}\r\n`;

    // Authorization header
    if (headers.authorization && headers.authorization[0]) {
      const auth = headers.authorization[0];

      let authStr = `Authorization: Digest username="${auth.username}", realm="${auth.realm}", nonce="${auth.nonce}", uri="${auth.uri}", response="${auth.response}", algorithm=${auth.algorithm}`;

      if (auth.opaque) authStr += `, opaque="${auth.opaque}"`;
      if (auth.qop) {
        authStr += `, qop=${auth.qop}, nc=${auth.nc}, cnonce="${auth.cnonce}"`;
      }

      message += authStr + "\r\n";
    }

    // Content-Length
    message += `Content-Length: 0\r\n`;
    message += `\r\n`;

    return message;
  }

  register(withAuth = false, authParams = null) {
    if (!this.sipStack) {
      console.error("SIP stack not initialized. Cannot register.");
      return;
    }

    const uri = `sip:${this.config.sipDomain}`;
    const fromUri = `sip:${this.config.sipUsername}@${this.config.sipDomain}`;
    const toUri = `sip:${this.config.sipUsername}@${this.config.sipDomain}`;

    // Use local IP and port from config
    const localIp =
      this.config.localIp === "0.0.0.0"
        ? this.getLocalIp()
        : this.config.localIp;
    const contactUri = `sip:${this.config.sipUsername}@${localIp}:${this.config.localPort}`;

    // Build Via header with TCP
    const viaHeader = {
      version: "2.0",
      protocol: "TCP",
      host: localIp,
      port: this.config.localPort,
      params: {
        branch: this.viaBranch,
        rport: true,
      },
    };

    const headers = {
      to: { uri: toUri },
      from: {
        uri: fromUri,
        params: { tag: this.fromTag },
        name: this.config.displayName,
      },
      "call-id": this.callId,
      cseq: { method: "REGISTER", seq: this.cseq },
      via: [viaHeader],
      "max-forwards": 70,
      contact: [
        {
          uri: contactUri,
          params: { expires: this.config.registerExpires },
        },
      ],
      expires: this.config.registerExpires,
      "user-agent": "Node.js SIP Client v1.0",
    };

    // Add authentication if we received a challenge
    if (withAuth && authParams) {
      const nc = "00000001";
      const cnonce = generateTag();
      const qop = authParams.qop || null;
      console.log(`QOP raw value: "${qop}"`);
      console.log(`QOP cleaned: "${qop ? qop.replace(/"/g, '') : 'null'}"`);

      const response = calculateDigest(
        this.config.sipUsername,
        authParams.realm,
        this.config.sipPassword,
        "REGISTER",
        uri,
        authParams.nonce,
        qop,
        nc,
        cnonce,
      );

      const authHeader = {
        scheme: "Digest",
        username: this.config.sipUsername,
        realm: authParams.realm.replace(/^["']|["']$/g, ""), // Clean quotes
        nonce: authParams.nonce.replace(/^["']|["']$/g, ""), // Clean quotes
        uri: uri,
        response: response,
        algorithm: "MD5", // Always use uppercase MD5
      };

      if (qop && (qop.toLowerCase() === 'auth' || qop.replace(/"/g, '').toLowerCase() === 'auth')) {
        authHeader.qop = "auth";
        authHeader.nc = nc;
        authHeader.cnonce = cnonce;
      }

      if (authParams.opaque) {
        authHeader.opaque = authParams.opaque.replace(/^["']|["']$/g, ""); // Clean quotes
      }

      headers.authorization = [authHeader];

      // Use TCP for authenticated request
      console.log(`\n=== Sending REGISTER (with auth) ===`);
      console.log(`To: ${this.config.sipUsername}@${this.config.sipDomain}`);
      console.log(`Via: ${localIp}:${this.config.localPort} (TCP)`);

      const message = this.buildSIPMessage(headers, "REGISTER", uri);
      console.log("=== SENDING SIP MESSAGE ===");
      console.log(
        `Raw TCP message to ${this.sipServerAddress.address}:${this.sipServerAddress.port}`,
      );
      console.log(message);
      console.log("===========================\n");

      // Connect and send via TCP
      if (!this.tcpSocket.connecting && !this.tcpSocket.readyState) {
        this.tcpSocket.connect(this.sipServerAddress.port, this.sipServerAddress.address, () => {
          console.log("TCP connection established");
          this.tcpSocket.write(message);
        });
      } else {
        this.tcpSocket.write(message);
      }

      this.cseq++;
      return;
    }

    const request = {
      method: "REGISTER",
      uri: uri,
      version: "2.0",
      headers: headers,
    };

    console.log(`\n=== Sending REGISTER (initial) ===`);
    console.log(`To: ${this.config.sipUsername}@${this.config.sipDomain}`);
    console.log(`Via: ${localIp}:${this.config.localPort} (TCP)`);

    this.sipStack.send(request, (response) => {
      this.handleRegisterResponse(response, authParams);
    });

    // Increment CSeq for next request
    this.cseq++;
  }

  handleRegisterResponse(response, previousAuthParams) {
    console.log(`\n=== Response: ${response.status} ${response.reason} ===`);

    // Extract to-tag from response if present
    if (
      response.headers.to &&
      response.headers.to.params &&
      response.headers.to.params.tag
    ) {
      this.toTag = response.headers.to.params.tag;
    }

    if (response.status === 401 || response.status === 407) {
      // Authentication required
      console.log("Authentication challenge received");

      const wwwAuth =
        response.headers["www-authenticate"] ||
        response.headers["proxy-authenticate"];

      if (wwwAuth && wwwAuth[0]) {
        // wwwAuth is an array, get the first element
        const authChallenge = wwwAuth[0];
        console.log("Raw auth challenge:", authChallenge);
        
        const authParams = {
          realm: authChallenge.realm,
          nonce: authChallenge.nonce,
          algorithm: authChallenge.algorithm || "MD5",
          qop: authChallenge.qop,
          opaque: authChallenge.opaque,
        };

        console.log("Parsed auth params:");
        console.log("  Realm:", authParams.realm);
        console.log("  Nonce:", authParams.nonce);
        console.log("  Algorithm:", authParams.algorithm);
        console.log("  QOP:", authParams.qop);
        console.log("  Opaque:", authParams.opaque);
        console.log("Re-sending with credentials...");

        // Shorter delay for authenticated request since we're using raw UDP now
        setTimeout(() => {
          this.register(true, authParams);
        }, 200);
      } else {
        console.error("No authentication challenge found in response");
        console.log("www-authenticate header:", wwwAuth);
      }
    } else if (response.status === 200) {
      // Registration successful
      this.registered = true;
      console.log("✓ Registration successful!");
      console.log(`✓ Extension ${this.config.extension} is now registered`);

      // Parse expires from response
      let expires = this.config.registerExpires;
      if (response.headers.contact && response.headers.contact[0]) {
        const contactExpires = response.headers.contact[0].params?.expires;
        if (contactExpires) {
          expires = parseInt(contactExpires);
        }
      } else if (response.headers.expires) {
        expires = parseInt(response.headers.expires);
      }

      console.log(`✓ Registration expires in ${expires} seconds`);

      // Set up re-registration before expiry
      if (this.registrationInterval) {
        clearInterval(this.registrationInterval);
      }

      const reregisterTime = expires * this.config.reRegisterMultiplier * 1000;
      console.log(
        `✓ Will re-register in ${Math.floor(reregisterTime / 1000)} seconds`,
      );
      console.log("\n>>> SIP Extension is ready and registered! <<<\n");

      this.registrationInterval = setInterval(() => {
        console.log("\n--- Refreshing registration ---");
        this.register();
      }, reregisterTime);
    } else if (response.status >= 400) {
      console.error(
        `✗ Registration failed: ${response.status} ${response.reason}`,
      );

      if (response.headers["warning"]) {
        console.error("Warning:", response.headers["warning"]);
      }

      // Common error codes
      switch (response.status) {
        case 403:
          console.error("Reason: Forbidden - Check your credentials");
          break;
        case 404:
          console.error("Reason: Not Found - Extension may not exist");
          break;
        case 408:
          console.error(
            "Reason: Request Timeout - Check network connectivity or server load",
          );
          break;
        case 423:
          console.error(
            "Reason: Interval Too Brief - Registration expires too soon",
          );
          break;
        case 480:
          console.error("Reason: Temporarily Unavailable - PBX may be busy");
          break;
        case 486:
          console.error("Reason: Busy Here");
          break;
        case 503:
          console.error("Reason: Service Unavailable - PBX may be down");
          break;
      }

      // Retry after delay for temporary errors
      if (response.status >= 500 || response.status === 408) {
        console.log("Will retry in 30 seconds...");
        setTimeout(() => this.register(), 30000);
      }
    } else {
      console.log(`Unexpected response: ${response.status} ${response.reason}`);
    }
  }

  shutdown() {
    console.log("\n\n=== Shutting down ===");

    if (this.registrationInterval) {
      clearInterval(this.registrationInterval);
    }

    if (this.tcpSocket) {
      this.tcpSocket.destroy();
    }

    if (this.registered && this.sipStack) {
      console.log("Unregistering extension...");

      // Send unregister (expires: 0)
      const uri = `sip:${this.config.sipDomain}`;
      const fromUri = `sip:${this.config.sipUsername}@${this.config.sipDomain}`;
      const toUri = `sip:${this.config.sipUsername}@${this.config.sipDomain}`;
      const localIp =
        this.config.localIp === "0.0.0.0"
          ? this.getLocalIp()
          : this.config.localIp;
      const contactUri = `sip:${this.config.sipUsername}@${localIp}:${this.config.localPort}`;

      this.sipStack.send(
        {
          method: "REGISTER",
          uri: uri,
          headers: {
            to: { uri: toUri },
            from: { uri: fromUri, params: { tag: this.fromTag } },
            "call-id": this.callId,
            cseq: { method: "REGISTER", seq: this.cseq++ },
            contact: [{ uri: contactUri, params: { expires: 0 } }],
            expires: 0,
          },
        },
        (response) => {
          if (response.status === 200) {
            console.log("✓ Unregistered successfully");
          }
          console.log("Goodbye!");
          process.exit(0);
        },
      );

      setTimeout(() => {
        console.log("Timeout waiting for unregister. Exiting...");
        process.exit(0);
      }, 3000);
    } else {
      console.log("Not registered or SIP stack unavailable. Exiting...");
      process.exit(0);
    }
  }
}

// Create and start the client
const client = new SIPClient(config);
client.start();
