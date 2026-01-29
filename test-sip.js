const sip = require("sip");
const config = require("./config");

console.log("=== Testing SIP Connection (TCP) ===");
console.log(`Target: ${config.sipDomain}`);
console.log(`Extension: ${config.extension}`);
console.log("====================================\n");

// Simple SIP test with TCP
const sipConfig = {
  port: 5061, // Use different port to avoid conflicts
  address: "0.0.0.0",
  tcp: true, // Force TCP instead of UDP
  logger: {
    send: (message, address) => {
      console.log(">>> SENDING >>>");
      console.log(`To: ${address.address}:${address.port} (TCP)`);
      console.log(message);
      console.log(">>> END SEND >>>\n");
    },
    recv: (message, address) => {
      console.log("<<< RECEIVED <<<");
      console.log(`From: ${address.address}:${address.port} (TCP)`);
      console.log(message);
      console.log("<<< END RECV <<<\n");
    },
    error: (error) => {
      console.error("!!! ERROR !!!");
      console.error(error);
      console.error("!!! END ERROR !!!\n");
    }
  }
};

try {
  sip.start(sipConfig, (request) => {
    console.log(`Incoming ${request.method} request`);
  });

  console.log("SIP stack started successfully (TCP mode)");
  console.log("Sending test REGISTER...\n");

  // Send a simple REGISTER request
  setTimeout(() => {
    const request = {
      method: "REGISTER",
      uri: `sip:${config.sipDomain}`,
      version: "2.0",
      headers: {
        to: { uri: `sip:${config.sipUsername}@${config.sipDomain}` },
        from: { 
          uri: `sip:${config.sipUsername}@${config.sipDomain}`,
          params: { tag: "test123" }
        },
        "call-id": "test-call-id-123",
        cseq: { method: "REGISTER", seq: 1 },
        via: [{
          version: "2.0",
          protocol: "TCP", // Use TCP
          host: "127.0.0.1",
          port: 5061,
          params: { branch: "z9hG4bKtest123" }
        }],
        "max-forwards": 70,
        contact: [{ uri: `sip:${config.sipUsername}@127.0.0.1:5061;transport=tcp` }],
        expires: 3600,
        "user-agent": "SIP Test Client TCP"
      }
    };

    sip.send(request, (response) => {
      console.log(`\n=== RESPONSE RECEIVED ===`);
      console.log(`Status: ${response.status} ${response.reason}`);
      console.log("Response headers:", JSON.stringify(response.headers, null, 2));
      console.log("=========================\n");
      
      if (response.status === 401 || response.status === 407) {
        console.log("✅ Server responded with auth challenge - TCP connection works!");
      } else if (response.status === 200) {
        console.log("✅ Registration successful!");
      } else {
        console.log(`Server responded with: ${response.status} ${response.reason}`);
      }
      
      process.exit(0);
    });

  }, 1000);

  // Timeout after 15 seconds
  setTimeout(() => {
    console.log("❌ Test timed out - no response from server");
    console.log("This confirms UDP/TCP SIP traffic is blocked on your network");
    console.log("💡 Try deploying to Render - cloud servers usually have better connectivity");
    process.exit(1);
  }, 15000);

} catch (error) {
  console.error("Failed to start SIP test:", error);
  process.exit(1);
}