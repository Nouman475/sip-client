module.exports = {
  // Extension Configuration (from VoiceInfra form)
  displayName: "dsd",          // Display Name
  extension: "207",             // Extension Number
  sipDomain: "m.sgycm.yeastarcloud.com", // SIP Domain
  sipUsername: "207@mgastech.com",           // SIP Username (email format for Yeastar)
  sipPassword: "475909rmnK",        // SIP Password
  
  // Local Configuration
  localIp: "0.0.0.0",          // Bind to all interfaces
  localPort: 5060,              // SIP port
  
  // Registration Settings
  registerExpires: 3600,        // Registration expiry in seconds (1 hour)
  reRegisterMultiplier: 0.9,   // Re-register at 90% of expiry time
  
  // Optional: Outbound Proxy (if needed)
  // outboundProxy: "192.168.5.150:5060",
};