module.exports = {
  // Extension Configuration (from VoiceInfra form)
  displayName: "dsd",          // Display Name
  extension: "207",             // Extension Number
  sipDomain: "m.sgycm.yeastarcloud.com", // SIP Domain
  sipUsername: "207",           // SIP Username (usually same as extension)
  sipPassword: "Smart@0500",    // SIP Password
  
  // Local Configuration
  localIp: "0.0.0.0",          // Bind to all interfaces
  localPort: 5060,              // SIP port
  
  // Registration Settings
  registerExpires: 3600,        // Registration expiry in seconds (1 hour)
  reRegisterMultiplier: 0.9,   // Re-register at 90% of expiry time
  
  // Optional: Outbound Proxy (if needed)
  // outboundProxy: "192.168.5.150:5060",
};