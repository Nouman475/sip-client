module.exports = {
  // Extension Configuration
  displayName: "dsd",
  extension: "207",
  sipDomain: "m.sgycm.yeastarcloud.com",
  sipUsername: "207",
  sipPassword: "475909rmnK",
  
  // Local Configuration
  localIp: "0.0.0.0",
  localPort: 5070, // Changed from 5060 to avoid EADDRINUSE
  
  // Registration Settings
  registerExpires: 3600,
  reRegisterMultiplier: 0.9,
};