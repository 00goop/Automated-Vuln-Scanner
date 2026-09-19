import axios from 'axios';
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';
axios.defaults.timeout = 20000;

// API client
export const api = {
  getHealth: () => axios.get(`${API_BASE}/health`),
  getSecurityScore: () => axios.get(`${API_BASE}/security-score`),
  getVulnerabilities: (params) => axios.get(`${API_BASE}/vulnerabilities`, { params }),
  chat: (message, context) => axios.post(`${API_BASE}/chat`, { message, context }),
  analyzeCode: (code, filename) => axios.post(`${API_BASE}/analyze/code`, { code, filename }),
  decode: (text, encoding) => axios.post(`${API_BASE}/crypto/decode`, { text, encoding }),
  encode: (text, encoding) => axios.post(`${API_BASE}/crypto/encode`, { text, encoding }),
  identifyHash: (hash) => axios.post(`${API_BASE}/crypto/identify-hash`, `hash_string=${encodeURIComponent(hash)}`, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }),
  domainLookup: (domain) => axios.get(`${API_BASE}/osint/domain/${domain}`),
  ipLookup: (ip) => axios.get(`${API_BASE}/osint/ip/${ip}`),
  usernameSearch: (username) => axios.get(`${API_BASE}/osint/username/${username}`),
};

