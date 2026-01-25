import { useState, useEffect } from 'react';
import {
  Shield, Home, AlertTriangle, FileText, Settings,
  MessageCircle, Send, TrendingUp, RefreshCw, X,
  ChevronRight, Clock, Zap, Code, Lock, Search,
  Upload, Hash, Globe, User, Terminal
} from 'lucide-react';
import axios from 'axios';
import './index.css';

const API_BASE = 'http://localhost:8000/api';

// API client
const api = {
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

// Sidebar Navigation
function Sidebar({ activeView, setActiveView, criticalCount }) {
  const navItems = [
    { id: 'dashboard', icon: Home, label: 'Dashboard' },
    { id: 'vulnerabilities', icon: AlertTriangle, label: 'Vulnerabilities', badge: criticalCount },
    { id: 'code-analysis', icon: Code, label: 'Code Grader' },
    { id: 'crypto', icon: Lock, label: 'Crypto Tools' },
    { id: 'osint', icon: Search, label: 'OSINT' },
    { id: 'settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Terminal size={24} color="white" />
        </div>
        <div>
          <div className="brand-name">MR-ROBOT</div>
          <div className="brand-tagline">Security Toolkit</div>
        </div>
      </div>

      <nav className="nav-section">
        <div className="nav-label">Modules</div>
        {navItems.map(item => (
          <button
            key={item.id}
            className={`nav-item ${activeView === item.id ? 'active' : ''}`}
            onClick={() => setActiveView(item.id)}
          >
            <item.icon size={20} />
            <span>{item.label}</span>
            {item.badge > 0 && (
              <span className="nav-item-badge">{item.badge}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="sync-status">
        <div className="sync-dot" />
        <span>MR-ROBOT v2.0</span>
      </div>
    </aside>
  );
}

// Security Score Hero
function SecurityScoreHero({ score }) {
  return (
    <div className="security-score-hero">
      <div className="security-score-value">{score?.score || '--'}</div>
      <div className="security-score-label">
        Security Score • {score?.label || 'Loading...'}
      </div>
      {score?.score > 0 && (
        <div className="security-score-trend">
          <TrendingUp size={16} />
          Keep improving by fixing high-priority items
        </div>
      )}
    </div>
  );
}

// Priority Breakdown Grid
function PriorityBreakdown({ breakdown }) {
  const items = [
    { key: 'critical', label: 'Critical', color: 'critical' },
    { key: 'high', label: 'High', color: 'high' },
    { key: 'moderate', label: 'Moderate', color: 'moderate' },
    { key: 'low', label: 'Low', color: 'low' },
  ];

  return (
    <div className="priority-grid">
      {items.map(item => (
        <div key={item.key} className={`priority-card ${item.color}`}>
          <div className="priority-card-count">
            {breakdown?.[item.key] || 0}
          </div>
          <div className="priority-card-label">{item.label}</div>
        </div>
      ))}
    </div>
  );
}

// Code Analysis View
function CodeAnalysisView() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeCode = async () => {
    if (!code.trim()) return;
    setLoading(true);
    try {
      const res = await api.analyzeCode(code, 'code.py');
      setResult(res.data);
    } catch (err) {
      setResult({ success: false, error: 'Analysis failed' });
    }
    setLoading(false);
  };

  return (
    <section className="fix-first-section">
      <div className="section-header">
        <div>
          <h2 className="section-title">🔍 Code Security Grader</h2>
          <p className="section-subtitle">Paste your code to get a security grade (A-F)</p>
        </div>
      </div>

      <div className="code-analyzer">
        <textarea
          className="code-input"
          placeholder="Paste your Python code here..."
          value={code}
          onChange={(e) => setCode(e.target.value)}
          rows={12}
        />
        <button
          className="btn btn-primary"
          onClick={analyzeCode}
          disabled={loading}
          style={{ marginTop: '16px' }}
        >
          {loading ? 'Analyzing...' : '🔬 Analyze Code'}
        </button>

        {result && (
          <div className="analysis-result" style={{ marginTop: '24px' }}>
            {result.success ? (
              <>
                <div className="grade-display" style={{
                  background: result.grade_color + '20',
                  borderLeft: `4px solid ${result.grade_color}`,
                  padding: '20px',
                  borderRadius: '12px',
                  marginBottom: '16px'
                }}>
                  <div style={{ fontSize: '3rem', fontWeight: 'bold', color: result.grade_color }}>
                    {result.grade}
                  </div>
                  <div style={{ color: '#94a3b8' }}>{result.grade_label}</div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
                  <div className="priority-card critical">
                    <div className="priority-card-count">{result.summary.high_severity}</div>
                    <div className="priority-card-label">High</div>
                  </div>
                  <div className="priority-card high">
                    <div className="priority-card-count">{result.summary.medium_severity}</div>
                    <div className="priority-card-label">Medium</div>
                  </div>
                  <div className="priority-card low">
                    <div className="priority-card-count">{result.summary.low_severity}</div>
                    <div className="priority-card-label">Low</div>
                  </div>
                </div>

                {result.findings?.length > 0 && (
                  <div className="vuln-list">
                    <h3 style={{ marginBottom: '12px', color: '#f8fafc' }}>Findings</h3>
                    {result.findings.slice(0, 5).map((f, i) => (
                      <div key={i} className="vuln-card">
                        <div className={`vuln-priority-badge ${f.severity}`}>
                          {f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : '🟡'}
                        </div>
                        <div className="vuln-content">
                          <div className="vuln-header">
                            <span className="vuln-id">Line {f.line_number}</span>
                            <span className={`vuln-priority-label ${f.severity}`}>{f.severity}</span>
                          </div>
                          <p className="vuln-description">{f.title}</p>
                          {f.code_snippet && (
                            <code style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{f.code_snippet}</code>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <div style={{ color: '#f87171' }}>Error: {result.error}</div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

// Crypto Tools View
function CryptoToolsView() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [encoding, setEncoding] = useState('base64');
  const [mode, setMode] = useState('decode');

  const encodings = ['base64', 'hex', 'url', 'rot13', 'binary', 'reverse', 'atbash'];

  const process = async () => {
    if (!input.trim()) return;
    try {
      const res = mode === 'decode'
        ? await api.decode(input, encoding)
        : await api.encode(input, encoding);
      setOutput(res.data.success ? res.data.output : `Error: ${res.data.error}`);
    } catch (err) {
      setOutput('Error processing request');
    }
  };

  return (
    <section className="fix-first-section">
      <div className="section-header">
        <div>
          <h2 className="section-title">🔐 Crypto Tools</h2>
          <p className="section-subtitle">Encode, decode, and analyze data</p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <button
          className={`btn ${mode === 'decode' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setMode('decode')}
        >
          Decode
        </button>
        <button
          className={`btn ${mode === 'encode' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setMode('encode')}
        >
          Encode
        </button>
        <select
          value={encoding}
          onChange={(e) => setEncoding(e.target.value)}
          style={{
            background: '#1e293b',
            color: '#f8fafc',
            border: '1px solid rgba(255,255,255,0.2)',
            borderRadius: '8px',
            padding: '8px 12px'
          }}
        >
          {encodings.map(e => (
            <option key={e} value={e}>{e.toUpperCase()}</option>
          ))}
        </select>
      </div>

      <textarea
        className="code-input"
        placeholder={`Enter text to ${mode}...`}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        rows={4}
      />

      <button className="btn btn-primary" onClick={process} style={{ margin: '16px 0' }}>
        {mode === 'decode' ? '🔓 Decode' : '🔒 Encode'}
      </button>

      {output && (
        <div style={{ marginTop: '16px' }}>
          <label style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Output:</label>
          <textarea
            className="code-input"
            value={output}
            readOnly
            rows={4}
            style={{ marginTop: '8px' }}
          />
        </div>
      )}
    </section>
  );
}

// OSINT View
function OsintView() {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState('domain');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setResult(null);

    try {
      let res;
      if (searchType === 'domain') {
        res = await api.domainLookup(query);
      } else if (searchType === 'ip') {
        res = await api.ipLookup(query);
      } else {
        res = await api.usernameSearch(query);
      }
      setResult(res.data);
    } catch (err) {
      setResult({ success: false, error: 'Search failed' });
    }
    setLoading(false);
  };

  return (
    <section className="fix-first-section">
      <div className="section-header">
        <div>
          <h2 className="section-title">🔎 OSINT Search</h2>
          <p className="section-subtitle">Domain, IP, and username reconnaissance</p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {[
          { id: 'domain', icon: Globe, label: 'Domain' },
          { id: 'ip', icon: Globe, label: 'IP' },
          { id: 'username', icon: User, label: 'Username' }
        ].map(t => (
          <button
            key={t.id}
            className={`btn ${searchType === t.id ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setSearchType(t.id)}
          >
            <t.icon size={16} />
            {t.label}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', gap: '8px' }}>
        <input
          className="chat-input"
          style={{ flex: 1 }}
          placeholder={`Enter ${searchType}...`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && search()}
        />
        <button className="btn btn-primary" onClick={search} disabled={loading}>
          {loading ? '...' : '🔍 Search'}
        </button>
      </div>

      {result && (
        <div style={{ marginTop: '24px', background: '#0f172a', borderRadius: '12px', padding: '16px' }}>
          {result.success !== false ? (
            <pre style={{
              color: '#94a3b8',
              fontSize: '0.85rem',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word'
            }}>
              {JSON.stringify(result, null, 2)}
            </pre>
          ) : (
            <div style={{ color: '#f87171' }}>Error: {result.error}</div>
          )}
        </div>
      )}
    </section>
  );
}

// Dashboard View with quick access cards
function DashboardView({ securityScore, setActiveView }) {
  const quickActions = [
    { id: 'code-analysis', icon: Code, title: 'Code Grader', desc: 'Upload & analyze code', color: '#8b5cf6' },
    { id: 'crypto', icon: Lock, title: 'Crypto Tools', desc: 'Encode, decode, hash', color: '#06b6d4' },
    { id: 'osint', icon: Search, title: 'OSINT', desc: 'Domain & user recon', color: '#f97316' },
    { id: 'vulnerabilities', icon: AlertTriangle, title: 'Vulnerabilities', desc: 'CVE prioritization', color: '#ef4444' },
  ];

  return (
    <>
      <SecurityScoreHero score={securityScore} />
      <PriorityBreakdown breakdown={securityScore?.breakdown} />

      <section className="fix-first-section">
        <div className="section-header">
          <h2 className="section-title">🛠️ Security Toolkit</h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          {quickActions.map(action => (
            <div
              key={action.id}
              className="priority-card"
              style={{ borderLeftColor: action.color, cursor: 'pointer' }}
              onClick={() => setActiveView(action.id)}
            >
              <action.icon size={32} color={action.color} style={{ marginBottom: '8px' }} />
              <div className="priority-card-count" style={{ fontSize: '1.2rem' }}>{action.title}</div>
              <div className="priority-card-label">{action.desc}</div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

// Chat Panel
function ChatPanel({ isOpen, onClose }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: "I'm MR-ROBOT's AI assistant. How can I help with security today?" }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const sendMessage = async (text) => {
    if (!text.trim()) return;
    setMessages(prev => [...prev, { role: 'user', content: text }]);
    setInput('');
    setLoading(true);

    try {
      const res = await api.chat(text, {});
      setMessages(prev => [...prev, { role: 'assistant', content: res.data.response }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Connection error. Is the backend running?' }]);
    }
    setLoading(false);
  };

  if (!isOpen) return null;

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div className="chat-header-icon"><Terminal size={20} color="white" /></div>
        <div>
          <div className="chat-header-title">MR-ROBOT AI</div>
          <div className="chat-header-status">● Online</div>
        </div>
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
          <X size={20} />
        </button>
      </div>

      <div className="chat-messages">
        {messages.map((msg, i) => (
          <div key={i} className={`chat-message ${msg.role}`}>{msg.content}</div>
        ))}
        {loading && <div className="chat-message assistant" style={{ opacity: 0.5 }}>Thinking...</div>}
      </div>

      <div className="chat-input-container">
        <input
          className="chat-input"
          placeholder="Ask me anything..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessage(input)}
        />
        <button className="chat-send" onClick={() => sendMessage(input)}><Send size={18} /></button>
      </div>
    </div>
  );
}

// Main App
function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [securityScore, setSecurityScore] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chatOpen, setChatOpen] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [scoreRes, vulnsRes] = await Promise.all([
          api.getSecurityScore(),
          api.getVulnerabilities({ limit: 100 })
        ]);
        setSecurityScore(scoreRes.data);
        setVulnerabilities(vulnsRes.data.vulnerabilities || []);
      } catch (err) {
        // Demo data
        setSecurityScore({ score: 72, label: 'Good', breakdown: { critical: 2, high: 5, moderate: 8, low: 12 } });
      }
    };
    fetchData();
  }, []);

  const criticalCount = vulnerabilities.filter(v => v.priority_level === 'Critical Priority').length;

  return (
    <div className="app-container">
      <Sidebar activeView={activeView} setActiveView={setActiveView} criticalCount={criticalCount} />

      <main className="main-content">
        {activeView === 'dashboard' && <DashboardView securityScore={securityScore} setActiveView={setActiveView} />}
        {activeView === 'vulnerabilities' && (
          <section className="fix-first-section">
            <h2 className="section-title">Vulnerabilities</h2>
            <p className="section-subtitle">{vulnerabilities.length} CVEs analyzed</p>
          </section>
        )}
        {activeView === 'code-analysis' && <CodeAnalysisView />}
        {activeView === 'crypto' && <CryptoToolsView />}
        {activeView === 'osint' && <OsintView />}
        {activeView === 'settings' && (
          <section className="fix-first-section">
            <h2 className="section-title">Settings</h2>
            <p className="section-subtitle">Configure MR-ROBOT</p>
          </section>
        )}
      </main>

      <button className="chat-fab" onClick={() => setChatOpen(!chatOpen)}>
        <MessageCircle size={28} />
      </button>

      <ChatPanel isOpen={chatOpen} onClose={() => setChatOpen(false)} />
    </div>
  );
}

export default App;
