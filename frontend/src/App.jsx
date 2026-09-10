import ChatPanel from './components/ChatPanel';
import OsintView from './components/OsintView';
import CryptoToolsView from './components/CryptoToolsView';
import CodeAnalysisView from './components/CodeAnalysisView';
import { useState, useEffect } from 'react';
import {
  Shield, Home, AlertTriangle, FileText, Settings,
  MessageCircle, Send, TrendingUp, RefreshCw, X,
  ChevronRight, Clock, Zap, Code, Lock, Search,
  Upload, Hash, Globe, User, Terminal
} from 'lucide-react';
import { api } from './services/api';
import './index.css';

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
            aria-label={item.label}
            aria-current={activeView === item.id ? "page" : undefined}
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


// Crypto Tools View


// OSINT View


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
      {securityScore && <SecurityScoreHero score={securityScore} />}
      {securityScore && <PriorityBreakdown breakdown={securityScore.breakdown} />}

      <section className="fix-first-section">
        <div className="section-header">
          <h2 className="section-title">🛠️ Security Toolkit</h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          {quickActions.map(action => (
            <button
              key={action.id}
              className="priority-card"
              style={{ borderLeftColor: action.color, cursor: 'pointer', textAlign: 'left', color: 'inherit' }}
              onClick={() => setActiveView(action.id)}
            >
              <action.icon size={32} color={action.color} style={{ marginBottom: '8px' }} />
              <div className="priority-card-count" style={{ fontSize: '1.2rem' }}>{action.title}</div>
              <div className="priority-card-label">{action.desc}</div>
            </button>
          ))}
        </div>
      </section>
    </>
  );
}

// Chat Panel


// Main App
function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [securityScore, setSecurityScore] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chatOpen, setChatOpen] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [scoreRes, vulnsRes] = await Promise.all([
          api.getSecurityScore(),
          api.getVulnerabilities({ limit: 100 })
        ]);
        setSecurityScore(scoreRes.data);
        setVulnerabilities(vulnsRes.data.vulnerabilities || []);
      } catch {
        setConnectionError(true);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const criticalCount = vulnerabilities.filter(v => v.priority_level === 'Critical Priority').length;

  return (
    <div className="app-container">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Sidebar activeView={activeView} setActiveView={setActiveView} criticalCount={criticalCount} />

      <main className="main-content" id="main-content">
        <header className="workspace-heading"><div><p className="eyebrow">MR-ROBOT / SECURITY WORKBENCH</p><h1>Understand the signal.</h1><p>Inspect code, investigate indicators, and prioritize with context.</p></div><span className="environment-label">{connectionError ? 'API offline' : loading ? 'Connecting' : 'Local workspace'}</span></header>
        <p className="methodology-note">Priority scores are experimental indicators, not validated exploitation probabilities.</p>
        {loading && <p role="status">Connecting to your security workspace…</p>}
        {connectionError && <div className="connection-notice" role="alert">The API is unavailable. Start the backend and refresh to load your data. No sample security results are displayed.</div>}
        {activeView === 'dashboard' && <DashboardView securityScore={securityScore} setActiveView={setActiveView} />}
        {activeView === 'vulnerabilities' && (
          <section className="fix-first-section">
            <h2 className="section-title">Vulnerabilities</h2>
            <p className="section-subtitle">{vulnerabilities.length} CVEs analyzed</p>
            {!vulnerabilities.length && <p className="empty-state">No CVEs have been analyzed in this session yet.</p>}
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

      <button aria-label="Toggle AI assistant" aria-expanded={chatOpen} className="chat-fab" onClick={() => setChatOpen(!chatOpen)}>
        <MessageCircle size={28} />
      </button>

      <ChatPanel isOpen={chatOpen} onClose={() => setChatOpen(false)} />
    </div>
  );
}

export default App;
