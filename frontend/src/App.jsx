import ChatPanel from './components/ChatPanel';
import OsintView from './components/OsintView';
import CryptoToolsView from './components/CryptoToolsView';
import CodeAnalysisView from './components/CodeAnalysisView';
import { useState, useEffect } from 'react';
import {
  Home, AlertTriangle, Settings,
  MessageCircle, TrendingUp, ChevronRight, Code, Lock, Search,
  Terminal, Database, Activity
} from 'lucide-react';
import { api } from './services/api';
import './index.css';

// Sidebar Navigation
function Sidebar({ activeView, setActiveView, criticalCount, connectionError, loading }) {
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
          <Terminal size={22} />
        </div>
        <div>
          <div className="brand-name">MR.<span>ROBOT</span></div>
          <div className="brand-tagline">Defensive workbench</div>
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
        <div className={`sync-dot ${connectionError ? 'offline' : ''}`} />
        <span>{connectionError ? 'API DISCONNECTED' : loading ? 'NEGOTIATING LINK' : 'SYSTEM READY'}</span>
      </div>
    </aside>
  );
}

// Security Score Hero
function SecurityScoreHero({ score }) {
  return (
    <div className="security-score-hero">
      <div className="panel-index">01 // PRIORITY SIGNAL</div>
      <div className="security-score-value">{score?.score ?? '--'}</div>
      <div className="security-score-label">
        Experimental security score / {score?.label || 'Awaiting data'}
      </div>
      {score?.score > 0 && (
        <div className="security-score-trend">
          <TrendingUp size={16} />
          Review high-priority evidence first
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
function DashboardView({ securityScore, setActiveView, connectionError, loading, vulnerabilityCount, modelMode }) {
  const quickActions = [
    { id: 'vulnerabilities', icon: AlertTriangle, title: 'Prioritize CVEs', desc: 'Rank NVD records with inspectable context' },
    { id: 'code-analysis', icon: Code, title: 'Inspect Source', desc: 'Run Bandit-backed Python static analysis' },
    { id: 'crypto', icon: Lock, title: 'Transform Data', desc: 'Encode, decode, hash, and verify input' },
    { id: 'osint', icon: Search, title: 'Trace Indicators', desc: 'Inspect public domain and username signals' },
  ];

  return (
    <>
      <section className="command-hero">
        <div className="hero-copy">
          <p className="terminal-path">root@mr-robot:~/operations<span aria-hidden="true">$</span></p>
          <h2>See the signal.<br /><em>Verify the evidence.</em></h2>
          <p className="hero-summary">A focused defensive workspace for CVE triage, source inspection, data transforms, and open-source intelligence.</p>
          <div className="hero-actions">
            <button className="command-button primary" onClick={() => setActiveView('vulnerabilities')}>Review CVE queue <ChevronRight size={16} /></button>
            <button className="command-button" onClick={() => setActiveView('code-analysis')}>Inspect source</button>
          </div>
        </div>
        <div className="truth-panel" aria-label="System capabilities">
          <div className="panel-index">00 // SYSTEM TRUTH</div>
          <dl>
            <div><dt>API link</dt><dd className={connectionError ? 'signal-bad' : 'signal-good'}>{connectionError ? 'offline' : loading ? 'connecting' : 'ready'}</dd></div>
            <div><dt>CVE source</dt><dd>NVD feed</dd></div>
            <div><dt>Scoring mode</dt><dd>{connectionError || loading ? 'unavailable' : modelMode}</dd></div>
            <div><dt>Static scan</dt><dd>Bandit</dd></div>
            <div><dt>Records loaded</dt><dd>{connectionError ? '—' : vulnerabilityCount}</dd></div>
          </dl>
          <p>Outputs support triage. They do not replace validation or exploitability review.</p>
        </div>
      </section>

      {securityScore && <SecurityScoreHero score={securityScore} />}
      {securityScore && <PriorityBreakdown breakdown={securityScore.breakdown} />}

      <section className="fix-first-section">
        <div className="section-header">
          <div><p className="panel-index">02 // MODULE INDEX</p><h2 className="section-title">Choose an operation</h2></div>
        </div>
        <div className="module-grid">
          {quickActions.map((action, index) => (
            <button
              key={action.id}
              className="module-card"
              onClick={() => setActiveView(action.id)}
            >
              <div className="module-card-top"><span>0{index + 1}</span><action.icon size={20} /></div>
              <strong>{action.title}</strong>
              <p>{action.desc}</p>
              <span className="module-open">OPEN MODULE <ChevronRight size={14} /></span>
            </button>
          ))}
        </div>
      </section>
    </>
  );
}

function VulnerabilitiesView({ vulnerabilities }) {
  const priorityClass = (label = '') => label.toLowerCase().split(' ')[0];

  return (
    <section className="fix-first-section">
      <div className="section-header">
        <div><p className="panel-index">QUEUE // NVD RECORDS</p><h2 className="section-title">Vulnerability triage</h2></div>
        <span className="record-count">{vulnerabilities.length} ANALYZED</span>
      </div>
      {!vulnerabilities.length ? (
        <div className="terminal-empty"><Database size={24} /><strong>No records loaded.</strong><p>Start the API and sync the NVD dataset to build a review queue.</p></div>
      ) : (
        <div className="vuln-list">
          {vulnerabilities.slice(0, 30).map((vulnerability) => (
            <article className="vuln-card" key={vulnerability.cve_id}>
              <div className="vuln-content">
                <div className="vuln-header">
                  <span className="vuln-id">{vulnerability.cve_id}</span>
                  <span className={`vuln-priority-label ${priorityClass(vulnerability.priority_level)}`}>{vulnerability.priority_level || 'Unclassified'}</span>
                </div>
                <p className="vuln-description">{vulnerability.description || 'No NVD description available.'}</p>
                <div className="vuln-metadata"><span>CVSS {vulnerability.cvss_base_score ?? '—'}</span><span>PRIORITY {Number.isFinite(vulnerability.priority_score) ? `${Math.round(vulnerability.priority_score * 100)}/100` : 'unavailable'}</span><span>{vulnerability.model_mode ? `Experimental model: ${vulnerability.model_mode}` : 'CVSS heuristic · no ML model'}</span></div>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
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
  const viewTitles = {
    dashboard: ['OPERATIONS', 'Defensive operations'],
    vulnerabilities: ['TRIAGE', 'Vulnerability queue'],
    'code-analysis': ['SOURCE', 'Static analysis'],
    crypto: ['TRANSFORM', 'Cryptographic tools'],
    osint: ['RECON', 'Open-source intelligence'],
    settings: ['SYSTEM', 'Workbench settings'],
  };
  const [viewCode, viewTitle] = viewTitles[activeView];

  return (
    <div className="app-container">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Sidebar activeView={activeView} setActiveView={setActiveView} criticalCount={criticalCount} connectionError={connectionError} loading={loading} />

      <main className="main-content" id="main-content">
        <header className="workspace-heading"><div><p className="eyebrow">MR.ROBOT // {viewCode}</p><h1>{viewTitle}</h1></div><span className={`environment-label ${connectionError ? 'offline' : ''}`}><Activity size={13} />{connectionError ? 'API OFFLINE' : loading ? 'CONNECTING' : 'LOCAL / READY'}</span></header>
        {loading && <p role="status">Connecting to your security workspace…</p>}
        {connectionError && <div className="connection-notice" role="alert">The API is unavailable. Start the backend and refresh to load your data. No sample security results are displayed.</div>}
        {activeView === 'dashboard' && <DashboardView securityScore={securityScore} setActiveView={setActiveView} connectionError={connectionError} loading={loading} vulnerabilityCount={vulnerabilities.length} modelMode={vulnerabilities.length ? (vulnerabilities.some(v => v.model_mode) ? 'experimental model' : 'CVSS heuristic / no model') : 'awaiting records'} />}
        {activeView === 'vulnerabilities' && <VulnerabilitiesView vulnerabilities={vulnerabilities} />}
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

