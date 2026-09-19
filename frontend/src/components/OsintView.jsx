import { useState } from 'react';
import {
  Shield, Home, AlertTriangle, FileText, Settings,
  MessageCircle, Send, TrendingUp, RefreshCw, X,
  ChevronRight, Clock, Zap, Code, Lock, Search,
  Upload, Hash, Globe, User, Terminal
} from 'lucide-react';
import { api } from '../services/api';

export default function OsintView() {
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
    } catch {
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
