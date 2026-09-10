import { useState } from 'react';
import {
  Shield, Home, AlertTriangle, FileText, Settings,
  MessageCircle, Send, TrendingUp, RefreshCw, X,
  ChevronRight, Clock, Zap, Code, Lock, Search,
  Upload, Hash, Globe, User, Terminal
} from 'lucide-react';
import { api } from '../services/api';

export default function CodeAnalysisView() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeCode = async () => {
    if (!code.trim()) return;
    setLoading(true);
    try {
      const res = await api.analyzeCode(code, 'code.py');
      setResult(res.data);
    } catch {
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
