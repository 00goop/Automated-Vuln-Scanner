import { useState } from 'react';
import {
  Shield, Home, AlertTriangle, FileText, Settings,
  MessageCircle, Send, TrendingUp, RefreshCw, X,
  ChevronRight, Clock, Zap, Code, Lock, Search,
  Upload, Hash, Globe, User, Terminal
} from 'lucide-react';
import { api } from '../services/api';

export default function CryptoToolsView() {
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
    } catch {
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
