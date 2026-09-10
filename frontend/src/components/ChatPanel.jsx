import { useState } from 'react';
import {
  Shield, Home, AlertTriangle, FileText, Settings,
  MessageCircle, Send, TrendingUp, RefreshCw, X,
  ChevronRight, Clock, Zap, Code, Lock, Search,
  Upload, Hash, Globe, User, Terminal
} from 'lucide-react';
import { api } from '../services/api';

export default function ChatPanel({ isOpen, onClose }) {
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
    } catch {
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
          <div className="chat-header-status">Security assistant</div>
        </div>
        <button aria-label="Close assistant" onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
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
          aria-label="Message to security assistant"
          placeholder="Ask me anything..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessage(input)}
        />
        <button aria-label="Send message" className="chat-send" onClick={() => sendMessage(input)}><Send size={18} /></button>
      </div>
    </div>
  );
}
