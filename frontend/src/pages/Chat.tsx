import { useState, useRef, useEffect } from 'react';
import { sendChatMessage, resetChat, uploadDocument } from '../services/api';
import type { FeatureFlags, User } from '../types/api';

interface Props {
  features: FeatureFlags;
  user: User;
  onLogout: () => void;
}

interface Message {
  id: number;
  role: 'user' | 'assistant' | 'system';
  content: string;
}

let _id = 0;

export default function Chat({ user, onLogout }: Props) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [docContext, setDocContext] = useState('');
  const [docName, setDocName]   = useState('');
  const fileRef  = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const add = (role: Message['role'], content: string) =>
    setMessages(prev => [...prev, { id: _id++, role, content }]);

  const handleSend = async () => {
    const text = input.trim();
    if (!text || loading) return;
    setInput('');

    const fullMessage = docContext
      ? `[DOCUMENT CONTEXT]\n${docContext}\n\n[USER QUESTION]\n${text}`
      : text;

    add('user', text);
    setLoading(true);
    try {
      const reply = await sendChatMessage(fullMessage, user.id);
      add('assistant', reply);
    } catch (err: unknown) {
      add('system', `⚠️ ${err instanceof Error ? err.message : 'Error'}`);
    } finally {
      setLoading(false);
      if (docContext) { setDocContext(''); setDocName(''); }
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    add('system', `📄 Uploading and scanning "${file.name}"…`);
    try {
      const res = await uploadDocument(file, user.id);
      if (res.success && res.safe_context) {
        setDocContext(res.safe_context);
        setDocName(file.name);
        add('system', `✅ Document scanned — ${res.stats?.safe_chunks ?? '?'} safe chunks ready. Ask your question below.`);
      } else {
        add('system', `🚫 Document blocked: ${res.message || 'Security check failed'}`);
      }
    } catch (err: unknown) {
      add('system', `⚠️ ${err instanceof Error ? err.message : 'Upload failed'}`);
    } finally {
      setLoading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  return (
    <div style={styles.root}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <div style={styles.avatar}>E</div>
          <div>
            <div style={styles.headerTitle}>Essam — Finance Assistant</div>
            <div style={styles.headerSub}>AI-Proxy v2 · Protected</div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <span style={styles.userBadge}>👤 {user.username}</span>
          {user.role === 'admin' && (
            <a href="/admin" style={styles.btnGhost}>Admin Panel</a>
          )}
          <button style={styles.btnGhost} onClick={async () => { await resetChat(); setMessages([]); setDocContext(''); setDocName(''); }}>
            Reset
          </button>
          <button style={{ ...styles.btnGhost, color: '#ef4444', borderColor: '#ef4444' }} onClick={onLogout}>
            Logout
          </button>
        </div>
      </div>

      {/* Messages */}
      <div style={styles.messages}>
        {messages.length === 0 && (
          <div style={styles.empty}>
            <div style={styles.emptyIcon}>🛡️</div>
            <p style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>AI-Proxy Finance Assistant</p>
            <p style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>
              Your conversation is protected by the multi-layer security proxy.
            </p>
          </div>
        )}

        {messages.map(m => (
          <div key={m.id} style={{
            ...styles.msgRow,
            justifyContent: m.role === 'user' ? 'flex-end' : m.role === 'system' ? 'center' : 'flex-start',
          }}>
            {m.role === 'assistant' && <div style={{ ...styles.msgAvatar, background: 'var(--color-primary)', color: '#0b1020' }}>E</div>}
            <div style={{
              ...styles.bubble,
              ...(m.role === 'user'      ? styles.bubbleUser      : {}),
              ...(m.role === 'assistant' ? styles.bubbleAssistant : {}),
              ...(m.role === 'system'    ? styles.bubbleSystem    : {}),
            }}>
              {m.content}
            </div>
            {m.role === 'user' && <div style={{ ...styles.msgAvatar, background: 'var(--color-accent)' }}>{user.username[0].toUpperCase()}</div>}
          </div>
        ))}

        {loading && (
          <div style={{ ...styles.msgRow, justifyContent: 'flex-start' }}>
            <div style={{ ...styles.msgAvatar, background: 'var(--color-primary)', color: '#0b1020' }}>E</div>
            <div style={{ ...styles.bubble, ...styles.bubbleAssistant, display: 'flex', gap: 6, alignItems: 'center', padding: '12px 16px' }}>
              {[0, 150, 300].map(d => (
                <span key={d} style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--color-text-secondary)', display: 'inline-block', animation: `bounce 1.2s ${d}ms infinite` }} />
              ))}
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Doc banner */}
      {docName && (
        <div style={styles.docBanner}>
          <span>📎 <strong>{docName}</strong> — context will be sent with your next message</span>
          <button style={styles.docClear} onClick={() => { setDocContext(''); setDocName(''); }}>✕</button>
        </div>
      )}

      {/* Input row */}
      <div style={styles.inputRow}>
        <input ref={fileRef} type="file" style={{ display: 'none' }}
          accept=".pdf,.docx,.txt,.md,.jpg,.jpeg,.png,.bmp,.tiff,.webp"
          onChange={handleFileUpload} />
        <button style={styles.attachBtn} title="Upload document" onClick={() => fileRef.current?.click()}>
          📎
        </button>
        <input
          style={styles.chatInput}
          placeholder="Type a message…"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
          disabled={loading}
        />
        <button style={{ ...styles.sendBtn, opacity: loading || !input.trim() ? 0.4 : 1 }}
          onClick={handleSend} disabled={loading || !input.trim()}>
          Send
        </button>
      </div>

      <style>{`
        @keyframes bounce {
          0%, 80%, 100% { transform: translateY(0); }
          40% { transform: translateY(-6px); }
        }
      `}</style>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  root:            { display: 'flex', flexDirection: 'column', height: '100vh', maxWidth: 820, margin: '0 auto', background: 'var(--color-bg)' },
  header:          { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface)', flexShrink: 0 },
  headerLeft:      { display: 'flex', alignItems: 'center', gap: 12 },
  avatar:          { width: 38, height: 38, borderRadius: '50%', background: 'var(--color-primary)', color: '#0b1020', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 16 },
  headerTitle:     { fontSize: 15, fontWeight: 600 },
  headerSub:       { fontSize: 11, color: 'var(--color-text-secondary)' },
  headerRight:     { display: 'flex', alignItems: 'center', gap: 8 },
  userBadge:       { fontSize: 13, color: 'var(--color-text-secondary)' },
  btnGhost:        { background: 'none', border: '1px solid var(--color-border)', padding: '6px 12px', borderRadius: 8, fontSize: 12, cursor: 'pointer', color: 'var(--color-text)', textDecoration: 'none' },
  messages:        { flex: 1, overflowY: 'auto', padding: '20px 16px', display: 'flex', flexDirection: 'column', gap: 12 },
  empty:           { margin: '60px auto', textAlign: 'center', color: 'var(--color-text-secondary)' },
  emptyIcon:       { fontSize: 40, marginBottom: 12 },
  msgRow:          { display: 'flex', alignItems: 'flex-end', gap: 8 },
  msgAvatar:       { width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, flexShrink: 0, color: '#fff' },
  bubble:          { maxWidth: '70%', padding: '10px 14px', borderRadius: 14, fontSize: 14, lineHeight: 1.55, whiteSpace: 'pre-wrap', wordBreak: 'break-word' },
  bubbleUser:      { background: 'var(--color-accent)', color: '#fff', borderBottomRightRadius: 4 },
  bubbleAssistant: { background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderBottomLeftRadius: 4 },
  bubbleSystem:    { background: 'rgba(0,212,255,0.07)', border: '1px solid rgba(0,212,255,0.2)', color: 'var(--color-primary)', fontSize: 13, borderRadius: 10, maxWidth: '80%' },
  docBanner:       { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 20px', background: 'rgba(0,212,255,0.08)', borderTop: '1px solid rgba(0,212,255,0.2)', fontSize: 13, flexShrink: 0 },
  docClear:        { background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-secondary)', fontSize: 16 },
  inputRow:        { display: 'flex', gap: 10, padding: '14px 16px', borderTop: '1px solid var(--color-border)', background: 'var(--color-surface)', alignItems: 'center', flexShrink: 0 },
  attachBtn:       { fontSize: 20, background: 'none', border: 'none', cursor: 'pointer', padding: '6px 8px', borderRadius: 8, lineHeight: 1 },
  chatInput:       { flex: 1, padding: '10px 14px', border: '1px solid var(--color-border)', borderRadius: 10, background: 'var(--color-surface-2)', color: 'var(--color-text)', fontSize: 14, outline: 'none' },
  sendBtn:         { background: 'var(--color-primary)', color: '#0b1020', border: 'none', padding: '10px 22px', borderRadius: 10, fontSize: 14, cursor: 'pointer', fontWeight: 600, flexShrink: 0 },
};
