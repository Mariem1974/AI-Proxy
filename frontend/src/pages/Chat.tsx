import { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import 'katex/dist/katex.min.css';
import { sendChatMessage, resetChat, uploadDocument } from '../services/api';
import type { FeatureFlags, User } from '../types/api';

interface Props {
  features: FeatureFlags;
  user: User;
  onLogout: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

interface Message {
  id: number;
  role: 'user' | 'assistant' | 'system';
  content: string;
}

let _id = 0;

const ShieldIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const SunIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
);

const MoonIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
  </svg>
);

const SendIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
  </svg>
);

export default function Chat({ user, onLogout, theme, onToggleTheme }: Props) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [docContext, setDocContext] = useState('');
  const [docName, setDocName]   = useState('');
  const fileRef   = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLInputElement>(null);

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
      setTimeout(() => inputRef.current?.focus(), 50);
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

  const handleReset = async () => {
    await resetChat();
    setMessages([]);
    setDocContext('');
    setDocName('');
  };

  const initials = user.username[0].toUpperCase();

  return (
    <div style={s.root}>
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div style={s.header}>
        <div style={s.headerLeft}>
          <div style={s.avatarBrand}>
            <ShieldIcon />
          </div>
          <div>
            <div style={s.headerTitle}>Security Booster</div>
            <div style={s.headerSub}>9-Stage Security Pipeline · Finance Protected</div>
          </div>
        </div>

        <div style={s.headerRight}>
          <div style={s.userPill}>
            <div style={s.userDot} />
            {user.username}
          </div>

          {user.role === 'admin' && (
            <a href="/admin" style={s.btnGhost}>Admin</a>
          )}

          <button
            style={s.btnGhost}
            title="New conversation"
            onClick={handleReset}
          >
            New chat
          </button>

          <button className="btn-theme" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} onClick={onToggleTheme}>
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>

          <button
            style={{ ...s.btnGhost, color: 'var(--color-danger)', borderColor: 'var(--color-danger)' }}
            onClick={onLogout}
          >
            Logout
          </button>
        </div>
      </div>

      {/* ── Messages ───────────────────────────────────────────────────── */}
      <div style={s.messages}>
        {messages.length === 0 && (
          <div style={s.empty}>
            <div style={s.emptyShield}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <polyline points="9 12 11 14 15 10" />
              </svg>
            </div>
            <p style={s.emptyTitle}>Welcome to Security Booster</p>
            <p style={s.emptyDesc}>Your finance assistant secured by a 9-stage protection pipeline.</p>
            <div style={s.emptyPills}>
              {['Unicode Guard', 'Injection Filter', 'BERT Classifier', 'PII Shield', 'Context Gate'].map(label => (
                <span key={label} style={s.pill}>{label}</span>
              ))}
            </div>
          </div>
        )}

        {messages.map(m => (
          <div key={m.id} style={{
            ...s.msgRow,
            justifyContent: m.role === 'user' ? 'flex-end' : m.role === 'system' ? 'center' : 'flex-start',
          }}>
            {m.role === 'assistant' && (
              <div style={s.msgAvatarAssistant}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
            )}
            <div
              className={m.role === 'assistant' ? 'prose-bubble' : undefined}
              style={{
                ...s.bubble,
                ...(m.role === 'user'      ? s.bubbleUser      : {}),
                ...(m.role === 'assistant' ? s.bubbleAssistant : {}),
                ...(m.role === 'system'    ? s.bubbleSystem    : {}),
              }}
            >
              {m.role === 'assistant' ? (
                <ReactMarkdown
                  remarkPlugins={[remarkGfm, remarkMath]}
                  rehypePlugins={[rehypeKatex]}
                  components={{
                    p:  ({ children }) => <p style={{ margin: '0 0 8px' }}>{children}</p>,
                    h1: ({ children }) => <h1 style={{ fontSize: 16, fontWeight: 700, margin: '10px 0 6px' }}>{children}</h1>,
                    h2: ({ children }) => <h2 style={{ fontSize: 15, fontWeight: 700, margin: '10px 0 5px' }}>{children}</h2>,
                    h3: ({ children }) => <h3 style={{ fontSize: 14, fontWeight: 600, margin: '8px 0 4px' }}>{children}</h3>,
                    ul: ({ children }) => <ul style={{ paddingLeft: 18, margin: '4px 0 8px' }}>{children}</ul>,
                    ol: ({ children }) => <ol style={{ paddingLeft: 18, margin: '4px 0 8px' }}>{children}</ol>,
                    li: ({ children }) => <li style={{ margin: '2px 0' }}>{children}</li>,
                    code: ({ children, className }) => className
                      ? <pre style={{ background: 'rgba(0,0,0,.25)', borderRadius: 8, padding: '10px 12px', overflowX: 'auto', margin: '6px 0', fontSize: 12 }}><code>{children}</code></pre>
                      : <code style={{ background: 'rgba(0,0,0,.2)', borderRadius: 4, padding: '1px 5px', fontSize: 13 }}>{children}</code>,
                    strong: ({ children }) => <strong style={{ fontWeight: 600 }}>{children}</strong>,
                    blockquote: ({ children }) => <blockquote style={{ borderLeft: '3px solid var(--color-primary)', paddingLeft: 10, margin: '6px 0', color: 'var(--color-text-secondary)' }}>{children}</blockquote>,
                    table: ({ children }) => <table style={{ borderCollapse: 'collapse', width: '100%', margin: '8px 0', fontSize: 13 }}>{children}</table>,
                    th: ({ children }) => <th style={{ border: '1px solid var(--color-border)', padding: '4px 8px', background: 'var(--color-surface-2)', textAlign: 'left' }}>{children}</th>,
                    td: ({ children }) => <td style={{ border: '1px solid var(--color-border)', padding: '4px 8px' }}>{children}</td>,
                  }}
                >
                  {m.content}
                </ReactMarkdown>
              ) : m.content}
            </div>
            {m.role === 'user' && (
              <div style={s.msgAvatarUser}>{initials}</div>
            )}
          </div>
        ))}

        {loading && (
          <div style={{ ...s.msgRow, justifyContent: 'flex-start' }}>
            <div style={s.msgAvatarAssistant}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div style={{ ...s.bubble, ...s.bubbleAssistant, display: 'flex', gap: 5, alignItems: 'center', padding: '14px 18px' }}>
              {[0, 160, 320].map(d => (
                <span key={d} style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: 'var(--color-primary)',
                  display: 'inline-block',
                  animation: `aegis-bounce 1.3s ${d}ms infinite`,
                  opacity: 0.7,
                }} />
              ))}
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* ── Doc context banner ─────────────────────────────────────────── */}
      {docName && (
        <div style={s.docBanner}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 16 }}>📎</span>
            <span><strong>{docName}</strong> will be included in your next message</span>
          </div>
          <button style={s.docClear} onClick={() => { setDocContext(''); setDocName(''); }}>✕</button>
        </div>
      )}

      {/* ── Input bar ──────────────────────────────────────────────────── */}
      <div style={s.inputRow}>
        <input
          ref={fileRef}
          type="file"
          style={{ display: 'none' }}
          accept=".pdf,.docx,.txt,.md,.jpg,.jpeg,.png,.bmp,.tiff,.webp"
          onChange={handleFileUpload}
        />
        <button
          style={s.attachBtn}
          title="Attach document"
          onClick={() => fileRef.current?.click()}
          disabled={loading}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
          </svg>
        </button>
        <input
          ref={inputRef}
          style={s.chatInput}
          placeholder="Ask about finance, accounts, or banking…"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
          disabled={loading}
        />
        <button
          style={{
            ...s.sendBtn,
            opacity: loading || !input.trim() ? 0.38 : 1,
            cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
          }}
          onClick={handleSend}
          disabled={loading || !input.trim()}
          title="Send message"
        >
          <SendIcon />
        </button>
      </div>

      <style>{`
        @keyframes aegis-bounce {
          0%, 80%, 100% { transform: translateY(0); opacity: 0.5; }
          40% { transform: translateY(-7px); opacity: 1; }
        }
      `}</style>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  root: {
    display: 'flex', flexDirection: 'column',
    height: '100vh', maxWidth: 860, margin: '0 auto',
    background: 'var(--color-bg)',
  },

  /* header */
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '12px 20px',
    borderBottom: '1px solid var(--color-border)',
    background: 'var(--color-surface)',
    boxShadow: 'var(--shadow-sm)',
    flexShrink: 0,
  },
  headerLeft:  { display: 'flex', alignItems: 'center', gap: 12 },
  headerRight: { display: 'flex', alignItems: 'center', gap: 8 },

  avatarBrand: {
    width: 38, height: 38, borderRadius: 12,
    background: 'linear-gradient(135deg, var(--color-primary), var(--color-accent))',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    color: '#fff', flexShrink: 0,
    boxShadow: 'var(--shadow-primary)',
  },
  headerTitle: { fontSize: 15, fontWeight: 700, letterSpacing: '-0.01em' },
  headerSub:   { fontSize: 10, color: 'var(--color-text-secondary)', marginTop: 1, letterSpacing: '0.02em' },

  userPill: {
    display: 'flex', alignItems: 'center', gap: 6,
    fontSize: 12, color: 'var(--color-text-secondary)',
    background: 'var(--color-surface-2)',
    border: '1px solid var(--color-border)',
    borderRadius: 20, padding: '4px 10px',
  },
  userDot: {
    width: 6, height: 6, borderRadius: '50%',
    background: 'var(--color-success)',
  },

  btnGhost: {
    background: 'none', border: '1.5px solid var(--color-border)',
    padding: '5px 12px', borderRadius: 8,
    fontSize: 12, cursor: 'pointer',
    color: 'var(--color-text)', textDecoration: 'none',
    transition: 'border-color 0.2s, background 0.2s',
    fontFamily: 'inherit',
  },

  /* messages */
  messages: {
    flex: 1, overflowY: 'auto',
    padding: '24px 20px',
    display: 'flex', flexDirection: 'column', gap: 14,
  },

  /* empty state */
  empty: {
    margin: 'auto',
    textAlign: 'center',
    color: 'var(--color-text-secondary)',
    padding: '0 16px',
    maxWidth: 400,
  },
  emptyShield: {
    width: 72, height: 72, borderRadius: 24,
    background: 'linear-gradient(135deg, var(--color-primary-dim), var(--color-accent-dim))',
    border: '1.5px solid var(--color-border)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    margin: '0 auto 20px',
    color: 'var(--color-primary)',
  },
  emptyTitle: {
    fontSize: 18, fontWeight: 700, color: 'var(--color-text)',
    marginBottom: 8, letterSpacing: '-0.01em',
  },
  emptyDesc: { fontSize: 13, lineHeight: 1.7, marginBottom: 20 },
  emptyPills: { display: 'flex', flexWrap: 'wrap', gap: 6, justifyContent: 'center' },
  pill: {
    fontSize: 11, fontWeight: 500,
    background: 'var(--color-primary-dim)',
    color: 'var(--color-primary)',
    border: '1px solid rgba(0,212,255,0.2)',
    borderRadius: 20, padding: '3px 10px',
    letterSpacing: '0.02em',
  },

  /* messages */
  msgRow:    { display: 'flex', alignItems: 'flex-end', gap: 8 },

  msgAvatarAssistant: {
    width: 30, height: 30, borderRadius: 10,
    background: 'linear-gradient(135deg, var(--color-primary), var(--color-accent))',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    flexShrink: 0, color: '#fff',
  },
  msgAvatarUser: {
    width: 30, height: 30, borderRadius: 10,
    background: 'var(--color-accent)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    flexShrink: 0, color: '#fff',
    fontSize: 13, fontWeight: 700,
  },

  bubble: {
    maxWidth: '72%', padding: '11px 16px',
    borderRadius: 16, fontSize: 14,
    lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
  },
  bubbleUser: {
    background: 'var(--color-accent)',
    color: '#fff',
    borderBottomRightRadius: 4,
    boxShadow: '0 2px 8px var(--color-accent-dim)',
  },
  bubbleAssistant: {
    background: 'var(--color-surface)',
    border: '1px solid var(--color-border)',
    borderBottomLeftRadius: 4,
    boxShadow: 'var(--shadow-sm)',
  },
  bubbleSystem: {
    background: 'var(--color-primary-dim)',
    border: '1px solid rgba(0,212,255,0.18)',
    color: 'var(--color-primary)',
    fontSize: 13, borderRadius: 12, maxWidth: '82%',
    textAlign: 'center' as const,
  },

  /* doc banner */
  docBanner: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '10px 20px',
    background: 'var(--color-primary-dim)',
    borderTop: '1px solid rgba(0,212,255,0.18)',
    fontSize: 13, flexShrink: 0,
    color: 'var(--color-text)',
  },
  docClear: {
    background: 'none', border: 'none', cursor: 'pointer',
    color: 'var(--color-text-secondary)', fontSize: 16, lineHeight: 1,
  },

  /* input area */
  inputRow: {
    display: 'flex', gap: 10, padding: '14px 16px',
    borderTop: '1px solid var(--color-border)',
    background: 'var(--color-surface)',
    alignItems: 'center', flexShrink: 0,
    boxShadow: '0 -4px 20px rgba(0,0,0,.1)',
  },
  attachBtn: {
    width: 38, height: 38,
    background: 'var(--color-surface-2)',
    border: '1.5px solid var(--color-border)',
    borderRadius: 10, cursor: 'pointer',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    color: 'var(--color-text-secondary)', flexShrink: 0,
    transition: 'border-color 0.2s, background 0.2s',
  },
  chatInput: {
    flex: 1, padding: '11px 16px',
    border: '1.5px solid var(--color-border)',
    borderRadius: 12,
    background: 'var(--color-surface-2)',
    color: 'var(--color-text)',
    fontSize: 14, outline: 'none',
    fontFamily: 'inherit',
    transition: 'border-color 0.2s, box-shadow 0.2s',
  },
  sendBtn: {
    width: 42, height: 42,
    background: 'linear-gradient(135deg, var(--color-primary), var(--color-primary-dark))',
    color: '#fff',
    border: 'none', borderRadius: 12,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    flexShrink: 0,
    transition: 'opacity 0.2s, transform 0.15s',
    boxShadow: 'var(--shadow-primary)',
  },
};
