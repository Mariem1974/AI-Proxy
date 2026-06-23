import { useState, useEffect } from 'react';
import type {
  FeatureFlags, AlertSettings, SecurityLog, User,
  AlertOverTime, TopThreat, TopBlockedUser, SeverityBreakdown,
} from '../types/api';
import { AlertSettingsSchema, flattenZodErrors } from '../lib/schemas';
import {
  getFeatures,
  toggleInputUnicode, toggleInputSpacy, toggleBert, toggleInputPii, toggleInputContext,
  toggleOutputSpacy, toggleOutputPii, toggleOutputContext, toggleDocumentProcessing,
  setBertModel, getBertModel,
  uploadContextPdf, setThreshold, getVectorstoreStatus,
  getUsers, unblockUser,
  getAlertSettings, updateAlertSettings,
  getSecurityLogs, downloadSecurityLogs,
  getAlertsOverTime, getTopThreats, getTopBlockedUsers, getSeverityBreakdown,
} from '../services/api';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';

interface Props {
  features:         FeatureFlags;
  onFeaturesChange: (f: FeatureFlags) => void;
  user:             User;
  onLogout:         () => void;
  theme:            'dark' | 'light';
  onToggleTheme:    () => void;
}

// ── Toggle component ──────────────────────────────────────────────────────────
function Toggle({ label, sublabel, enabled, onToggle }: {
  label: string; sublabel?: string; enabled: boolean; onToggle: () => void;
}) {
  return (
    <div className="toggle-row" onClick={onToggle}>
      <div className="toggle-info">
        <span className="toggle-label">{label}</span>
        {sublabel && <span className="toggle-sublabel">{sublabel}</span>}
      </div>
      <div className={`toggle-switch ${enabled ? 'on' : 'off'}`}>
        <div className="toggle-thumb" />
      </div>
    </div>
  );
}

// ── Severity badge ────────────────────────────────────────────────────────────
function Badge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308',
    low: '#22c55e', info: '#00d4ff',
  };
  return (
    <span style={{
      background: map[severity] || '#64748b', color: '#fff',
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
      textTransform: 'uppercase',
    }}>{severity}</span>
  );
}

// ── Panel wrapper ─────────────────────────────────────────────────────────────
function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      background: 'var(--color-surface)', border: '1px solid var(--color-border)',
      borderRadius: 14, padding: 20,
    }}>
      <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 14, color: 'var(--color-text)' }}>{title}</h3>
      {children}
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Admin({ features, onFeaturesChange, user, onLogout, theme, onToggleTheme }: Props) {
  const [tab, setTab] = useState<'pipeline' | 'context' | 'logs' | 'users' | 'alerts' | 'analytics'>('pipeline');
  const [bertModel, setBertModelState] = useState('distilbert');
  const [vsStatus, setVsStatus] = useState<{ is_loaded: boolean; chunk_count: number } | null>(null);
  const [threshold, setThresholdVal] = useState(50);
  const [logs, setLogs]   = useState<SecurityLog[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [alerts, setAlerts] = useState<AlertSettings | null>(null);
  const [alertErrors, setAlertErrors] = useState<Record<string, string>>({});
  const [logFilter, setLogFilter] = useState('');
  const [toast, setToast] = useState('');

  // Analytics state
  const [alertsOverTime, setAlertsOverTime] = useState<AlertOverTime[]>([]);
  const [topThreats, setTopThreats] = useState<TopThreat[]>([]);
  const [topBlocked, setTopBlocked] = useState<TopBlockedUser[]>([]);
  const [severityData, setSeverityData] = useState<SeverityBreakdown[]>([]);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  useEffect(() => {
    Promise.all([
      getBertModel().then(r => setBertModelState(r.active_model)),
      getVectorstoreStatus().then(setVsStatus),
      getSecurityLogs(200).then(r => setLogs(r.logs)),
      getUsers().then(r => setUsers(r.users)),
      getAlertSettings().then(setAlerts),
    ]).catch(console.error);
  }, []);

  const loadAnalytics = async () => {
    setAnalyticsLoading(true);
    try {
      const [ot, tt, tb, sv] = await Promise.all([
        getAlertsOverTime(24),
        getTopThreats(),
        getTopBlockedUsers(),
        getSeverityBreakdown(),
      ]);
      setAlertsOverTime(ot.data);
      setTopThreats(tt.data);
      setTopBlocked(tb.data);
      setSeverityData(sv.data);
    } catch (e) {
      console.error('Analytics load failed:', e);
    } finally {
      setAnalyticsLoading(false);
    }
  };

  // Load analytics when that tab is activated for the first time
  useEffect(() => {
    if (tab === 'analytics' && alertsOverTime.length === 0 && !analyticsLoading) {
      loadAnalytics();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  const doToggle = async (fn: () => Promise<object>) => {
    await fn();
    const f = await getFeatures();
    onFeaturesChange(f);
  };

  const handlePdf = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]; if (!file) return;
    try {
      const res = await uploadContextPdf(file);
      showToast(res.success ? `PDF loaded — ${res.chunk_count} chunks` : res.error || 'Failed');
      getVectorstoreStatus().then(setVsStatus);
    } catch (err: unknown) { showToast(err instanceof Error ? err.message : 'Error'); }
  };

  const filteredLogs = logs.filter(l =>
    !logFilter ||
    l.detection_type?.toLowerCase().includes(logFilter.toLowerCase()) ||
    l.username?.toLowerCase().includes(logFilter.toLowerCase()) ||
    l.severity?.toLowerCase().includes(logFilter.toLowerCase())
  );

  const tabs = ['pipeline', 'context', 'logs', 'users', 'alerts', 'analytics'] as const;

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 1200, margin: '0 auto', padding: 24, color: 'var(--color-text)', background: 'var(--color-bg)', minHeight: '100vh' }}>
      {toast && (
        <div style={{ position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)', background: 'var(--color-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text)', padding: '10px 20px', borderRadius: 12, fontSize: 14, zIndex: 1000, boxShadow: '0 4px 20px rgba(0,0,0,.4)' }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 40, height: 40, borderRadius: 12, background: 'linear-gradient(135deg, var(--color-primary), var(--color-accent))', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', boxShadow: 'var(--shadow-primary)', flexShrink: 0 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.01em', lineHeight: 1.2 }}>
              Security Booster
              <span style={{ marginLeft: 8, background: 'var(--color-primary-dim)', color: 'var(--color-primary)', border: '1px solid rgba(0,212,255,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.03em' }}>CONTROL CENTER</span>
            </h1>
            <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 1 }}>
              <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--color-success)', marginRight: 5, verticalAlign: 'middle' }} />
              {user.username}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <a href="/" className="btn-secondary" style={{ textDecoration: 'none' }}>← Chat</a>
          <button className="btn-theme" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} onClick={onToggleTheme}>
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
          <button className="btn-secondary" style={{ color: 'var(--color-danger)', borderColor: 'var(--color-danger)' }} onClick={onLogout}>Logout</button>
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--color-border)', marginBottom: 24 }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            background: 'none', border: 'none', padding: '10px 18px', cursor: 'pointer',
            fontSize: 14, color: tab === t ? 'var(--color-primary)' : 'var(--color-text-secondary)',
            borderBottom: tab === t ? '2px solid var(--color-primary)' : '2px solid transparent',
            marginBottom: -1, fontWeight: tab === t ? 600 : 400, transition: 'color .15s',
          }}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* ── PIPELINE TAB ── */}
      {tab === 'pipeline' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
          <Panel title="Input Pipeline">
            <Toggle label="Unicode Firewall" sublabel="Emoji stego + homoglyph attacks"
              enabled={features.INPUT_UNICODE_FIREWALL} onToggle={() => doToggle(toggleInputUnicode)} />
            <Toggle label="spaCy Rules v2" sublabel="Injection · SQLi · XSS · CMDi · SSTI"
              enabled={features.INPUT_SPACY_FIREWALL} onToggle={() => doToggle(toggleInputSpacy)} />
            <Toggle label="BERT Classifier" sublabel="ModernBERT + rephrase loop"
              enabled={features.BERT_FIREWALL} onToggle={() => doToggle(toggleBert)} />
            <Toggle label="PII Detector" sublabel="GLiNER — 41 PII types, redact input"
              enabled={features.INPUT_PII_FIREWALL} onToggle={() => doToggle(toggleInputPii)} />
            <Toggle label="Context Relevance" sublabel="Vector DB domain boundary"
              enabled={features.INPUT_CONTEXT_RELEVANCE} onToggle={() => doToggle(toggleInputContext)} />
          </Panel>

          <Panel title="Output Pipeline">
            <Toggle label="spaCy Rules v2" sublabel="Secrets · toxic · Egyptian PII"
              enabled={features.OUTPUT_SPACY_FIREWALL} onToggle={() => doToggle(toggleOutputSpacy)} />
            <Toggle label="PII Detector" sublabel="GLiNER + Llama3.2 redaction"
              enabled={features.OUTPUT_PII_FIREWALL} onToggle={() => doToggle(toggleOutputPii)} />
            <Toggle label="Context Relevance" sublabel="Block off-domain LLM responses"
              enabled={features.OUTPUT_CONTEXT_RELEVANCE} onToggle={() => doToggle(toggleOutputContext)} />
          </Panel>

          <Panel title="Document Processing">
            <Toggle label="File Upload Scanning" sublabel="FileGate + OCR + full pipeline"
              enabled={features.DOCUMENT_PROCESSING} onToggle={() => doToggle(toggleDocumentProcessing)} />
            <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 8 }}>
              Supports PDF, DOCX, images (jpg/png/bmp/tiff), TXT
            </p>
          </Panel>

          <Panel title="Classifier Model">
            <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 12 }}>Select active injection classifier</p>
            {(['modernbert', 'distilbert'] as const).map(m => (
              <button key={m} onClick={async () => { await setBertModel(m); setBertModelState(m); showToast(`Switched to ${m}`); }}
                style={{
                  display: 'block', width: '100%', textAlign: 'left', marginBottom: 8,
                  padding: '10px 14px', borderRadius: 10, cursor: 'pointer', fontSize: 13,
                  background: bertModel === m ? 'var(--color-primary)' : 'var(--color-surface-2)',
                  color: bertModel === m ? '#0b1020' : 'var(--color-text)',
                  border: `1px solid ${bertModel === m ? 'var(--color-primary)' : 'var(--color-border)'}`,
                  fontWeight: bertModel === m ? 600 : 400,
                }}>
                {m === 'modernbert' ? '⚡ ModernBERT (new — 512 tokens)' : '📦 DistilBERT (legacy — 128 tokens)'}
              </button>
            ))}
            <p style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginTop: 6 }}>
              Active: <strong style={{ color: 'var(--color-primary)' }}>{bertModel}</strong>
              {features.bert_settings && <> · Safe &lt;{features.bert_settings.SAFE_THRESHOLD} · Block &gt;{features.bert_settings.MEDIUM_THRESHOLD}</>}
            </p>
          </Panel>
        </div>
      )}

      {/* ── CONTEXT TAB ── */}
      {tab === 'context' && (
        <Panel title="Vector DB — Context Settings">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', background: 'var(--color-surface-2)', borderRadius: 10, marginBottom: 20 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: vsStatus?.is_loaded ? 'var(--color-success)' : '#ef4444', flexShrink: 0 }} />
            <span style={{ fontSize: 13 }}>
              {vsStatus?.is_loaded ? `Loaded — ${vsStatus.chunk_count} chunks` : 'Not loaded — upload a domain PDF to enable context filters'}
            </span>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 8 }}>Upload Domain PDF</label>
            <input type="file" accept=".pdf" onChange={handlePdf}
              style={{ fontSize: 13, color: 'var(--color-text)' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 8 }}>
              Similarity Threshold: <strong style={{ color: 'var(--color-primary)' }}>{threshold}%</strong>
            </label>
            <input type="range" min={0} max={100} value={threshold}
              onChange={e => setThresholdVal(Number(e.target.value))}
              style={{ width: '100%', marginBottom: 10 }} />
            <button className="btn-primary" onClick={async () => { await setThreshold(threshold); showToast(`Threshold set to ${threshold}%`); }}>
              Save Threshold
            </button>
          </div>
        </Panel>
      )}

      {/* ── LOGS TAB ── */}
      {tab === 'logs' && (
        <div>
          <div style={{ display: 'flex', gap: 10, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <input className="input-field" style={{ flex: 1, minWidth: 200 }}
              placeholder="Filter by type / user / severity…"
              value={logFilter} onChange={e => setLogFilter(e.target.value)} />
            <button type="button" className="btn-secondary" onClick={() => downloadSecurityLogs().catch(console.error)}>
              ⬇ Download JSON
            </button>
            <button className="btn-secondary" onClick={() => getSecurityLogs(200).then(r => setLogs(r.logs))}>
              ↻ Refresh
            </button>
          </div>
          <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 12 }}>
            {filteredLogs.length} events · JSON auto-saved as <code>security_logs.json</code> in server directory
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: 'var(--color-surface)' }}>
                  {['Time', 'User', 'Detection', 'Action', 'Severity', 'Prompt'].map(h => (
                    <th key={h} style={{ padding: '10px 12px', textAlign: 'left', borderBottom: '1px solid var(--color-border)', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid var(--color-border)' }}>
                    <td style={{ padding: '8px 12px', whiteSpace: 'nowrap', fontSize: 12, color: 'var(--color-text-secondary)' }}>{new Date(log.timestamp).toLocaleString()}</td>
                    <td style={{ padding: '8px 12px' }}>{log.username}</td>
                    <td style={{ padding: '8px 12px' }}><code style={{ background: 'var(--color-surface-2)', padding: '2px 6px', borderRadius: 4, fontSize: 11 }}>{log.detection_type}</code></td>
                    <td style={{ padding: '8px 12px' }}>{log.action}</td>
                    <td style={{ padding: '8px 12px' }}><Badge severity={log.severity} /></td>
                    <td style={{ padding: '8px 12px', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-text-secondary)', fontSize: 12 }} title={log.prompt}>{log.prompt?.slice(0, 60)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── USERS TAB ── */}
      {tab === 'users' && (
        <div>
          <button className="btn-secondary" style={{ marginBottom: 14 }}
            onClick={() => getUsers().then(r => setUsers(r.users))}>↻ Refresh</button>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: 'var(--color-surface)' }}>
                  {['ID', 'Username', 'Email', 'Role', 'Status', 'Violations', 'Actions'].map(h => (
                    <th key={h} style={{ padding: '10px 12px', textAlign: 'left', borderBottom: '1px solid var(--color-border)', fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid var(--color-border)', background: u.is_blocked ? 'rgba(239,68,68,0.05)' : 'transparent' }}>
                    <td style={{ padding: '9px 12px' }}>{u.id}</td>
                    <td style={{ padding: '9px 12px', fontWeight: 500 }}>{u.username}</td>
                    <td style={{ padding: '9px 12px', color: 'var(--color-text-secondary)' }}>{u.email}</td>
                    <td style={{ padding: '9px 12px' }}>{u.role}</td>
                    <td style={{ padding: '9px 12px' }}>
                      <span style={{ color: u.is_blocked ? '#ef4444' : '#22c55e', fontWeight: 600, fontSize: 12 }}>
                        {u.is_blocked ? '🔒 Blocked' : '✅ Active'}
                      </span>
                    </td>
                    <td style={{ padding: '9px 12px', color: 'var(--color-text-secondary)' }}>
                      {u.failed_attempts} attempts · {u.temp_blocks} temp blocks
                    </td>
                    <td style={{ padding: '9px 12px' }}>
                      {u.is_blocked && (
                        <button onClick={async () => { await unblockUser(u.id); showToast(`${u.username} unblocked`); getUsers().then(r => setUsers(r.users)); }}
                          style={{ background: '#f97316', color: '#fff', border: 'none', padding: '5px 12px', borderRadius: 6, fontSize: 12, cursor: 'pointer' }}>
                          Unblock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── ANALYTICS TAB ── */}
      {tab === 'analytics' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <p style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>
              TimescaleDB-powered security analytics
            </p>
            <button className="btn-secondary" onClick={loadAnalytics} disabled={analyticsLoading}>
              {analyticsLoading ? 'Loading…' : '↻ Refresh'}
            </button>
          </div>

          {alertsOverTime.length === 0 && topThreats.length === 0 && !analyticsLoading && (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--color-text-secondary)', fontSize: 14 }}>
              No analytics data yet. Click Refresh to load.
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(480px, 1fr))', gap: 20 }}>

            {/* Alerts Over Time */}
            <Panel title="Alerts Over Time (last 24 h)">
              {alertsOverTime.length === 0 ? (
                <p style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>No data</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={alertsOverTime} margin={{ top: 4, right: 8, left: -20, bottom: 4 }}>
                    <XAxis dataKey="bucket" tick={{ fontSize: 10 }}
                      tickFormatter={v => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
                    <YAxis tick={{ fontSize: 10 }} allowDecimals={false} />
                    <Tooltip
                      labelFormatter={v => new Date(v).toLocaleString()}
                      contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 12 }}
                    />
                    <Bar dataKey="count" fill="var(--color-primary)" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </Panel>

            {/* Top Threat Types */}
            <Panel title="Top Threat Types">
              {topThreats.length === 0 ? (
                <p style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>No data</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={topThreats} layout="vertical" margin={{ top: 4, right: 24, left: 8, bottom: 4 }}>
                    <XAxis type="number" tick={{ fontSize: 10 }} allowDecimals={false} />
                    <YAxis type="category" dataKey="type" tick={{ fontSize: 10 }} width={130} />
                    <Tooltip
                      contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 12 }}
                    />
                    <Bar dataKey="count" fill="#f97316" radius={[0, 3, 3, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </Panel>

            {/* Severity Breakdown */}
            <Panel title="Severity Breakdown">
              {severityData.length === 0 ? (
                <p style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>No data</p>
              ) : (() => {
                const COLORS: Record<string, string> = {
                  CRITICAL: '#ef4444', HIGH: '#f97316',
                  MEDIUM: '#eab308', LOW: '#22c55e', INFO: '#00d4ff',
                };
                return (
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        dataKey="count"
                        nameKey="severity"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        label={({ severity, percent }) =>
                          `${severity} ${(percent * 100).toFixed(0)}%`
                        }
                        labelLine={false}
                      >
                        {severityData.map((entry, i) => (
                          <Cell
                            key={i}
                            fill={COLORS[entry.severity?.toUpperCase()] ?? '#64748b'}
                          />
                        ))}
                      </Pie>
                      <Legend iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                      <Tooltip
                        contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 12 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                );
              })()}
            </Panel>

            {/* Top Blocked Users */}
            <Panel title="Top Users by Violations">
              {topBlocked.length === 0 ? (
                <p style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>No data</p>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr>
                        {['User', 'Violations', 'Fails', 'Temp Blocks', 'Status'].map(h => (
                          <th key={h} style={{ padding: '6px 10px', textAlign: 'left', borderBottom: '1px solid var(--color-border)', fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {topBlocked.map((u, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--color-border)' }}>
                          <td style={{ padding: '6px 10px', fontWeight: 500 }}>{u.username}</td>
                          <td style={{ padding: '6px 10px', color: 'var(--color-primary)' }}>{u.total_violations}</td>
                          <td style={{ padding: '6px 10px' }}>{u.failed_attempts}</td>
                          <td style={{ padding: '6px 10px' }}>{u.temp_blocks}</td>
                          <td style={{ padding: '6px 10px' }}>
                            <span style={{ color: u.is_blocked ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                              {u.is_blocked ? 'Blocked' : 'Active'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>

          </div>
        </div>
      )}

      {/* ── ALERTS TAB ── */}
      {tab === 'alerts' && alerts && (
        <Panel title="SOC Alert Settings">
          <div style={{ maxWidth: 520 }}>
            {[
              { label: 'Max Violations Before Block', key: 'max_attempts_to_block' },
              { label: 'Violation Window (minutes)',  key: 'warning_window_minutes' },
              { label: 'Temp Block Duration (minutes)', key: 'block_duration_minutes' },
              { label: 'Max Temp Blocks Before Permanent', key: 'max_temp_blocks' },
            ].map(({ label, key }) => (
              <div key={key} style={{ marginBottom: 14 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 6 }}>{label}</label>
                <input type="number" className="input-field"
                  style={alertErrors[key] ? { border: '1px solid #ef4444' } : {}}
                  value={(alerts as unknown as Record<string, number>)[key]}
                  onChange={e => { setAlerts({ ...alerts, [key]: +e.target.value }); setAlertErrors(ae => ({ ...ae, [key]: '' })); }} />
                {alertErrors[key] && <p style={{ color: '#f87171', fontSize: 11, marginTop: 4 }}>{alertErrors[key]}</p>}
              </div>
            ))}
            <hr style={{ border: 'none', borderTop: '1px solid var(--color-border)', margin: '16px 0' }} />
            <div className="toggle-row" onClick={() => setAlerts({ ...alerts, enable_email: !alerts.enable_email })}>
              <div className="toggle-info"><span className="toggle-label">Email Alerts (Gmail SMTP)</span></div>
              <div className={`toggle-switch ${alerts.enable_email ? 'on' : 'off'}`}><div className="toggle-thumb" /></div>
            </div>
            {alerts.enable_email && (
              <div className="mb-4 mt-2">
                <label className="block text-sm font-medium mb-1">Alert Email</label>
                <input
                  type="email"
                  className={`input-field w-full ${alertErrors.email_address ? 'border border-red-500' : ''}`}
                  value={alerts.email_address}
                  onChange={e => { setAlerts({ ...alerts, email_address: e.target.value }); setAlertErrors(ae => ({ ...ae, email_address: '' })); }}
                />
                {alertErrors.email_address && <p className="mt-1 text-xs text-red-400">{alertErrors.email_address}</p>}
              </div>
            )}
            <div className="toggle-row" onClick={() => setAlerts({ ...alerts, enable_telegram: !alerts.enable_telegram })}>
              <div className="toggle-info"><span className="toggle-label">Telegram Alerts</span></div>
              <div className={`toggle-switch ${alerts.enable_telegram ? 'on' : 'off'}`}><div className="toggle-thumb" /></div>
            </div>
            {alerts.enable_telegram && (
              <div className="mb-4 mt-2">
                <label className="block text-sm font-medium mb-1">Telegram Chat ID</label>
                <input
                  type="text"
                  className={`input-field w-full ${alertErrors.telegram_chat_id ? 'border border-red-500' : ''}`}
                  value={alerts.telegram_chat_id}
                  onChange={e => { setAlerts({ ...alerts, telegram_chat_id: e.target.value }); setAlertErrors(ae => ({ ...ae, telegram_chat_id: '' })); }}
                />
                {alertErrors.telegram_chat_id && <p className="mt-1 text-xs text-red-400">{alertErrors.telegram_chat_id}</p>}
              </div>
            )}
            <button
              type="button"
              className="btn-primary mt-4"
              onClick={async () => {
                const result = AlertSettingsSchema.safeParse(alerts);
                if (!result.success) {
                  setAlertErrors(flattenZodErrors(result.error));
                  return;
                }
                setAlertErrors({});
                await updateAlertSettings(alerts!);
                showToast('Alert settings saved');
              }}
            >
              Save Settings
            </button>
          </div>
        </Panel>
      )}
    </div>
  );
}
