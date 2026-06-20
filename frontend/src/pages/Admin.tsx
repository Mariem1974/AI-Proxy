import { useState, useEffect } from 'react';
import type { FeatureFlags, AlertSettings, SecurityLog, User } from '../types/api';
import {
  getFeatures,
  toggleInputUnicode, toggleInputSpacy, toggleBert, toggleInputPii, toggleInputContext,
  toggleOutputSpacy, toggleOutputPii, toggleOutputContext, toggleDocumentProcessing,
  setBertModel, getBertModel,
  uploadContextPdf, setThreshold, getVectorstoreStatus,
  getUsers, unblockUser,
  getAlertSettings, updateAlertSettings,
  getSecurityLogs, getLogsDownloadUrl,
} from '../services/api';

interface Props {
  features:         FeatureFlags;
  onFeaturesChange: (f: FeatureFlags) => void;
  user:             User;
  onLogout:         () => void;
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
export default function Admin({ features, onFeaturesChange, user, onLogout }: Props) {
  const [tab, setTab] = useState<'pipeline' | 'context' | 'logs' | 'users' | 'alerts'>('pipeline');
  const [bertModel, setBertModelState] = useState('distilbert');
  const [vsStatus, setVsStatus] = useState<{ is_loaded: boolean; chunk_count: number } | null>(null);
  const [threshold, setThresholdVal] = useState(50);
  const [logs, setLogs]   = useState<SecurityLog[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [alerts, setAlerts] = useState<AlertSettings | null>(null);
  const [logFilter, setLogFilter] = useState('');
  const [toast, setToast] = useState('');

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

  const tabs = ['pipeline', 'context', 'logs', 'users', 'alerts'] as const;

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 1200, margin: '0 auto', padding: 24, color: 'var(--color-text)', background: 'var(--color-bg)', minHeight: '100vh' }}>
      {toast && (
        <div style={{ position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)', background: 'var(--color-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text)', padding: '10px 20px', borderRadius: 12, fontSize: 14, zIndex: 1000, boxShadow: '0 4px 20px rgba(0,0,0,.4)' }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>
            AI-Proxy Admin
            <span style={{ marginLeft: 8, background: 'var(--color-primary)', color: '#0b1020', borderRadius: 6, padding: '2px 8px', fontSize: 12 }}>v2</span>
          </h1>
          <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 2 }}>Logged in as {user.username}</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <a href="/" className="btn-secondary" style={{ textDecoration: 'none' }}>Chat</a>
          <button className="btn-secondary" style={{ color: '#ef4444', borderColor: '#ef4444' }} onClick={onLogout}>Logout</button>
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
            <a href={getLogsDownloadUrl()} download="security_logs.json" className="btn-secondary">
              ⬇ Download JSON
            </a>
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
                  value={(alerts as unknown as Record<string, number>)[key]}
                  onChange={e => setAlerts({ ...alerts, [key]: +e.target.value })} />
              </div>
            ))}
            <hr style={{ border: 'none', borderTop: '1px solid var(--color-border)', margin: '16px 0' }} />
            <div className="toggle-row" onClick={() => setAlerts({ ...alerts, enable_email: !alerts.enable_email })}>
              <div className="toggle-info"><span className="toggle-label">Email Alerts (Gmail SMTP)</span></div>
              <div className={`toggle-switch ${alerts.enable_email ? 'on' : 'off'}`}><div className="toggle-thumb" /></div>
            </div>
            {alerts.enable_email && (
              <div style={{ marginBottom: 14, marginTop: 10 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 6 }}>Alert Email</label>
                <input type="email" className="input-field" value={alerts.email_address}
                  onChange={e => setAlerts({ ...alerts, email_address: e.target.value })} />
              </div>
            )}
            <div className="toggle-row" onClick={() => setAlerts({ ...alerts, enable_telegram: !alerts.enable_telegram })}>
              <div className="toggle-info"><span className="toggle-label">Telegram Alerts</span></div>
              <div className={`toggle-switch ${alerts.enable_telegram ? 'on' : 'off'}`}><div className="toggle-thumb" /></div>
            </div>
            {alerts.enable_telegram && (
              <div style={{ marginBottom: 14, marginTop: 10 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 6 }}>Telegram Chat ID</label>
                <input type="text" className="input-field" value={alerts.telegram_chat_id}
                  onChange={e => setAlerts({ ...alerts, telegram_chat_id: e.target.value })} />
              </div>
            )}
            <button className="btn-primary" style={{ marginTop: 16 }}
              onClick={async () => { await updateAlertSettings(alerts); showToast('Alert settings saved'); }}>
              Save Settings
            </button>
          </div>
        </Panel>
      )}
    </div>
  );
}
