import type {
  AuthResponse, FeatureFlags, ToggleResponse, ThresholdResponse,
  VectorStoreStatus, UploadResponse, DocumentUploadResponse,
  SecurityLog, AlertSettings, User,
  AlertOverTime, TopThreat, TopBlockedUser, SeverityBreakdown,
} from '../types/api';
import { AuthResponseSchema, FeatureFlagsSchema } from '../lib/schemas';

const BASE = '/api';

let _token: string | null = localStorage.getItem('ai_proxy_token');

export function setToken(t: string | null) {
  _token = t;
}

function adminHeaders(): Record<string, string> {
  return _token ? { Authorization: `Bearer ${_token}` } : {};
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const txt = await res.text();
    try { const j = JSON.parse(txt); throw new Error(j.message || j.error || txt); }
    catch (e) { if (e instanceof Error && e.message !== txt) throw e; throw new Error(txt); }
  }
  const txt = await res.text();
  try { return JSON.parse(txt); } catch { return txt as T; }
}

// ── Auth ──────────────────────────────────────────────────────────────────────
export async function login(username: string, password: string): Promise<AuthResponse> {
  const data = await handle<AuthResponse>(await fetch(`${BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }));
  return AuthResponseSchema.parse(data) as AuthResponse;
}

export async function register(username: string, password: string, email: string): Promise<AuthResponse> {
  const data = await handle<AuthResponse>(await fetch(`${BASE}/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, email }),
  }));
  return AuthResponseSchema.parse(data) as AuthResponse;
}

// ── Chat ──────────────────────────────────────────────────────────────────────
export async function sendChatMessage(message: string, userId?: number): Promise<string> {
  const res = await fetch(`${BASE}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, user_id: userId }),
  });
  if (!res.ok) {
    const txt = await res.text();
    try { const j = JSON.parse(txt); throw new Error(j.message || j.error || txt); }
    catch (e) { if (e instanceof Error && e.message !== txt) throw e; throw new Error(txt); }
  }
  return res.text();
}

export async function resetChat(userId?: number): Promise<void> {
  const qs = userId ? `?user_id=${userId}` : '';
  await fetch(`${BASE}/reset${qs}`, { method: 'POST' });
}

// ── Document upload ───────────────────────────────────────────────────────────
export async function uploadDocument(file: File, userId?: number): Promise<DocumentUploadResponse> {
  const fd = new FormData();
  fd.append('file', file);
  if (userId) fd.append('user_id', String(userId));
  return handle<DocumentUploadResponse>(await fetch(`${BASE}/upload-document`, { method: 'POST', body: fd }));
}

// ── Feature flags ─────────────────────────────────────────────────────────────
export async function getFeatures(): Promise<FeatureFlags> {
  const data = await handle<FeatureFlags>(await fetch(`${BASE}/features`));
  return FeatureFlagsSchema.parse(data) as FeatureFlags;
}

// ── Input toggles ─────────────────────────────────────────────────────────────
export async function toggleInputUnicode():  Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-unicode`,  { method: 'POST', headers: adminHeaders() }));
}
export async function toggleInputSpacy():   Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-spacy`,   { method: 'POST', headers: adminHeaders() }));
}
export async function toggleBert():         Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/bert`,          { method: 'POST', headers: adminHeaders() }));
}
export async function toggleInputPii():     Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-pii`,     { method: 'POST', headers: adminHeaders() }));
}
export async function toggleInputContext(): Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-context`, { method: 'POST', headers: adminHeaders() }));
}

// ── Output toggles ────────────────────────────────────────────────────────────
export async function toggleOutputSpacy():   Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/output-spacy`,   { method: 'POST', headers: adminHeaders() }));
}
export async function toggleOutputPii():     Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/output-pii`,     { method: 'POST', headers: adminHeaders() }));
}
export async function toggleOutputContext(): Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/output-context`, { method: 'POST', headers: adminHeaders() }));
}
export async function toggleDocumentProcessing(): Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/document-processing`, { method: 'POST', headers: adminHeaders() }));
}

// ── BERT model ────────────────────────────────────────────────────────────────
export async function setBertModel(model: 'modernbert' | 'distilbert'): Promise<{ active_model: string }> {
  return handle<{ active_model: string }>(await fetch(`${BASE}/bert/model`, {
    method: 'POST',
    headers: { ...adminHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ model }),
  }));
}
export async function getBertModel(): Promise<{ active_model: string; loaded_model: string }> {
  return handle<{ active_model: string; loaded_model: string }>(await fetch(`${BASE}/bert/model`));
}

// ── Context PDF ───────────────────────────────────────────────────────────────
export async function uploadContextPdf(file: File): Promise<UploadResponse> {
  const fd = new FormData(); fd.append('file', file);
  return handle<UploadResponse>(await fetch(`${BASE}/upload-context-pdf`, { method: 'POST', headers: adminHeaders(), body: fd }));
}
export async function setThreshold(threshold: number): Promise<ThresholdResponse> {
  return handle<ThresholdResponse>(await fetch(`${BASE}/set-threshold`, {
    method: 'POST',
    headers: { ...adminHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ threshold }),
  }));
}
export async function getVectorstoreStatus(): Promise<VectorStoreStatus> {
  return handle<VectorStoreStatus>(await fetch(`${BASE}/vectorstore-status`));
}

// ── Users ─────────────────────────────────────────────────────────────────────
export async function getUsers(): Promise<{ users: User[] }> {
  return handle<{ users: User[] }>(await fetch(`${BASE}/users`, { headers: adminHeaders() }));
}
export async function unblockUser(userId: number): Promise<void> {
  await fetch(`${BASE}/users/unblock/${userId}`, { method: 'POST', headers: adminHeaders() });
}

// ── Alert settings ────────────────────────────────────────────────────────────
export async function getAlertSettings(): Promise<AlertSettings> {
  return handle<AlertSettings>(await fetch(`${BASE}/alert-settings`, { headers: adminHeaders() }));
}
export async function updateAlertSettings(s: AlertSettings): Promise<AlertSettings> {
  return handle<AlertSettings>(await fetch(`${BASE}/alert-settings`, {
    method: 'POST',
    headers: { ...adminHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(s),
  }));
}

// ── Security logs ─────────────────────────────────────────────────────────────
export async function getSecurityLogs(limit = 100): Promise<{ logs: SecurityLog[] }> {
  return handle<{ logs: SecurityLog[] }>(await fetch(`${BASE}/security-logs?limit=${limit}`, { headers: adminHeaders() }));
}

export async function downloadSecurityLogs(): Promise<void> {
  const res = await fetch(`${BASE}/security-logs/download`, { headers: adminHeaders() });
  if (!res.ok) throw new Error(`Download failed: ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security_logs.json';
  a.click();
  URL.revokeObjectURL(url);
}

// ── Analytics ─────────────────────────────────────────────────────────────────

export async function getAlertsOverTime(hours = 24): Promise<{ data: AlertOverTime[] }> {
  return handle<{ data: AlertOverTime[] }>(
    await fetch(`${BASE}/analytics/alerts-over-time?hours=${hours}`, { headers: adminHeaders() })
  );
}

export async function getTopThreats(): Promise<{ data: TopThreat[] }> {
  return handle<{ data: TopThreat[] }>(
    await fetch(`${BASE}/analytics/top-threats`, { headers: adminHeaders() })
  );
}

export async function getTopBlockedUsers(): Promise<{ data: TopBlockedUser[] }> {
  return handle<{ data: TopBlockedUser[] }>(
    await fetch(`${BASE}/analytics/top-blocked-users`, { headers: adminHeaders() })
  );
}

export async function getSeverityBreakdown(): Promise<{ data: SeverityBreakdown[] }> {
  return handle<{ data: SeverityBreakdown[] }>(
    await fetch(`${BASE}/analytics/severity-breakdown`, { headers: adminHeaders() })
  );
}
