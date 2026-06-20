import type {
  AuthResponse, FeatureFlags, ToggleResponse, ThresholdResponse,
  VectorStoreStatus, UploadResponse, DocumentUploadResponse,
  SecurityLog, AlertSettings, User,
} from '../types/api';

const BASE = '/api';

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
  return handle<AuthResponse>(await fetch(`${BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }));
}

export async function register(username: string, password: string, email: string): Promise<AuthResponse> {
  return handle<AuthResponse>(await fetch(`${BASE}/auth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, email }),
  }));
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

export async function resetChat(): Promise<void> {
  await fetch(`${BASE}/reset`, { method: 'POST' });
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
  return handle<FeatureFlags>(await fetch(`${BASE}/features`));
}

// ── Input toggles ─────────────────────────────────────────────────────────────
export async function toggleInputUnicode():  Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-unicode`,  { method: 'POST' }));
}
export async function toggleInputSpacy():   Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-spacy`,   { method: 'POST' }));
}
export async function toggleBert():         Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/bert`,          { method: 'POST' }));
}
export async function toggleInputPii():     Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-pii`,     { method: 'POST' }));
}
export async function toggleInputContext(): Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/input-context`, { method: 'POST' }));
}

// ── Output toggles ────────────────────────────────────────────────────────────
export async function toggleOutputSpacy():   Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/output-spacy`,   { method: 'POST' }));
}
export async function toggleOutputPii():     Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/output-pii`,     { method: 'POST' }));
}
export async function toggleOutputContext(): Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/output-context`, { method: 'POST' }));
}
export async function toggleDocumentProcessing(): Promise<ToggleResponse> {
  return handle<ToggleResponse>(await fetch(`${BASE}/toggle/document-processing`, { method: 'POST' }));
}

// ── BERT model ────────────────────────────────────────────────────────────────
export async function setBertModel(model: 'modernbert' | 'distilbert'): Promise<{ active_model: string }> {
  const fd = new FormData(); fd.append('model', model);
  return handle<{ active_model: string }>(await fetch(`${BASE}/bert/model`, { method: 'POST', body: fd }));
}
export async function getBertModel(): Promise<{ active_model: string; loaded_model: string }> {
  return handle<{ active_model: string; loaded_model: string }>(await fetch(`${BASE}/bert/model`));
}

// ── Context PDF ───────────────────────────────────────────────────────────────
export async function uploadContextPdf(file: File): Promise<UploadResponse> {
  const fd = new FormData(); fd.append('file', file);
  return handle<UploadResponse>(await fetch(`${BASE}/upload-context-pdf`, { method: 'POST', body: fd }));
}
export async function setThreshold(threshold: number): Promise<ThresholdResponse> {
  const fd = new FormData(); fd.append('threshold', String(threshold));
  return handle<ThresholdResponse>(await fetch(`${BASE}/set-threshold`, { method: 'POST', body: fd }));
}
export async function getVectorstoreStatus(): Promise<VectorStoreStatus> {
  return handle<VectorStoreStatus>(await fetch(`${BASE}/vectorstore-status`));
}

// ── Users ─────────────────────────────────────────────────────────────────────
export async function getUsers(): Promise<{ users: User[] }> {
  return handle<{ users: User[] }>(await fetch(`${BASE}/users`));
}
export async function unblockUser(userId: number): Promise<void> {
  await fetch(`${BASE}/users/unblock/${userId}`, { method: 'POST' });
}

// ── Alert settings ────────────────────────────────────────────────────────────
export async function getAlertSettings(): Promise<AlertSettings> {
  return handle<AlertSettings>(await fetch(`${BASE}/alert-settings`));
}
export async function updateAlertSettings(s: AlertSettings): Promise<AlertSettings> {
  const fd = new FormData();
  Object.entries(s).forEach(([k, v]) => fd.append(k, String(v)));
  return handle<AlertSettings>(await fetch(`${BASE}/alert-settings`, { method: 'POST', body: fd }));
}

// ── Security logs ─────────────────────────────────────────────────────────────
export async function getSecurityLogs(limit = 100): Promise<{ logs: SecurityLog[] }> {
  return handle<{ logs: SecurityLog[] }>(await fetch(`${BASE}/security-logs?limit=${limit}`));
}
export function getLogsDownloadUrl(): string {
  return `${BASE}/security-logs/download`;
}
