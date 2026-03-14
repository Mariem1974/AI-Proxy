// API Service for communicating with the FastAPI backend
import type {
  VectorStoreStatus,
  UploadResponse,
  ToggleResponse,
  ThresholdResponse,
} from '../types/api';

const API_BASE = '/api';

// Helper function to handle responses
async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    try {
      const json = JSON.parse(text);
      throw new Error(json.message || json.error || text);
    } catch {
      throw new Error(text);
    }
  }
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return text as T;
  }
}

// Chat API
export async function sendChatMessage(message: string): Promise<string> {
  const response = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ message }),
  });

  if (!response.ok) {
    const text = await response.text();
    try {
      const json = JSON.parse(text);
      throw new Error(json.message || json.error || text);
    } catch {
      throw new Error(text);
    }
  }

  return response.text();
}

export async function resetChat(): Promise<void> {
  await fetch(`${API_BASE}/reset`, {
    method: 'POST',
  });
}

// Feature Toggles - Input
export async function toggleInputSpacy(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/input-spacy`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

export async function toggleBert(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/bert`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

export async function toggleInputPii(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/input-pii`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

export async function toggleInputContext(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/input-context`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

// Feature Toggles - Output
export async function toggleOutputSpacy(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/output-spacy`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

export async function toggleOutputPii(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/output-pii`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

export async function toggleOutputContext(): Promise<ToggleResponse> {
  const response = await fetch(`${API_BASE}/toggle/output-context`, {
    method: 'POST',
  });
  return handleResponse<ToggleResponse>(response);
}

// Settings
export async function setThreshold(threshold: number): Promise<ThresholdResponse> {
  const formData = new FormData();
  formData.append('threshold', threshold.toString());

  const response = await fetch(`${API_BASE}/set-threshold`, {
    method: 'POST',
    body: formData,
  });
  return handleResponse<ThresholdResponse>(response);
}

// Vector Store
export async function uploadPDF(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/upload-context-pdf`, {
    method: 'POST',
    body: formData,
  });
  return handleResponse<UploadResponse>(response);
}

export async function getVectorStoreStatus(): Promise<VectorStoreStatus> {
  const response = await fetch(`${API_BASE}/vectorstore-status`);
  return handleResponse<VectorStoreStatus>(response);
}
