export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_blocked: boolean;
  failed_attempts: number;
  temp_blocks: number;
  created_at?: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface BertSettings {
  SAFE_THRESHOLD:   number;
  MEDIUM_THRESHOLD: number;
  MAX_REPHRASE:     number;
  ACTIVE_MODEL:     'modernbert' | 'distilbert';
}

export interface FeatureFlags {
  INPUT_UNICODE_FIREWALL:   boolean;
  INPUT_SPACY_FIREWALL:     boolean;
  BERT_FIREWALL:            boolean;
  INPUT_PII_FIREWALL:       boolean;
  INPUT_CONTEXT_RELEVANCE:  boolean;
  OUTPUT_SPACY_FIREWALL:    boolean;
  OUTPUT_PII_FIREWALL:      boolean;
  OUTPUT_CONTEXT_RELEVANCE: boolean;
  DOCUMENT_PROCESSING:      boolean;
  bert_settings:            BertSettings;
}

export interface ToggleResponse {
  [key: string]: boolean | object;
}

export interface ThresholdResponse {
  threshold: number;
}

export interface VectorStoreStatus {
  is_loaded:          boolean;
  chunk_count:        number;
  persist_directory:  string;
  pdf_path?:          string | null;
}

export interface UploadResponse {
  success:             boolean;
  message?:            string;
  chunk_count?:        number;
  vectorstore_status?: VectorStoreStatus;
  error?:              string;
}

export interface DocumentUploadResponse {
  success:      boolean;
  safe_context?: string;
  stats?: {
    total_chunks:    number;
    malicious_chunks: number;
    safe_chunks:     number;
    file_type:       string;
    file_size_mb:    number;
  };
  message?: string;
  error?:   string;
}

export interface SecurityLog {
  id:             number;
  timestamp:      string;
  user_id:        number;
  username:       string;
  prompt:         string;
  detection_type: string;
  action:         string;
  severity:       string;
  details?:       Record<string, unknown>;
}

export interface AlertSettings {
  max_attempts_to_block:  number;
  warning_window_minutes: number;
  block_duration_minutes: number;
  max_temp_blocks:        number;
  enable_email:           boolean;
  enable_telegram:        boolean;
  email_address:          string;
  telegram_chat_id:       string;
}

// kept for backward compatibility with App.tsx
export interface ContextSettings {
  SIMILARITY_THRESHOLD: number;
  pdf_uploaded:         boolean;
  chunk_count:          number;
  VECTOR_STORE_PATH:    string;
}
