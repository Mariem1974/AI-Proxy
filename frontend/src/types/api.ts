// Types for the AI-Proxy Chatbot API

export interface ChatRequest {
  message: string;
}

export interface ChatResponse {
  message?: string;
  error?: string;
}

export interface FeatureFlags {
  INPUT_SPACY_FIREWALL: boolean;
  BERT_FIREWALL: boolean;
  INPUT_PII_FIREWALL: boolean;
  INPUT_CONTEXT_RELEVANCE: boolean;
  OUTPUT_SPACY_FIREWALL: boolean;
  OUTPUT_PII_FIREWALL: boolean;
  OUTPUT_CONTEXT_RELEVANCE: boolean;
}

export interface ContextSettings {
  SIMILARITY_THRESHOLD: number;
  pdf_uploaded: boolean;
  chunk_count: number;
  VECTOR_STORE_PATH: string;
}

export interface VectorStoreStatus {
  is_loaded: boolean;
  chunk_count: number;
  pdf_path: string | null;
  persist_directory: string;
}

export interface UploadResponse {
  success: boolean;
  message?: string;
  error?: string;
  chunk_count?: number;
  vectorstore_status?: VectorStoreStatus;
}

export interface ToggleResponse {
  input_spacy?: boolean;
  bert?: boolean;
  input_pii?: boolean;
  input_context?: boolean;
  output_spacy?: boolean;
  output_pii?: boolean;
  output_context?: boolean;
  error?: string;
  vectorstore_status?: VectorStoreStatus;
}

export interface ThresholdResponse {
  threshold: number;
  error?: string;
}

export interface Message {
  id: string;
  role: 'user' | 'assistant' | 'error';
  content: string;
  timestamp: Date;
}
