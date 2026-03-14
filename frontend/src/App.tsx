import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Chat from './pages/Chat';
import Admin from './pages/Admin';
import type { FeatureFlags, ContextSettings, VectorStoreStatus } from './types/api';

// Default feature flags (will be loaded from backend)
// All disabled by default as per user requirement
const defaultFeatures: FeatureFlags = {
  INPUT_SPACY_FIREWALL: false,
  BERT_FIREWALL: false,
  INPUT_PII_FIREWALL: false,
  INPUT_CONTEXT_RELEVANCE: false,
  OUTPUT_SPACY_FIREWALL: false,
  OUTPUT_PII_FIREWALL: false,
  OUTPUT_CONTEXT_RELEVANCE: false,
};

const defaultContextSettings: ContextSettings = {
  SIMILARITY_THRESHOLD: 50,
  pdf_uploaded: false,
  chunk_count: 0,
  VECTOR_STORE_PATH: '',
};

const defaultVectorStoreStatus: VectorStoreStatus = {
  is_loaded: false,
  chunk_count: 0,
  pdf_path: null,
  persist_directory: '',
};

export default function App() {
  const [features, setFeatures] = useState<FeatureFlags>(defaultFeatures);
  const [contextSettings, setContextSettings] = useState<ContextSettings>(defaultContextSettings);
  const [vectorStoreStatus, setVectorStoreStatus] = useState<VectorStoreStatus>(defaultVectorStoreStatus);

  // Load initial state from backend
  useEffect(() => {
    const loadInitialState = async () => {
      try {
        // Fetch vector store status
        const response = await fetch('/api/vectorstore-status');
        if (response.ok) {
          const status = await response.json();
          setVectorStoreStatus(status);
          setContextSettings(prev => ({
            ...prev,
            pdf_uploaded: status.is_loaded,
            chunk_count: status.chunk_count,
          }));
        }
      } catch (error) {
        console.error('Failed to load initial state:', error);
      }
    };

    loadInitialState();
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={
            <Chat features={features} />
          }
        />
        <Route
          path="/admin"
          element={
            <Admin
              features={features}
              contextSettings={contextSettings}
              vectorStoreStatus={vectorStoreStatus}
              onFeaturesChange={setFeatures}
              onVectorStoreStatusChange={setVectorStoreStatus}
              onThresholdChange={(threshold) =>
                setContextSettings((prev) => ({ ...prev, SIMILARITY_THRESHOLD: threshold }))
              }
            />
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
