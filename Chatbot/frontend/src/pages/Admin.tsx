import { useState, useRef, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import * as api from '../services/api';
import type { FeatureFlags, VectorStoreStatus } from '../types/api';

interface AdminProps {
  features: FeatureFlags;
  contextSettings: { SIMILARITY_THRESHOLD: number };
  vectorStoreStatus: VectorStoreStatus;
  onFeaturesChange: (features: FeatureFlags) => void;
  onVectorStoreStatusChange: (status: VectorStoreStatus) => void;
  onThresholdChange: (threshold: number) => void;
}

export default function Admin({
  features,
  contextSettings,
  vectorStoreStatus,
  onFeaturesChange,
  onVectorStoreStatusChange,
  onThresholdChange,
}: AdminProps) {
  const [threshold, setThreshold] = useState(contextSettings.SIMILARITY_THRESHOLD);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleToggle = async (toggleFn: () => Promise<any>, featureKey: keyof FeatureFlags) => {
    try {
      const result = await toggleFn();
      if (result.error) {
        alert(result.error);
        return;
      }
      
      // Map feature keys to API response keys
      const keyMap: Record<string, string> = {
        'INPUT_SPACY_FIREWALL': 'input_spacy',
        'BERT_FIREWALL': 'bert',
        'INPUT_PII_FIREWALL': 'input_pii',
        'INPUT_CONTEXT_RELEVANCE': 'input_context',
        'OUTPUT_SPACY_FIREWALL': 'output_spacy',
        'OUTPUT_PII_FIREWALL': 'output_pii',
        'OUTPUT_CONTEXT_RELEVANCE': 'output_context',
      };
      
      const apiKey = keyMap[featureKey] || featureKey.toLowerCase();
      onFeaturesChange({ ...features, [featureKey]: result[apiKey] });
      if (result.vectorstore_status) {
        onVectorStoreStatusChange(result.vectorstore_status);
      }
    } catch (error) {
      console.error('Toggle failed:', error);
    }
  };

  const handleFileSelect = async (e: FormEvent<HTMLInputElement>) => {
    const file = e.currentTarget.files?.[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.pdf')) {
      setUploadStatus({ message: 'Only PDF files are allowed.', type: 'error' });
      return;
    }

    setIsUploading(true);
    setUploadStatus({ message: 'Processing PDF... please wait.', type: 'success' });

    try {
      const result = await api.uploadPDF(file);
      if (result.success) {
        setUploadStatus({ message: result.message || 'PDF uploaded successfully!', type: 'success' });
        if (result.vectorstore_status) {
          onVectorStoreStatusChange(result.vectorstore_status);
        }
      } else {
        setUploadStatus({ message: result.error || 'Failed to process PDF.', type: 'error' });
      }
    } catch (error) {
      setUploadStatus({ message: error instanceof Error ? error.message : 'An error occurred', type: 'error' });
    } finally {
      setIsUploading(false);
    }
  };

  const handleSetThreshold = async () => {
    try {
      const result = await api.setThreshold(threshold);
      onThresholdChange(result.threshold);
      alert(`Threshold set to ${result.threshold}%`);
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Failed to set threshold');
    }
  };

  const inputToggles = [
    { key: 'INPUT_SPACY_FIREWALL' as const, label: 'Input spaCy Firewall', getter: () => handleToggle(api.toggleInputSpacy, 'INPUT_SPACY_FIREWALL') },
    { key: 'BERT_FIREWALL' as const, label: 'BERT Firewall', getter: () => handleToggle(api.toggleBert, 'BERT_FIREWALL') },
    { key: 'INPUT_PII_FIREWALL' as const, label: 'Input PII Firewall', getter: () => handleToggle(api.toggleInputPii, 'INPUT_PII_FIREWALL') },
    { key: 'INPUT_CONTEXT_RELEVANCE' as const, label: 'Input Similarity Check', getter: () => handleToggle(api.toggleInputContext, 'INPUT_CONTEXT_RELEVANCE') },
  ];

  const outputToggles = [
    { key: 'OUTPUT_SPACY_FIREWALL' as const, label: 'Output spaCy Firewall', getter: () => handleToggle(api.toggleOutputSpacy, 'OUTPUT_SPACY_FIREWALL') },
    { key: 'OUTPUT_PII_FIREWALL' as const, label: 'Output PII Firewall', getter: () => handleToggle(api.toggleOutputPii, 'OUTPUT_PII_FIREWALL') },
    { key: 'OUTPUT_CONTEXT_RELEVANCE' as const, label: 'Output PDF Similarity', getter: () => handleToggle(api.toggleOutputContext, 'OUTPUT_CONTEXT_RELEVANCE') },
  ];

  return (
    <div className="min-h-screen p-4 md:p-6">
      {/* Header */}
      <header className="glass rounded-2xl p-4 md:p-5 flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center">
            <span className="text-[#0b1020] font-bold text-xl">A</span>
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wide">AI-Proxy Admin</h1>
            <p className="text-sm text-[var(--color-text-secondary)]">Security Controls</p>
          </div>
        </div>
        <Link to="/" className="btn-ghost text-sm">
          Go to Chat
        </Link>
      </header>

      {/* Warning Banner */}
      <div className="mb-6 p-4 rounded-2xl border border-red-500/30 bg-red-500/10">
        <div className="flex items-center gap-3">
          <svg className="w-6 h-6 text-[var(--color-danger)] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <p className="text-[var(--color-text-primary)]">
            Toggle security features live and manage the domain PDF used by similarity checking.
          </p>
        </div>
      </div>

      {/* Toggle Cards Grid */}
      <div className="grid md:grid-cols-2 gap-6 mb-6">
        {/* Input Phase */}
        <div className="card">
          <h2 className="text-sm font-bold text-[var(--color-text-secondary)] uppercase tracking-wider mb-4">
            Input Phase
          </h2>
          <div className="space-y-3">
            {inputToggles.map((toggle) => (
              <button
                key={toggle.key}
                onClick={toggle.getter}
                className="w-full flex items-center justify-between p-4 rounded-xl bg-white/5 border border-[var(--color-border)] hover:bg-white/10 transition-all"
              >
                <span className="font-medium">{toggle.label}</span>
                <div className={`toggle-switch ${features[toggle.key] ? 'active' : ''}`} />
              </button>
            ))}
          </div>
        </div>

        {/* Output Phase */}
        <div className="card">
          <h2 className="text-sm font-bold text-[var(--color-text-secondary)] uppercase tracking-wider mb-4">
            Output Phase
          </h2>
          <div className="space-y-3">
            {outputToggles.map((toggle) => (
              <button
                key={toggle.key}
                onClick={toggle.getter}
                className="w-full flex items-center justify-between p-4 rounded-xl bg-white/5 border border-[var(--color-border)] hover:bg-white/10 transition-all"
              >
                <span className="font-medium">{toggle.label}</span>
                <div className={`toggle-switch ${features[toggle.key] ? 'active' : ''}`} />
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Domain Similarity Settings */}
      <div className="card">
        <h2 className="text-sm font-bold text-[var(--color-text-secondary)] uppercase tracking-wider mb-4">
          Domain Similarity Settings
        </h2>

        <div className="space-y-6">
          {/* PDF Upload */}
          <div>
            <label className="block mb-3">
              <strong>Upload Domain PDF</strong>
              <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                This PDF will be used for both input and output similarity checks.
              </p>
            </label>
            
            <div className="upload-area">
              <input
                ref={fileInputRef}
                type="file"
                accept=".pdf"
                onChange={handleFileSelect}
                className="hidden"
                disabled={isUploading}
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="btn-primary"
                disabled={isUploading}
              >
                {isUploading ? 'Processing...' : 'Choose PDF File'}
              </button>
              <p className="text-sm text-[var(--color-text-secondary)] mt-2">
                Supported format: PDF
              </p>
            </div>

            {uploadStatus && (
              <div className={`mt-3 p-3 rounded-xl ${uploadStatus.type === 'success' ? 'bg-green-500/15 text-green-200' : 'bg-red-500/15 text-red-200'}`}>
                {uploadStatus.message}
              </div>
            )}

            {/* Vector Store Status */}
            <div className="mt-4 p-4 rounded-xl bg-white/5 border border-[var(--color-border)]">
              <div className="flex items-center gap-2">
                {vectorStoreStatus.is_loaded ? (
                  <>
                    <svg className="w-5 h-5 text-[var(--color-success)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    <span className="text-[var(--color-success)]">
                      Vector store ready: {vectorStoreStatus.chunk_count} chunks
                    </span>
                  </>
                ) : (
                  <>
                    <svg className="w-5 h-5 text-[var(--color-danger)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                    <span className="text-[var(--color-danger)]">No vector store loaded</span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Threshold Slider */}
          <div>
            <label className="block mb-3">
              <strong>Similarity Threshold</strong>
              <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                Minimum similarity percentage required for context relevance
              </p>
            </label>
            
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="0"
                max="100"
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                className="range-slider flex-1"
              />
              <span className="text-lg font-bold text-[var(--color-primary)] min-w-[60px] text-center">
                {threshold}%
              </span>
              <button onClick={handleSetThreshold} className="btn-ghost text-sm">
                Set
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
