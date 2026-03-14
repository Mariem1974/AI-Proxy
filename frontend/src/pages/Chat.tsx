import { useState, useRef, useEffect, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { sendChatMessage, resetChat } from '../services/api';
import type { Message, FeatureFlags } from '../types/api';

interface ChatProps {
  features: FeatureFlags;
}

export default function Chat({ features }: ChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    // Add placeholder for bot response
    const botMessageId = crypto.randomUUID();
    setMessages((prev) => [
      ...prev,
      {
        id: botMessageId,
        role: 'assistant',
        content: 'Thinking...',
        timestamp: new Date(),
      },
    ]);

    try {
      const response = await sendChatMessage(userMessage.content);
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === botMessageId
            ? { ...msg, content: response, timestamp: new Date() }
            : msg
        )
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An error occurred';
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === botMessageId
            ? {
                ...msg,
                role: 'error',
                content: errorMessage,
                timestamp: new Date(),
              }
            : msg
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = async () => {
    try {
      await resetChat();
      setMessages([]);
    } catch (error) {
      console.error('Failed to reset chat:', error);
    }
  };

  const statusGroups = [
    {
      title: 'INPUT',
      items: [
        { key: 'INPUT_SPACY_FIREWALL', label: 'SPACY', value: features.INPUT_SPACY_FIREWALL },
        { key: 'BERT_FIREWALL', label: 'BERT', value: features.BERT_FIREWALL },
        { key: 'INPUT_PII_FIREWALL', label: 'PII', value: features.INPUT_PII_FIREWALL },
        { key: 'INPUT_CONTEXT_RELEVANCE', label: 'S_Prm', value: features.INPUT_CONTEXT_RELEVANCE },
      ],
    },
    {
      title: 'OUTPUT',
      items: [
        { key: 'OUTPUT_SPACY_FIREWALL', label: 'SPACY', value: features.OUTPUT_SPACY_FIREWALL },
        { key: 'OUTPUT_PII_FIREWALL', label: 'PII', value: features.OUTPUT_PII_FIREWALL },
        { key: 'OUTPUT_CONTEXT_RELEVANCE', label: 'S_Res', value: features.OUTPUT_CONTEXT_RELEVANCE },
      ],
    },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="glass rounded-2xl p-4 md:p-5 mx-4 mt-4 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-[var(--color-primary)] to-[var(--color-accent)] flex items-center justify-center">
            <span className="text-[#0b1020] font-bold text-xl">E</span>
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wide">ESSAM</h1>
            <p className="text-sm text-[var(--color-text-secondary)]">FinAssist AI</p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="flex flex-wrap items-center justify-center gap-3">
          {statusGroups.map((group) => (
            <div key={group.title} className="flex items-center gap-2 px-3 py-2 rounded-full bg-white/5 border border-[var(--color-border)]">
              <span className="text-xs font-bold text-[var(--color-primary)] px-2 tracking-wider">
                {group.title}
              </span>
              {group.items.map((item) => (
                <div key={item.key} className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-white/5">
                  <span className={`status-dot ${item.value ? 'active' : 'inactive'}`} />
                  <span className="text-xs text-[var(--color-text-secondary)]">{item.label}</span>
                </div>
              ))}
            </div>
          ))}

          <Link
            to="/admin"
            className="btn-ghost text-sm px-4 py-2"
          >
            Admin
          </Link>
        </div>
      </header>

      {/* Chat Messages */}
      <main className="flex-1 overflow-y-auto mx-4 mt-4 p-4 glass rounded-2xl" style={{ maxHeight: 'calc(100vh - 220px)' }}>
        <div className="flex flex-col gap-3">
          {messages.length === 0 && (
            <div className="text-center py-12">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-[var(--color-primary)] to-[var(--color-accent)] flex items-center justify-center">
                <svg className="w-8 h-8 text-[#0b1020]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                </svg>
              </div>
              <p className="text-[var(--color-text-secondary)]">Start a conversation with the AI Assistant</p>
              <p className="text-sm text-[var(--color-text-secondary)] mt-1">Your messages are secured by multiple security layers</p>
            </div>
          )}
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'} animate-fade-in`}
            >
              <div className={`message-bubble ${message.role}`}>
                {message.content}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>
      </main>

      {/* Input Area */}
      <footer className="mx-4 mt-4 mb-4 p-4 glass rounded-2xl">
        <form onSubmit={handleSubmit} className="flex items-center gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type your message..."
              className="input-field w-full pr-4"
              disabled={isLoading}
            />
          </div>
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            )}
          </button>
          <button
            type="button"
            onClick={handleReset}
            className="btn-ghost"
            disabled={isLoading}
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </form>
      </footer>
    </div>
  );
}
