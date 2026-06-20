import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Chat from './pages/Chat';
import Admin from './pages/Admin';
import Login from './pages/Login';
import Register from './pages/Register';
import { getFeatures } from './services/api';
import type { FeatureFlags, User } from './types/api';

const defaultFeatures: FeatureFlags = {
  INPUT_UNICODE_FIREWALL:   false,
  INPUT_SPACY_FIREWALL:     false,
  BERT_FIREWALL:            false,
  INPUT_PII_FIREWALL:       false,
  INPUT_CONTEXT_RELEVANCE:  false,
  OUTPUT_SPACY_FIREWALL:    false,
  OUTPUT_PII_FIREWALL:      false,
  OUTPUT_CONTEXT_RELEVANCE: false,
  DOCUMENT_PROCESSING:      false,
  bert_settings: {
    SAFE_THRESHOLD:   0.30,
    MEDIUM_THRESHOLD: 0.70,
    MAX_REPHRASE:     3,
    ACTIVE_MODEL:     'modernbert',
  },
};

export default function App() {
  const [features, setFeatures] = useState<FeatureFlags>(defaultFeatures);

  const [user, setUser] = useState<User | null>(() => {
    try { return JSON.parse(localStorage.getItem('ai_proxy_user') || 'null'); }
    catch { return null; }
  });
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem('ai_proxy_token')
  );

  const handleLogin = (loggedInUser: User, authToken: string) => {
    setUser(loggedInUser);
    setToken(authToken);
    localStorage.setItem('ai_proxy_user', JSON.stringify(loggedInUser));
    localStorage.setItem('ai_proxy_token', authToken);
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('ai_proxy_user');
    localStorage.removeItem('ai_proxy_token');
  };

  useEffect(() => {
    if (!user) return;
    getFeatures().then(setFeatures).catch(console.error);
  }, [user]);

  const isAuthenticated = !!user && !!token;
  const isAdmin = user?.role === 'admin';

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"
          element={isAuthenticated
            ? <Navigate to={isAdmin ? '/admin' : '/'} replace />
            : <Login onLogin={handleLogin} />}
        />
        <Route path="/register"
          element={isAuthenticated
            ? <Navigate to="/" replace />
            : <Register onLogin={handleLogin} />}
        />
        <Route path="/"
          element={isAuthenticated
            ? <Chat features={features} user={user!} onLogout={handleLogout} />
            : <Navigate to="/login" replace />}
        />
        <Route path="/admin"
          element={!isAuthenticated
            ? <Navigate to="/login" replace />
            : !isAdmin
              ? <Navigate to="/" replace />
              : <Admin
                  features={features}
                  onFeaturesChange={setFeatures}
                  user={user!}
                  onLogout={handleLogout}
                />}
        />
      </Routes>
    </BrowserRouter>
  );
}
