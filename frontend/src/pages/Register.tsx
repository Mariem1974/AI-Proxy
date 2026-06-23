import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { register, login } from '../services/api';
import { RegisterSchema, flattenZodErrors } from '../lib/schemas';

interface RegisterProps {
  onLogin: (user: any, token: string) => void;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
}

export default function Register({ onLogin, theme, onToggleTheme }: RegisterProps) {
  const [username, setUsername]           = useState('');
  const [email, setEmail]                 = useState('');
  const [password, setPassword]           = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fieldErrors, setFieldErrors]     = useState<Record<string, string>>({});
  const [serverError, setServerError]     = useState('');
  const [isLoading, setIsLoading]         = useState(false);
  const navigate = useNavigate();

  const clearField = (key: string) =>
    setFieldErrors(fe => ({ ...fe, [key]: '' }));

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setServerError('');

    const result = RegisterSchema.safeParse({ username, email, password, confirmPassword });
    if (!result.success) {
      setFieldErrors(flattenZodErrors(result.error));
      return;
    }
    setFieldErrors({});
    setIsLoading(true);

    try {
      await register(username, password, email);
      const loginData = await login(username, password);
      onLogin(loginData.user, loginData.token);
      navigate('/');
    } catch (err) {
      setServerError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ position: 'relative' }}>
      {onToggleTheme && (
        <button type="button" className="btn-theme" onClick={onToggleTheme} title="Toggle theme"
          style={{ position: 'absolute', top: 20, right: 20 }}>
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
      )}
      <div className="card w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl flex items-center justify-center"
            style={{ background: 'linear-gradient(135deg, var(--color-primary), var(--color-accent))', boxShadow: 'var(--shadow-primary)' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <polyline points="9 12 11 14 15 10" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold" style={{ letterSpacing: '-0.02em' }}>Create Account</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">Join Security Booster — Finance Security</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          {serverError && (
            <div className="p-3 rounded-xl bg-red-500/15 text-red-200 text-sm">
              {serverError}
            </div>
          )}

          <div>
            <label className="block mb-2 text-sm font-medium">Username</label>
            <input
              type="text"
              value={username}
              onChange={e => { setUsername(e.target.value); clearField('username'); }}
              className={`input-field w-full ${fieldErrors.username ? 'border border-red-500' : ''}`}
              placeholder="Choose username (3–50 chars, letters/numbers/_)"
              autoComplete="username"
            />
            {fieldErrors.username && <p className="mt-1 text-xs text-red-400">{fieldErrors.username}</p>}
          </div>

          <div>
            <label className="block mb-2 text-sm font-medium">Email</label>
            <input
              type="email"
              value={email}
              onChange={e => { setEmail(e.target.value); clearField('email'); }}
              className={`input-field w-full ${fieldErrors.email ? 'border border-red-500' : ''}`}
              placeholder="Enter email"
              autoComplete="email"
            />
            {fieldErrors.email && <p className="mt-1 text-xs text-red-400">{fieldErrors.email}</p>}
          </div>

          <div>
            <label className="block mb-2 text-sm font-medium">Password</label>
            <input
              type="password"
              value={password}
              onChange={e => { setPassword(e.target.value); clearField('password'); }}
              className={`input-field w-full ${fieldErrors.password ? 'border border-red-500' : ''}`}
              placeholder="At least 6 characters"
              autoComplete="new-password"
            />
            {fieldErrors.password && <p className="mt-1 text-xs text-red-400">{fieldErrors.password}</p>}
          </div>

          <div>
            <label className="block mb-2 text-sm font-medium">Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={e => { setConfirmPassword(e.target.value); clearField('confirmPassword'); }}
              className={`input-field w-full ${fieldErrors.confirmPassword ? 'border border-red-500' : ''}`}
              placeholder="Repeat password"
              autoComplete="new-password"
            />
            {fieldErrors.confirmPassword && <p className="mt-1 text-xs text-red-400">{fieldErrors.confirmPassword}</p>}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="btn-primary w-full disabled:opacity-50"
          >
            {isLoading ? 'Creating account…' : 'Sign Up'}
          </button>
        </form>

        <p className="text-center mt-6 text-[var(--color-text-secondary)]">
          Already have an account?{' '}
          <Link to="/login" className="text-[var(--color-primary)] hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
