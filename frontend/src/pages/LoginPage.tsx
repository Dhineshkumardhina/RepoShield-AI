import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState('dev@xerova.com');
  const [password, setPassword] = useState('XerovaDevPass2026!');
  const [role, setRole] = useState<'SecOps Lead' | 'Security Analyst' | 'Staff Engineer'>('SecOps Lead');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsLoading(true);

    try {
      const res = await login(email, password, role);
      if (res.success) {
        navigate('/dashboard');
      } else {
        setErrorMessage(res.error || 'Failed to authenticate.');
      }
    } catch {
      setErrorMessage('An unexpected error occurred during authentication.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUseDemoAccount = (demoEmail: string, demoRole: 'SecOps Lead' | 'Security Analyst' | 'Staff Engineer') => {
    setEmail(demoEmail);
    setPassword('XerovaDevPass2026!');
    setRole(demoRole);
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <Link to="/" className="inline-flex items-center gap-2 mb-4">
          <div className="w-8 h-8 rounded-md bg-slate-900 flex items-center justify-center text-white">
            <span className="material-symbols-outlined text-xl">shield</span>
          </div>
          <span className="font-semibold text-lg text-slate-900 tracking-tight">
            RepoShield AI
          </span>
        </Link>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">
          Enterprise Security Sign-In
        </h2>
        <p className="mt-1 text-xs text-slate-500 max-w-sm mx-auto">
          Sign in with your Xerova IAM SSO or operator access credentials.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-6 px-6 sm:px-8 shadow-2xs rounded-lg border border-slate-200">
          {errorMessage && (
            <div className="mb-4 p-3 rounded-md bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-2">
              <span className="material-symbols-outlined text-base text-red-600">error</span>
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-xs font-medium text-slate-700">
                Corporate Email
              </label>
              <div className="mt-1">
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-md text-xs text-slate-900 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 transition-all font-mono"
                  placeholder="analyst@xerova.com"
                />
              </div>
            </div>

            <div>
              <label htmlFor="role" className="block text-xs font-medium text-slate-700">
                Authorized Role
              </label>
              <select
                id="role"
                value={role}
                onChange={e => setRole(e.target.value as any)}
                className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-md text-xs text-slate-900 focus:outline-hidden focus:border-slate-400 transition-all"
              >
                <option value="SecOps Lead">SecOps Lead (Approval &amp; Auto-Merge)</option>
                <option value="Security Analyst">Security Analyst (Triage &amp; Verify)</option>
                <option value="Staff Engineer">Staff Engineer (View &amp; Sandbox Inspect)</option>
              </select>
            </div>

            <div>
              <label htmlFor="pass" className="block text-xs font-medium text-slate-700">
                SSO Password / Token
              </label>
              <input
                id="pass"
                type="password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-md text-xs text-slate-900 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 transition-all font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 py-2 px-4 bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs rounded-md shadow-2xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isLoading && <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>}
              <span>{isLoading ? 'Verifying Session...' : 'Authenticate to Console'}</span>
            </button>
          </form>

          {/* Quick Demo Credentials */}
          <div className="mt-5 pt-4 border-t border-slate-100">
            <span className="font-mono text-[10px] text-slate-400 uppercase tracking-wider block text-center mb-2 font-medium">
              Quick Role Presets
            </span>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => handleUseDemoAccount('dev@xerova.com', 'SecOps Lead')}
                className="p-2 rounded border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors"
              >
                <span className="font-semibold text-xs text-slate-800 block truncate">Xerova Dev Lead</span>
                <span className="text-[10px] text-slate-500 font-mono">dev@xerova.com</span>
              </button>
              <button
                type="button"
                onClick={() => handleUseDemoAccount('marcus.vance@xerova.com', 'Security Analyst')}
                className="p-2 rounded border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors"
              >
                <span className="font-semibold text-xs text-slate-800 block truncate">M. Vance</span>
                <span className="text-[10px] text-slate-500 font-mono">Security Analyst</span>
              </button>
            </div>
          </div>

          <div className="mt-5 text-center text-xs text-slate-500">
            Don't have an enterprise workspace yet?{' '}
            <Link to="/register" className="font-medium text-slate-900 hover:underline">
              Register Organization
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
