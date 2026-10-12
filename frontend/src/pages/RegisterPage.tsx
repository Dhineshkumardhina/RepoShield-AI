import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [organization, setOrganization] = useState('');
  const [agreeTerms, setAgreeTerms] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreeTerms) {
      setErrorMessage('You must acknowledge the AppSec scanning policy.');
      return;
    }

    setErrorMessage(null);
    setIsLoading(true);

    try {
      const res = await register(fullName, email, organization);
      if (res.success) {
        navigate('/dashboard');
      } else {
        setErrorMessage(res.error || 'Failed to register organization.');
      }
    } catch {
      setErrorMessage('An unexpected error occurred during workspace creation.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <Link to="/" className="inline-flex items-center gap-2 mb-4">
          <div className="w-9 h-9 rounded-md bg-slate-900 flex items-center justify-center text-white">
            <span className="material-symbols-outlined text-xl">shield</span>
          </div>
          <span className="font-semibold text-xl text-slate-900 tracking-tight">
            RepoShield AI
          </span>
        </Link>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">
          Register AppSec Workspace
        </h2>
        <p className="mt-1 text-xs text-slate-500 max-w-sm mx-auto">
          Configure automated fix verification for your repositories.
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-6 sm:px-10 shadow-sm rounded-2xl border border-slate-200">
          {errorMessage && (
            <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-2">
              <span className="material-symbols-outlined text-base text-red-600">error</span>
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                Full Name
              </label>
              <input
                id="name"
                type="text"
                required
                value={fullName}
                onChange={e => setFullName(e.target.value)}
                className="mt-1 w-full px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all"
                placeholder="Dr. Elena Rostova"
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                Work Email
              </label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="mt-1 w-full px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all font-mono-md"
                placeholder="elena@enterprise.org"
              />
            </div>

            <div>
              <label htmlFor="org" className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                Organization / Team Name
              </label>
              <input
                id="org"
                type="text"
                required
                value={organization}
                onChange={e => setOrganization(e.target.value)}
                className="mt-1 w-full px-3.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all"
                placeholder="Xerova Cloud Engineering"
              />
            </div>

            <div className="pt-2">
              <label className="flex items-start gap-2.5 text-xs text-slate-600 cursor-pointer">
                <input
                  type="checkbox"
                  checked={agreeTerms}
                  onChange={e => setAgreeTerms(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
                <span>
                  I authorize RepoShield AI to perform static analysis and execute isolated regression gates across designated repositories.
                </span>
              </label>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-4 py-2.5 px-4 bg-slate-900 hover:bg-slate-800 text-white font-medium text-sm rounded-md shadow-2xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isLoading && <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>}
              <span>{isLoading ? 'Creating Workspace...' : 'Initialize Workspace'}</span>
            </button>
          </form>

          <div className="mt-6 text-center text-xs text-slate-500 border-t border-slate-200 pt-4">
            Already have an active account?{' '}
            <Link to="/login" className="font-semibold text-blue-600 hover:underline">
              Sign In to Console
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
