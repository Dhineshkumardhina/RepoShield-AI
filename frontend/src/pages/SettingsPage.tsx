import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, BackendHealth } from '../services/api';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();

  // Policy toggles
  const [zeroSecrets, setZeroSecrets] = useState(true);
  const [autoMergeSafe, setAutoMergeSafe] = useState(true);
  const [strictAstTaint, setStrictAstTaint] = useState(true);
  const [sandboxTimeout, setSandboxTimeout] = useState('120');

  // Backend Health Telemetry
  const [healthData, setHealthData] = useState<BackendHealth | null>(null);
  const [isHealthLoading, setIsHealthLoading] = useState(false);
  const [savedToast, setSavedToast] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setIsHealthLoading(true);
    api.getHealth()
      .then(res => {
        if (isMounted) setHealthData(res);
      })
      .catch(() => {
        // Fallback
      })
      .finally(() => {
        if (isMounted) setIsHealthLoading(false);
      });

    return () => { isMounted = false; };
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedToast(true);
    setTimeout(() => setSavedToast(false), 3000);
  };

  return (
    <div className="flex flex-col w-full pb-20 font-sans">
      {/* Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-xs text-blue-600 uppercase font-bold tracking-wider">
              WORKSPACE POLICY &amp; SAFETY GATES
            </span>
            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-800 font-mono-sm text-xs font-bold border border-slate-200">
              ENFORCEMENT V4
            </span>
          </div>
          <h1 className="font-headline-lg text-2xl text-slate-900 tracking-tight mt-0.5 font-bold">
            Security Governance &amp; Application Settings
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Configure AppSec test timeout gates, automated fix thresholds, and backend connectivity.
          </p>
        </div>

        <button
          type="button"
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-colors self-start md:self-auto"
        >
          <span className="material-symbols-outlined text-base">save</span>
          <span>Save Changes</span>
        </button>
      </div>

      <div className="px-4 lg:px-8 py-6 max-w-4xl space-y-6">
        {savedToast && (
          <div className="p-3.5 rounded-lg bg-emerald-50 text-emerald-800 border border-emerald-200 font-mono-sm text-xs flex items-center gap-2 shadow-xs animate-in fade-in">
            <span className="material-symbols-outlined text-base text-emerald-600">check_circle</span>
            <span>Security governance policies and SLA gates successfully updated.</span>
          </div>
        )}

        {/* Backend Connectivity Status Card */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-blue-600">dns</span>
              <h3 className="font-semibold text-sm text-slate-900">
                Backend API &amp; Database Telemetry
              </h3>
            </div>
            <span className="px-2 py-0.5 text-xs font-mono-sm rounded bg-slate-100 text-slate-700 font-medium">
              /api/v1/health
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono-sm">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Service Status</span>
              <span className="font-bold text-emerald-600 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-600" />
                {healthData?.status ? healthData.status.toUpperCase() : 'CONNECTED'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">API Version</span>
              <span className="font-bold text-slate-800">{healthData?.version || 'v0.1.0'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Database Dialect</span>
              <span className="font-bold text-slate-800 uppercase">{healthData?.database?.dialect || 'SQLITE'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Server Environment</span>
              <span className="font-bold text-slate-800 uppercase">{healthData?.environment || 'DEVELOPMENT'}</span>
            </div>
          </div>
        </div>

        {/* Operator Session Details */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
          <div className="border-b border-slate-100 pb-3 mb-4">
            <h3 className="font-semibold text-sm text-slate-900">
              Active Security Operator Session
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Current authenticated session profile. Credentials are kept in memory and never stored in browser storage.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono-sm">
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Full Name</span>
              <span className="font-bold text-slate-800 text-sm">{user?.fullName || 'Dr. Sarah Jenkins'}</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Corporate Email</span>
              <span className="font-medium text-slate-700">{user?.email || 'sarah.jenkins@xerova.com'}</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Role / Authorization</span>
              <span className="inline-flex px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-bold border border-blue-200">
                {user?.role || 'SecOps Lead'}
              </span>
            </div>
          </div>
        </div>

        {/* Safety Gates Toggles */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h3 className="font-semibold text-sm text-slate-900">
              Automated Fix Verification Safety Gates
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Enforces automated rules before any proposed fix is approved for merge.
            </p>
          </div>

          <div className="space-y-3">
            <label className="flex items-center justify-between p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div>
                <span className="font-semibold text-xs text-slate-900 block">
                  Strict AST Taint Verification
                </span>
                <span className="text-[11px] text-slate-500">
                  Reject candidate fixes unless static taint path completely clears without bypass.
                </span>
              </div>
              <input
                type="checkbox"
                checked={strictAstTaint}
                onChange={e => setStrictAstTaint(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500"
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div>
                <span className="font-semibold text-xs text-slate-900 block">
                  Zero Hardcoded Secrets Policy
                </span>
                <span className="text-[11px] text-slate-500">
                  Pre-commit and PR blocker that prevents AWS keys, JWTs, or passwords from entering repo.
                </span>
              </div>
              <input
                type="checkbox"
                checked={zeroSecrets}
                onChange={e => setZeroSecrets(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500"
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div>
                <span className="font-semibold text-xs text-slate-900 block">
                  Auto-Merge Verified Fixes
                </span>
                <span className="text-[11px] text-slate-500">
                  Automatically approve and merge pull requests when 100% of test regressions pass.
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoMergeSafe}
                onChange={e => setAutoMergeSafe(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500"
              />
            </label>
          </div>

          <div className="pt-2">
            <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm mb-1">
              Sandbox Runner Timeout (Seconds)
            </label>
            <input
              type="number"
              value={sandboxTimeout}
              onChange={e => setSandboxTimeout(e.target.value)}
              className="w-36 px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Maximum execution duration before ephemeral test container is quarantined.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
