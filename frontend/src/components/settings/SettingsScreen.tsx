import React, { useState } from 'react';

export const SettingsScreen: React.FC = () => {
  const [zeroSecrets, setZeroSecrets] = useState(true);
  const [autoMergeSafe, setAutoMergeSafe] = useState(true);
  const [strictAstTaint, setStrictAstTaint] = useState(true);
  const [sandboxTimeout, setSandboxTimeout] = useState('120');
  const [slaBenchmark, setSlaBenchmark] = useState('5.0');
  const [savedToast, setSavedToast] = useState(false);

  const handleSave = () => {
    setSavedToast(true);
    setTimeout(() => setSavedToast(false), 2500);
  };

  return (
    <div className="flex flex-col w-full">
      {/* Header */}
      <div className="px-6 py-4 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-blue-600 uppercase font-bold tracking-wider">
              WORKSPACE POLICY &amp; SAFETY GATES
            </span>
            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-800 font-mono text-[10px] font-bold border border-slate-200">
              ENFORCEMENT V4
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Security Governance &amp; Auto-Remediation Controls
          </h1>
        </div>

        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 text-white hover:bg-slate-800 text-xs font-semibold transition-colors shadow-2xs"
        >
          <span className="material-symbols-outlined text-base">save</span>
          <span>Save Changes</span>
        </button>
      </div>

      {/* Main Settings Form */}
      <div className="p-6 max-w-4xl space-y-6">
        {savedToast && (
          <div className="p-3.5 rounded-lg bg-emerald-50 text-emerald-800 font-mono text-xs flex items-center gap-2 border border-emerald-200 shadow-2xs animate-in fade-in">
            <span className="material-symbols-outlined text-sm text-emerald-600">check_circle</span>
            <span>Security policies and SLA gates successfully updated.</span>
          </div>
        )}

        {/* Policy Section 1 */}
        <div className="rounded-xl bg-white p-5 border border-slate-200 shadow-2xs space-y-4">
          <div className="border-b border-slate-200 pb-3">
            <h3 className="font-bold text-slate-900 text-sm">
              Core Vulnerability &amp; Secret Policies
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Controls enforced by VCS pre-commit webhooks and AST scanner gates.
            </p>
          </div>

          <div className="space-y-4 text-xs">
            {/* Zero Tolerated Secrets */}
            <div className="flex items-center justify-between">
              <div className="pr-4">
                <span className="font-semibold text-slate-900 text-sm block">
                  Zero Hardcoded Secrets Policy
                </span>
                <span className="text-slate-600">
                  Immediately blocks commits with detected private keys, high-entropy tokens, or cloud credentials.
                </span>
              </div>
              <input
                type="checkbox"
                checked={zeroSecrets}
                onChange={e => setZeroSecrets(e.target.checked)}
                className="w-4 h-4 rounded text-slate-900 focus:ring-slate-900 accent-slate-900 cursor-pointer"
              />
            </div>

            {/* Strict AST Taint */}
            <div className="flex items-center justify-between pt-3.5 border-t border-slate-100">
              <div className="pr-4">
                <span className="font-semibold text-slate-900 text-sm block">
                  Strict AST Taint Verification
                </span>
                <span className="text-slate-600">
                  Propagates taint vectors through complex call chains, database DAOs, and RPC handlers.
                </span>
              </div>
              <input
                type="checkbox"
                checked={strictAstTaint}
                onChange={e => setStrictAstTaint(e.target.checked)}
                className="w-4 h-4 rounded text-slate-900 focus:ring-slate-900 accent-slate-900 cursor-pointer"
              />
            </div>

            {/* Automated PR Auto-Merge Gate */}
            <div className="flex items-center justify-between pt-3.5 border-t border-slate-100">
              <div className="pr-4">
                <span className="font-semibold text-slate-900 text-sm block">
                  Automated Fix Verification Auto-Merge Gate
                </span>
                <span className="text-slate-600">
                  Automatically approves and merges remediation PRs that achieve 100% test pass rate + clean AST taint check.
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoMergeSafe}
                onChange={e => setAutoMergeSafe(e.target.checked)}
                className="w-4 h-4 rounded text-slate-900 focus:ring-slate-900 accent-slate-900 cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Section 2: Sandbox & SLA Benchmarks */}
        <div className="rounded-xl bg-white p-5 border border-slate-200 shadow-2xs space-y-4">
          <div className="border-b border-slate-200 pb-3">
            <h3 className="font-bold text-slate-900 text-sm">
              Sandbox Runner &amp; Benchmark Thresholds
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Execution parameters for test runners and SLA alerts.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            <div>
              <label className="text-[10px] uppercase text-slate-500 font-semibold block mb-1">
                Sandbox Execution Timeout (Seconds)
              </label>
              <input
                type="number"
                value={sandboxTimeout}
                onChange={e => setSandboxTimeout(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 rounded-lg border border-slate-200 text-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900 shadow-2xs"
              />
              <span className="text-[11px] text-slate-400 mt-1 block">
                Jobs exceeding this duration receive Inconclusive status.
              </span>
            </div>

            <div>
              <label className="text-[10px] uppercase text-slate-500 font-semibold block mb-1">
                High/Critical SLA Benchmark (Days)
              </label>
              <input
                type="text"
                value={slaBenchmark}
                onChange={e => setSlaBenchmark(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 rounded-lg border border-slate-200 text-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-900 shadow-2xs"
              />
              <span className="text-[11px] text-slate-400 mt-1 block">
                Default enterprise benchmark: &lt; 5.0 days SLA.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
