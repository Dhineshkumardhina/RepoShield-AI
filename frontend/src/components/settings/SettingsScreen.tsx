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
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest border-b border-outline-variant/60 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-label-caps text-primary uppercase font-bold tracking-wider">
              WORKSPACE POLICY &amp; SAFETY GATES
            </span>
            <span className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface font-mono-sm text-mono-sm font-bold">
              ENFORCEMENT V4
            </span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Security Governance &amp; Auto-Remediation Controls
          </h1>
        </div>

        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-primary text-on-primary hover:bg-on-primary-fixed-variant font-body-sm font-medium transition-colors shadow-xs"
        >
          <span className="material-symbols-outlined text-base">save</span>
          <span>Save Changes</span>
        </button>
      </div>

      {/* Main Settings Form */}
      <div className="px-4 lg:px-gutter-desktop py-space-lg max-w-4xl space-y-space-lg">
        {savedToast && (
          <div className="p-3 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-xs flex items-center gap-1.5 shadow-xs animate-in fade-in">
            <span className="material-symbols-outlined text-sm">check_circle</span>
            <span>Security policies and SLA gates successfully updated.</span>
          </div>
        )}

        {/* Policy Section 1 */}
        <div className="rounded bg-surface-container-lowest p-space-md border border-outline-variant/60 shadow-xs space-y-4">
          <div className="border-b border-outline-variant/60 pb-3">
            <h3 className="font-headline-sm text-on-surface text-base">
              Core Vulnerability &amp; Secret Policies
            </h3>
            <p className="font-body-sm text-xs text-on-surface-variant">
              Controls enforced by VCS pre-commit webhooks and AST scanner gates.
            </p>
          </div>

          <div className="space-y-4 font-body-sm text-xs">
            {/* Zero Tolerated Secrets */}
            <div className="flex items-center justify-between">
              <div className="pr-4">
                <span className="font-medium text-on-surface text-sm block">
                  Zero Tolerated Secrets Policy
                </span>
                <span className="text-on-surface-variant">
                  Immediately blocks commits with detected private keys, high-entropy tokens, or cloud credentials.
                </span>
              </div>
              <input
                type="checkbox"
                checked={zeroSecrets}
                onChange={e => setZeroSecrets(e.target.checked)}
                className="w-4 h-4 rounded text-primary focus:ring-primary accent-primary cursor-pointer"
              />
            </div>

            {/* Strict AST Taint */}
            <div className="flex items-center justify-between pt-3 border-t border-outline-variant/60">
              <div className="pr-4">
                <span className="font-medium text-on-surface text-sm block">
                  Inter-Procedural AST Taint Analysis
                </span>
                <span className="text-on-surface-variant">
                  Propagates taint vectors through complex call chains, database DAOs, and RPC handlers.
                </span>
              </div>
              <input
                type="checkbox"
                checked={strictAstTaint}
                onChange={e => setStrictAstTaint(e.target.checked)}
                className="w-4 h-4 rounded text-primary focus:ring-primary accent-primary cursor-pointer"
              />
            </div>

            {/* Automated PR Auto-Merge Gate */}
            <div className="flex items-center justify-between pt-3 border-t border-outline-variant/60">
              <div className="pr-4">
                <span className="font-medium text-on-surface text-sm block">
                  Automated Fix Verification Auto-Merge Gate
                </span>
                <span className="text-on-surface-variant">
                  Automatically approves and merges remediation PRs that achieve 100% test pass rate + clean AST taint check.
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoMergeSafe}
                onChange={e => setAutoMergeSafe(e.target.checked)}
                className="w-4 h-4 rounded text-primary focus:ring-primary accent-primary cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Section 2: Sandbox & SLA Benchmarks */}
        <div className="rounded bg-surface-container-lowest p-space-md border border-outline-variant/60 shadow-xs space-y-4">
          <div className="border-b border-outline-variant/60 pb-3">
            <h3 className="font-headline-sm text-on-surface text-base">
              Sandbox Runner &amp; Benchmark Thresholds
            </h3>
            <p className="font-body-sm text-xs text-on-surface-variant">
              Execution parameters for test runners and SLA alerts.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono-sm text-xs">
            <div>
              <label className="font-label-caps text-on-surface-variant uppercase font-semibold block mb-1">
                Sandbox Execution Timeout (Seconds)
              </label>
              <input
                type="number"
                value={sandboxTimeout}
                onChange={e => setSandboxTimeout(e.target.value)}
                className="w-full px-3 py-1.5 bg-surface-container-low rounded border border-outline-variant/60 text-on-surface focus:outline-none focus:border-primary"
              />
              <span className="text-[11px] text-outline mt-1 block">
                Jobs exceeding this duration receive Inconclusive status.
              </span>
            </div>

            <div>
              <label className="font-label-caps text-on-surface-variant uppercase font-semibold block mb-1">
                High/Critical SLA Benchmark (Days)
              </label>
              <input
                type="text"
                value={slaBenchmark}
                onChange={e => setSlaBenchmark(e.target.value)}
                className="w-full px-3 py-1.5 bg-surface-container-low rounded border border-outline-variant/60 text-on-surface focus:outline-none focus:border-primary"
              />
              <span className="text-[11px] text-outline mt-1 block">
                Default enterprise benchmark: &lt; 5.0 days SLA.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
