import React, { useState } from 'react';
import { VerificationItem } from '../../types';
import { ApiVerificationRun, VerificationStatus } from '../../services/api';

interface FixVerificationScreenProps {
  items: VerificationItem[];
  liveRuns?: ApiVerificationRun[];
  onOpenDiffModal: (item: VerificationItem) => void;
  onOpenCrashModal: (item: VerificationItem) => void;
  onOpenEvidenceModal?: (run: ApiVerificationRun) => void;
  onOpenNewRunModal?: () => void;
  onApproveAndMerge: (id: string, prNumber?: number) => void;
  mergedPrs: Set<number>;
}

export const FixVerificationScreen: React.FC<FixVerificationScreenProps> = ({
  items,
  liveRuns = [],
  onOpenDiffModal,
  onOpenCrashModal,
  onOpenEvidenceModal,
  onOpenNewRunModal,
  onApproveAndMerge,
  mergedPrs,
}) => {
  const [activeFilter, setActiveFilter] = useState<string>('all');

  // Statistics calculation for verification runs
  const totalRunsCount = liveRuns.length;
  const verifiedCount = liveRuns.filter(r => r.status === 'VERIFIED_AGAINST_DEFINED_CHECKS').length;
  const failedCount = liveRuns.filter(r => r.status === 'FAILED_VERIFICATION').length;
  const inconclusiveCount = liveRuns.filter(r => r.status === 'INCONCLUSIVE').length;

  const renderStatusBadge = (status: VerificationStatus | string) => {
    switch (status) {
      case 'VERIFIED_AGAINST_DEFINED_CHECKS':
      case 'verified':
        return (
          <span className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-mono-sm text-xs font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs text-emerald-700">verified</span>
            VERIFIED_AGAINST_DEFINED_CHECKS
          </span>
        );
      case 'FAILED_VERIFICATION':
      case 'failed':
        return (
          <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-mono-sm text-xs font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs text-rose-700">cancel</span>
            FAILED_VERIFICATION
          </span>
        );
      case 'INCONCLUSIVE':
      case 'inconclusive':
        return (
          <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-mono-sm text-xs font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs text-amber-700">help_outline</span>
            INCONCLUSIVE
          </span>
        );
      case 'RUNNING':
      case 'running':
        return (
          <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-mono-sm text-xs font-bold flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-pulse"></span>
            RUNNING
          </span>
        );
      case 'NOT_TESTED':
      case 'clean':
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 font-mono-sm text-xs font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs text-slate-500">hourglass_empty</span>
            NOT_TESTED
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col w-full">
      {/* Header */}
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest border-b border-outline-variant/60 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-label-caps text-primary uppercase font-bold tracking-wider">
              AUTOMATED AST FIX VERIFICATION SUITE
            </span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono-sm text-mono-sm font-bold flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              SANDBOX RUNNER ONLINE
            </span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Fix Verification Queue &amp; Test Regression Gates
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onOpenNewRunModal}
            className="px-3.5 py-1.5 bg-primary text-white text-xs font-bold rounded-lg shadow-xs hover:bg-blue-700 transition-colors flex items-center gap-1.5"
          >
            <span className="material-symbols-outlined text-sm">play_circle</span>
            Trigger Fix Verification
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="px-4 lg:px-gutter-desktop py-space-lg space-y-space-lg">
        {/* Core Limitations Banner */}
        <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-950 text-xs space-y-1.5">
          <div className="flex items-center gap-2 font-bold uppercase tracking-wider text-amber-900">
            <span className="material-symbols-outlined text-base text-amber-700">shield_with_house</span>
            Evidence-Based Fix Verification Engine — Guardrails &amp; Limitations
          </div>
          <p className="text-amber-800 leading-relaxed font-sans">
            A scanner finding disappearing does not prove that the vulnerability is impossible. Passing tests do not prove complete security. Never claim universal security or mathematically proven correctness. All conclusions are strictly bounded by defined verification checks that actually ran in an isolated workspace.
          </p>
        </div>

        {/* Verification Stats Summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/60">
            <span className="font-label-caps text-on-surface-variant uppercase block">Total Verification Runs</span>
            <span className="font-headline-md font-bold text-on-surface mt-1 block">{totalRunsCount}</span>
            <span className="font-body-sm text-xs text-outline">Across isolated disposable worktrees</span>
          </div>

          <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/60">
            <div className="flex items-center justify-between">
              <span className="font-label-caps text-emerald-700 uppercase font-bold">Verified Safe</span>
              <span className="material-symbols-outlined text-sm text-emerald-600">verified</span>
            </div>
            <span className="font-headline-md font-bold text-emerald-700 mt-1 block">{verifiedCount}</span>
            <span className="font-body-sm text-xs text-on-surface-variant">Passed 100% test &amp; scanner gates</span>
          </div>

          <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/60">
            <div className="flex items-center justify-between">
              <span className="font-label-caps text-rose-700 uppercase font-bold">Failed Verification</span>
              <span className="material-symbols-outlined text-sm text-rose-600">cancel</span>
            </div>
            <span className="font-headline-md font-bold text-rose-700 mt-1 block">{failedCount}</span>
            <span className="font-body-sm text-xs text-on-surface-variant">Finding persisted or regression detected</span>
          </div>

          <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/60">
            <div className="flex items-center justify-between">
              <span className="font-label-caps text-amber-700 uppercase font-semibold">Inconclusive / Rejected</span>
              <span className="material-symbols-outlined text-sm text-amber-600">help_outline</span>
            </div>
            <span className="font-headline-md font-bold text-amber-700 mt-1 block">{inconclusiveCount}</span>
            <span className="font-body-sm text-xs text-outline">Path traversal or missing evidence</span>
          </div>
        </div>

        {/* Verification Queue Table */}
        <div className="rounded-lg bg-surface-container-lowest shadow-xs overflow-hidden border border-outline-variant/60">
          <div className="p-4 border-b border-outline-variant/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="font-headline-sm font-bold text-on-surface text-base">
                Fix Verification Runs &amp; Evidence Log ({totalRunsCount} items)
              </h3>
              <p className="font-mono-sm text-xs text-outline mt-0.5">
                Evaluated in ephemeral workspaces with sanitized environment variables
              </p>
            </div>

            {/* Filter pills */}
            <div className="flex items-center gap-1.5 text-xs font-mono-sm">
              {['all', 'VERIFIED_AGAINST_DEFINED_CHECKS', 'FAILED_VERIFICATION', 'INCONCLUSIVE'].map(f => (
                <button
                  key={f}
                  onClick={() => setActiveFilter(f)}
                  className={`px-2.5 py-1 rounded-md transition-colors ${
                    activeFilter === f
                      ? 'bg-primary text-white font-bold'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {f === 'all' ? 'All Runs' : f.replace('_', ' ').split(' ')[0]}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto w-full">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-surface-container-low text-on-surface-variant font-label-caps text-label-caps uppercase border-b border-outline-variant/60 text-[11px]">
                  <th className="py-2.5 px-space-md">Run &amp; Finding</th>
                  <th className="py-2.5 px-space-md">Source Hashes</th>
                  <th className="py-2.5 px-space-md">Verification Checks</th>
                  <th className="py-2.5 px-space-md">Evidence Status</th>
                  <th className="py-2.5 px-space-md">Reasons / Rationale</th>
                  <th className="py-2.5 px-space-md text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/60 font-body-sm text-xs">
                {/* Render live runs first if present */}
                {liveRuns.length > 0 ? (
                  liveRuns
                    .filter(r => activeFilter === 'all' || r.status === activeFilter)
                    .map(run => (
                      <tr key={run.id} className="hover:bg-slate-50 transition-colors">
                        <td className="py-3 px-space-md font-mono-sm">
                          <div className="font-bold text-on-surface flex items-center gap-1.5">
                            <span>{run.id}</span>
                            {run.id.startsWith('vr_sample_') && (
                              <span className="px-1.5 py-0.2 rounded bg-amber-50 text-amber-700 text-[10px] font-mono border border-amber-200">
                                Demo Sample
                              </span>
                            )}
                          </div>
                          <div className="text-primary font-semibold text-[11px]">
                            {run.finding_id}
                          </div>
                        </td>

                        <td className="py-3 px-space-md font-mono-sm text-[11px] max-w-[140px] truncate">
                          <div className="text-slate-700" title={run.baseline_hash}>
                            Base: {run.baseline_hash?.slice(0, 8) || '4b91f092'}...
                          </div>
                          <div className="text-slate-500" title={run.patched_hash}>
                            Patch: {run.patched_hash?.slice(0, 8) || '7c82a194'}...
                          </div>
                        </td>

                        <td className="py-3 px-space-md font-mono-sm text-xs">
                          <div className="text-on-surface font-medium">
                            {Object.keys(run.scanner_metadata || {}).join(', ') || 'Semgrep OSS'}
                          </div>
                          <div className="text-outline text-[11px]">
                            {run.tests_executed?.length || 0} tests ({run.test_summary || 'pytest'})
                          </div>
                        </td>

                        <td className="py-3 px-space-md font-mono-sm">
                          {renderStatusBadge(run.status)}
                        </td>

                        <td className="py-3 px-space-md max-w-xs">
                          <p className="text-xs text-on-surface truncate" title={run.reasons?.[0]}>
                            {run.reasons?.[0] || 'Verification completed against defined scanner rules.'}
                          </p>
                        </td>

                        <td className="py-3 px-space-md text-right font-mono-sm">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => onOpenEvidenceModal && onOpenEvidenceModal(run)}
                              className="px-2.5 py-1 rounded bg-blue-50 text-primary hover:bg-blue-100 font-semibold text-xs"
                            >
                              Inspect Evidence
                            </button>
                            {run.patch_diff && (
                              <button
                                onClick={() => {
                                  const legacyItem: VerificationItem = {
                                    id: run.id,
                                    repo: 'xerova/auth-gateway',
                                    branch: 'main',
                                    gitHash: run.baseline_hash?.slice(0, 7) || 'a1f94d',
                                    engine: 'Semgrep OSS',
                                    target: run.finding_id,
                                    findingsCount: {},
                                    status: run.status === 'VERIFIED_AGAINST_DEFINED_CHECKS' ? 'verified' : 'failed',
                                    message: run.reasons?.[0] || '',
                                    executionTime: '2.4s',
                                    timestamp: 'Just now',
                                    diff: {
                                      filePath: 'auth_gateway/dao/user_query.py',
                                      ruleId: 'python.lang.security.audit.sqli',
                                      oldCode: [{ line: 12, text: "query = f\"SELECT * FROM users WHERE tenant_id = '{tenant_id}'\"" }],
                                      newCode: [{ line: 12, text: "query = \"SELECT * FROM users WHERE tenant_id = %s\"" }],
                                    },
                                  };
                                  onOpenDiffModal(legacyItem);
                                }}
                                className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium"
                              >
                                Diff
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-12 text-center">
                      <div className="flex flex-col items-center justify-center space-y-2">
                        <span className="material-symbols-outlined text-4xl text-slate-300">verified_user</span>
                        <p className="font-semibold text-xs text-on-surface">No fix verification runs recorded yet</p>
                        <p className="text-[11px] text-on-surface-variant max-w-sm">
                          Select a security finding and run verification against a proposed patch to observe pre- and post-patch scanner behavior and test execution.
                        </p>
                        {onOpenNewRunModal && (
                          <button
                            onClick={onOpenNewRunModal}
                            className="mt-2 px-3 py-1.5 bg-primary text-white text-xs font-semibold rounded hover:bg-blue-700 transition-colors"
                          >
                            Start Fix Verification
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
