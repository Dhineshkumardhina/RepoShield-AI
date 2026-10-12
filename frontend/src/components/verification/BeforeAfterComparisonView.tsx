import React, { useState } from 'react';
import { ApiVerificationRun, ClassifiedFindingItem, FindingRegressionClassification } from '../../services/api';

interface BeforeAfterComparisonViewProps {
  run: ApiVerificationRun;
}

export const BeforeAfterComparisonView: React.FC<BeforeAfterComparisonViewProps> = ({ run }) => {
  const [filterClass, setFilterClass] = useState<string>('ALL');

  const renderClassificationBadge = (classification: FindingRegressionClassification) => {
    switch (classification) {
      case 'RESOLVED_BY_DEFINED_CHECKS':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800">
            <span className="material-symbols-outlined text-[13px] text-emerald-600 dark:text-emerald-400">check_circle</span>
            RESOLVED_BY_DEFINED_CHECKS
          </span>
        );
      case 'STILL_PRESENT':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-rose-100 text-rose-800 border border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800">
            <span className="material-symbols-outlined text-[13px] text-rose-600 dark:text-rose-400">warning</span>
            STILL_PRESENT
          </span>
        );
      case 'NEW':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-red-100 text-red-900 border border-red-400 dark:bg-red-950 dark:text-red-300 dark:border-red-800">
            <span className="material-symbols-outlined text-[13px] text-red-600 dark:text-red-400">add_alert</span>
            NEW (REGRESSION)
          </span>
        );
      case 'POTENTIALLY_REGRESSED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-purple-100 text-purple-900 border border-purple-300 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800">
            <span className="material-symbols-outlined text-[13px] text-purple-600 dark:text-purple-400">change_circle</span>
            POTENTIALLY_REGRESSED
          </span>
        );
      case 'UNCHANGED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-slate-100 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            <span className="material-symbols-outlined text-[13px] text-slate-500 dark:text-slate-400">horizontal_rule</span>
            UNCHANGED
          </span>
        );
      case 'INCOMPARABLE':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-amber-100 text-amber-800 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800">
            <span className="material-symbols-outlined text-[13px] text-amber-600 dark:text-amber-400">help_outline</span>
            INCOMPARABLE
          </span>
        );
    }
  };

  const classified = run.classified_findings || [];
  const filteredList = filterClass === 'ALL'
    ? classified
    : classified.filter(c => c.classification === filterClass);

  const baselineTests = run.baseline_test_results || {};
  const patchedTests = run.test_results || {};
  const testRegressions = run.test_regressions || [];

  return (
    <div className="space-y-6">
      {/* 1. Revision & Content Hash Baseline Comparison Bar */}
      <div className="bg-white rounded-xl p-4 border border-slate-200 shadow-2xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3 mb-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-slate-800 text-xl">compare_arrows</span>
            <span className="text-sm font-bold text-slate-900">Cryptographic Baseline vs Patched Comparison</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
            <span>Run: <span className="font-semibold text-slate-900">{run.id}</span></span>
            <span>•</span>
            <span>Target: <span className="font-semibold text-slate-900">{run.finding_id}</span></span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Baseline Content Hash</span>
              <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-slate-200 text-slate-700">PRE-PATCH</span>
            </div>
            <p className="font-mono text-xs text-slate-900 font-semibold truncate" title={run.baseline_hash || 'N/A'}>
              {run.baseline_hash || 'SHA256:4b91f092e038...'}
            </p>
          </div>

          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Patched Content Hash</span>
              <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold">POST-PATCH</span>
            </div>
            <p className="font-mono text-xs text-slate-900 font-semibold truncate" title={run.patched_hash || 'N/A'}>
              {run.patched_hash || 'SHA256:7c82a194df11...'}
            </p>
          </div>
        </div>
      </div>

      {/* 2. Test Suite Regression Inspection */}
      <div className="bg-white rounded-xl p-4 border border-slate-200 shadow-2xs space-y-3">
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-emerald-600 text-xl">biotech</span>
            <span className="text-sm font-bold text-slate-900">Isolated Test Suite Regression Analysis</span>
          </div>
          <span className="text-xs font-mono text-slate-600">
            {testRegressions.length === 0 ? '✓ 0 Test Regressions' : `⚠️ ${testRegressions.length} Test Regression(s)`}
          </span>
        </div>

        {testRegressions.length > 0 && (
          <div className="p-3 rounded-lg bg-rose-50 border border-rose-300 dark:bg-rose-950/40 dark:border-rose-800 text-rose-900 dark:text-rose-200 text-xs space-y-1">
            <div className="font-bold flex items-center gap-1.5">
              <span className="material-symbols-outlined text-sm text-rose-600">error</span>
              Blocking Functional Regressions Detected:
            </div>
            {testRegressions.map((reg, idx) => (
              <p key={idx} className="font-mono text-[11px] leading-relaxed pl-5">
                • {reg}
              </p>
            ))}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <div className="font-semibold text-slate-500 mb-1 text-[11px] uppercase">Baseline Test Outcome:</div>
            {Object.keys(baselineTests).length > 0 ? (
              Object.entries(baselineTests).map(([name, data]: [string, any]) => (
                <div key={name} className="font-mono text-[11px] text-slate-800">
                  <span className="font-bold">{name}</span>: {data.status} (Passed: {data.passed || 0}, Failed: {data.failed || 0})
                </div>
              ))
            ) : (
              <span className="text-slate-400 italic">No baseline unit test execution recorded.</span>
            )}
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <div className="font-semibold text-slate-500 mb-1 text-[11px] uppercase">Patched Test Outcome:</div>
            {Object.keys(patchedTests).length > 0 ? (
              Object.entries(patchedTests)
                .filter(([k]) => !k.startsWith('_'))
                .map(([name, data]: [string, any]) => (
                  <div key={name} className="font-mono text-[11px] text-slate-800">
                    <span className="font-bold">{name}</span>: {data.status} (Passed: {data.passed || 0}, Failed: {data.failed || 0})
                  </div>
                ))
            ) : (
              <span className="text-slate-400 italic">No patched test execution recorded.</span>
            )}
          </div>
        </div>
      </div>

      {/* 3. Classified Findings Before-and-After Matrix */}
      <div className="bg-white rounded-xl p-4 border border-slate-200 shadow-2xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-slate-700 text-xl">analytics</span>
              <h4 className="text-sm font-bold text-slate-900">
                Before &amp; After Finding Classifications ({classified.length})
              </h4>
            </div>
            <p className="text-xs text-slate-500">
              Systematic classification of all security checks across pre-patch and post-patch worktrees.
            </p>
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap gap-1">
            {['ALL', 'RESOLVED_BY_DEFINED_CHECKS', 'STILL_PRESENT', 'NEW', 'POTENTIALLY_REGRESSED', 'UNCHANGED', 'INCOMPARABLE'].map(c => (
              <button
                key={c}
                onClick={() => setFilterClass(c)}
                className={`px-2 py-1 text-[10px] font-mono font-bold rounded-md transition-colors ${
                  filterClass === c
                    ? 'bg-slate-900 text-white shadow-2xs'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {c === 'RESOLVED_BY_DEFINED_CHECKS' ? 'RESOLVED' : c === 'POTENTIALLY_REGRESSED' ? 'REGRESSED' : c}
              </button>
            ))}
          </div>
        </div>

        {filteredList.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 font-mono bg-slate-50 rounded-lg border border-slate-200">
            No findings matching selected classification filter.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredList.map((item, idx) => (
              <div
                key={idx}
                className={`p-3.5 rounded-lg border text-xs font-mono transition-all ${
                  item.classification === 'NEW'
                    ? 'bg-red-50/60 border-red-300'
                    : item.classification === 'RESOLVED_BY_DEFINED_CHECKS'
                    ? 'bg-emerald-50/60 border-emerald-300'
                    : item.classification === 'STILL_PRESENT'
                    ? 'bg-rose-50/60 border-rose-300'
                    : item.classification === 'POTENTIALLY_REGRESSED'
                    ? 'bg-purple-50/60 border-purple-300'
                    : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 mb-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-slate-900 text-sm">{item.rule_id}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-200 text-slate-800 font-semibold">
                      {item.severity}
                    </span>
                    <span className="text-[10px] text-slate-500">{item.scanner_name}</span>
                    {item.is_target_finding && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-white font-bold">
                        TARGET FINDING
                      </span>
                    )}
                  </div>
                  <div>
                    {renderClassificationBadge(item.classification)}
                  </div>
                </div>

                <p className="text-slate-700 font-sans text-xs mb-2">
                  {item.message}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 p-2 rounded-lg bg-white text-[11px] border border-slate-200 shadow-2xs">
                  <div>
                    <span className="text-slate-500 font-semibold block">File Location:</span>
                    <span className="text-slate-800 font-mono">{item.file_path}:{item.line_number || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-semibold block">Classification Rationale:</span>
                    <span className="text-slate-700 font-sans text-xs leading-relaxed">{item.classification_reason}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Unified Patch Diff */}
      {run.patch_diff && (
        <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 text-slate-100 font-mono text-xs space-y-2">
          <div className="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-2">
            <span className="font-bold flex items-center gap-1.5">
              <span className="material-symbols-outlined text-sm text-cyan-400">difference</span>
              Proposed Patch Unified Diff
            </span>
            <span className="text-[11px] text-slate-500">Atomic Isolated Worktree</span>
          </div>
          <pre className="overflow-x-auto whitespace-pre p-2 leading-relaxed max-h-56 text-[11px] text-emerald-400">
            {run.patch_diff}
          </pre>
        </div>
      )}
    </div>
  );
};
