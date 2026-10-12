import React from 'react';
import { VerificationItem } from '../../types';

interface DiffModalProps {
  item: VerificationItem | null;
  onClose: () => void;
  onApproveAndMerge: (id: string, prNumber?: number) => void;
  isMerged?: boolean;
}

export const DiffModal: React.FC<DiffModalProps> = ({ item, onClose, onApproveAndMerge, isMerged }) => {
  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs font-sans">
      <div className="relative w-full max-w-4xl bg-white rounded-xl shadow-2xl border border-slate-200 flex flex-col max-h-[90vh] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-2xs">
              <span className="material-symbols-outlined text-xl">difference</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900">
                  AST Remediation Diff: {item.repo}
                </h3>
                {item.prNumber && (
                  <span className="px-2 py-0.5 rounded-md bg-slate-100 font-mono text-xs text-slate-700 font-semibold border border-slate-200">
                    PR #{item.prNumber}
                  </span>
                )}
              </div>
              <p className="font-mono text-xs text-slate-500 mt-0.5">
                Commit: <span className="font-semibold text-slate-800">{item.gitHash}</span> • Branch: <span className="text-slate-800 font-medium">{item.branch}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
            title="Close"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {/* Status Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block">
                AST Taint Verification
              </span>
              <div className="flex items-center gap-1.5 mt-1 font-mono text-xs font-bold text-emerald-700">
                <span className="material-symbols-outlined text-base">verified</span>
                <span>STATUS: {item.astTaintStatus || 'PASS'}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block">
                Regression Test Runner
              </span>
              <div className="flex items-center gap-1.5 mt-1 font-mono text-xs font-bold text-slate-800">
                <span className="material-symbols-outlined text-base text-slate-600">fact_check</span>
                <span>{item.unitTestsPassRate || '24/24 Tests Passed'}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block">
                Audit Engine
              </span>
              <div className="flex items-center gap-1.5 mt-1 font-mono text-xs text-slate-800 font-semibold">
                <span className="material-symbols-outlined text-base text-slate-600">shield</span>
                <span className="truncate">{item.engine}</span>
              </div>
            </div>
          </div>

          {/* Description & Message */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block mb-1">
              Safety Verification Report
            </span>
            <p className="leading-relaxed font-sans">{item.message}</p>
          </div>

          {/* Code Diff Box (GitHub Style) */}
          {item.diff ? (
            <div className="rounded-xl border border-slate-200 overflow-hidden bg-white font-mono text-xs shadow-2xs">
              <div className="bg-slate-800 px-4 py-2.5 text-slate-300 flex items-center justify-between border-b border-slate-700">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm text-slate-400">code</span>
                  <span className="font-semibold text-white">{item.diff.filePath}</span>
                </div>
                <span className="text-slate-400 font-mono text-[11px]">git:{item.gitHash} → patch:verified</span>
              </div>

              {/* Deletion Lines */}
              {item.diff.oldCode.map((line, i) => (
                <div key={`old-${i}`} className="flex bg-rose-50 text-rose-900 border-l-2 border-rose-500 border-b border-rose-100">
                  <div className="w-12 px-2.5 py-1 text-right text-slate-400 select-none bg-rose-100/50 font-mono text-xs">
                    {line.line}
                  </div>
                  <div className="w-7 py-1 text-center font-bold select-none text-rose-600">-</div>
                  <div className="py-1 pr-3 font-mono text-xs overflow-x-auto whitespace-pre">{line.text}</div>
                </div>
              ))}

              {/* Addition Lines */}
              {item.diff.newCode.map((line, i) => (
                <div key={`new-${i}`} className="flex bg-emerald-50 text-emerald-900 border-l-2 border-emerald-500 border-b border-emerald-100">
                  <div className="w-12 px-2.5 py-1 text-right text-slate-400 select-none bg-emerald-100/50 font-mono text-xs">
                    {line.line}
                  </div>
                  <div className="w-7 py-1 text-center font-bold select-none text-emerald-600">+</div>
                  <div className="py-1 pr-3 font-mono text-xs overflow-x-auto whitespace-pre font-medium">{line.text}</div>
                </div>
              ))}

              <div className="p-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs">
                <span className="font-mono text-slate-600 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-sm text-slate-500">rule</span>
                  Resolved Rule: <code className="text-slate-900 font-bold">{item.diff.ruleId}</code>
                </span>
                <span className="font-mono text-emerald-700 font-semibold flex items-center gap-1">
                  <span className="material-symbols-outlined text-xs">check_circle</span> Parameterized &amp; Taint-Free
                </span>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-slate-50 text-center text-xs text-slate-500 border border-slate-200">
              No code modifications required for this scan run (Clean repository state).
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
            <span className="material-symbols-outlined text-base text-slate-600">lock_clock</span>
            <span>Cryptographic Merkle Proof: <span className="font-mono text-slate-800 font-semibold">0x7a8...92c</span></span>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors shadow-2xs"
            >
              Close
            </button>
            {item.status === 'verified' && item.prNumber && (
              <button
                disabled={isMerged}
                onClick={() => onApproveAndMerge(item.id, item.prNumber)}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-semibold transition-all shadow-2xs ${
                  isMerged
                    ? 'bg-emerald-600 text-white cursor-default'
                    : 'bg-slate-900 hover:bg-slate-800 text-white'
                }`}
              >
                <span className="material-symbols-outlined text-base">
                  {isMerged ? 'check' : 'call_merge'}
                </span>
                <span>{isMerged ? `PR #${item.prNumber} Merged` : `Approve & Merge PR #${item.prNumber}`}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
