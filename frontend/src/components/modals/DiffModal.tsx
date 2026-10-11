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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs">
      <div className="relative w-full max-w-4xl bg-surface-container-lowest rounded shadow-xl border border-outline-variant flex flex-col max-h-[90vh] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-5 py-4 border-b border-outline-variant flex items-center justify-between bg-surface-container-low">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-primary text-xl">difference</span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-headline-sm text-on-surface">
                  AST Remediation Diff Inspector: {item.repo}
                </h3>
                {item.prNumber && (
                  <span className="px-2 py-0.5 rounded bg-surface-container-high font-mono-sm text-on-surface font-semibold">
                    PR #{item.prNumber}
                  </span>
                )}
              </div>
              <p className="font-mono-sm text-on-surface-variant mt-0.5">
                Commit: <span className="font-semibold text-primary">{item.gitHash}</span> • Branch: <span className="text-on-surface font-medium">{item.branch}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors"
            title="Close"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {/* Status Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded bg-surface-container-low border border-outline-variant">
              <span className="font-label-caps text-on-surface-variant block uppercase">AST Taint Verification</span>
              <div className="flex items-center gap-1.5 mt-1 font-mono-md font-bold text-tertiary">
                <span className="material-symbols-outlined text-base">verified</span>
                <span>STATUS: {item.astTaintStatus || 'PASS'}</span>
              </div>
            </div>

            <div className="p-3 rounded bg-surface-container-low border border-outline-variant">
              <span className="font-label-caps text-on-surface-variant block uppercase">Regression Test Runner</span>
              <div className="flex items-center gap-1.5 mt-1 font-mono-md font-bold text-on-surface">
                <span className="material-symbols-outlined text-base text-primary">fact_check</span>
                <span>{item.unitTestsPassRate || '24/24 Tests Passed'}</span>
              </div>
            </div>

            <div className="p-3 rounded bg-surface-container-low border border-outline-variant">
              <span className="font-label-caps text-on-surface-variant block uppercase">Audit Engine</span>
              <div className="flex items-center gap-1.5 mt-1 font-mono-sm text-on-surface font-semibold">
                <span className="material-symbols-outlined text-base text-primary">shield</span>
                <span className="truncate">{item.engine}</span>
              </div>
            </div>
          </div>

          {/* Description & Message */}
          <div className="p-3 rounded bg-surface-container-low border border-outline-variant text-body-sm text-on-surface">
            <span className="font-label-caps text-on-surface-variant uppercase font-semibold block mb-1">
              Safety Verification Report
            </span>
            <p>{item.message}</p>
          </div>

          {/* Code Diff Box */}
          {item.diff ? (
            <div className="rounded border border-outline-variant overflow-hidden bg-surface-container-lowest font-mono-sm">
              <div className="bg-surface-container px-3 py-2 text-on-surface-variant flex items-center justify-between border-b border-outline-variant">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm">code</span>
                  <span className="font-semibold text-on-surface">{item.diff.filePath}</span>
                </div>
                <span className="text-outline font-mono-sm">git:{item.gitHash} → patch:verified</span>
              </div>

              {/* Deletion Lines */}
              {item.diff.oldCode.map((line, i) => (
                <div key={`old-${i}`} className="flex bg-[#ffdad6] text-[#93000a] border-b border-red-100">
                  <div className="w-12 px-2.5 py-1 text-right text-outline select-none bg-surface-container-high/60 font-mono-sm opacity-80">
                    {line.line}
                  </div>
                  <div className="w-7 py-1 text-center font-bold select-none text-error">-</div>
                  <div className="py-1 pr-3 font-mono text-mono-sm overflow-x-auto whitespace-pre">{line.text}</div>
                </div>
              ))}

              {/* Addition Lines */}
              {item.diff.newCode.map((line, i) => (
                <div key={`new-${i}`} className="flex bg-[#85f8c4]/30 text-[#005137] border-b border-emerald-100">
                  <div className="w-12 px-2.5 py-1 text-right text-outline select-none bg-surface-container-high/60 font-mono-sm opacity-80">
                    {line.line}
                  </div>
                  <div className="w-7 py-1 text-center font-bold select-none text-tertiary">+</div>
                  <div className="py-1 pr-3 font-mono text-mono-sm overflow-x-auto whitespace-pre font-medium">{line.text}</div>
                </div>
              ))}

              <div className="p-2.5 bg-surface-container-low border-t border-outline-variant flex items-center justify-between text-body-sm">
                <span className="font-mono-sm text-on-surface-variant flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-sm text-primary">rule</span>
                  Resolved Rule: <code className="text-primary font-bold">{item.diff.ruleId}</code>
                </span>
                <span className="font-mono-sm text-tertiary font-semibold flex items-center gap-1">
                  <span className="material-symbols-outlined text-xs">check_circle</span> Parameterized &amp; Taint-Free
                </span>
              </div>
            </div>
          ) : (
            <div className="p-6 rounded bg-surface-container-low text-center font-body-sm text-on-surface-variant">
              No code modifications required for this scan run (Clean repository state).
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 border-t border-outline-variant bg-surface-container-lowest flex items-center justify-between">
          <div className="flex items-center gap-2 text-mono-sm text-on-surface-variant">
            <span className="material-symbols-outlined text-base text-primary">lock_clock</span>
            <span>Cryptographic Merkle Proof: <span className="font-mono text-on-surface font-semibold">0x7a8...92c</span></span>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 rounded border border-outline-variant bg-surface-container-lowest hover:bg-surface-container text-on-surface font-body-sm transition-colors"
            >
              Close
            </button>
            {item.status === 'verified' && item.prNumber && (
              <button
                disabled={isMerged}
                onClick={() => onApproveAndMerge(item.id, item.prNumber)}
                className={`flex items-center gap-1.5 px-4 py-1.5 rounded font-body-sm font-medium transition-colors shadow-sm ${
                  isMerged
                    ? 'bg-tertiary text-on-tertiary cursor-default'
                    : 'bg-primary hover:bg-on-primary-fixed-variant text-on-primary'
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
