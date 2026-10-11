import React from 'react';
import { VerificationItem } from '../../types';

interface CrashInspectorModalProps {
  item: VerificationItem | null;
  onClose: () => void;
  onRerun: (id: string) => void;
  isRerunning?: boolean;
}

export const CrashInspectorModal: React.FC<CrashInspectorModalProps> = ({
  item,
  onClose,
  onRerun,
  isRerunning
}) => {
  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs">
      <div className="relative w-full max-w-3xl bg-surface-container-lowest rounded shadow-xl border border-outline-variant flex flex-col max-h-[85vh] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-5 py-4 border-b border-outline-variant flex items-center justify-between bg-error-container/40">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-error text-2xl">
              {item.status === 'failed' ? 'error' : 'timelapse'}
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-headline-sm text-on-surface">
                  {item.status === 'failed' ? 'Verification Regression Crash Inspector' : 'Sandbox Timeout Diagnostic'}
                </h3>
                {item.prNumber && (
                  <span className="px-2 py-0.5 rounded bg-error-container text-error font-mono-sm font-bold">
                    PR #{item.prNumber}
                  </span>
                )}
              </div>
              <p className="font-mono-sm text-on-surface-variant mt-0.5">
                Target: <span className="font-semibold text-on-surface">{item.repo}</span> • Branch: <span className="font-medium text-on-surface">{item.branch}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {/* Reason Alert Box */}
          <div className="p-3.5 rounded bg-error-container/30 border border-error/30 text-body-sm">
            <div className="flex items-center gap-2 font-mono-sm font-bold text-error mb-1">
              <span className="material-symbols-outlined text-base">warning</span>
              <span>QUARANTINE ENFORCEMENT: {item.status.toUpperCase()}</span>
            </div>
            <p className="font-mono-sm text-on-surface leading-relaxed">
              {item.crashReason || item.message}
            </p>
          </div>

          {/* Test Harness Status */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded bg-surface-container-low border border-outline-variant">
              <span className="font-label-caps text-on-surface-variant block uppercase">Test Harness Result</span>
              <span className="font-mono-md font-bold text-error mt-1 block">
                {item.unitTestsPassRate || 'Test Failed'}
              </span>
            </div>
            <div className="p-3 rounded bg-surface-container-low border border-outline-variant">
              <span className="font-label-caps text-on-surface-variant block uppercase">Sandbox Runner State</span>
              <span className="font-mono-md font-bold text-on-surface mt-1 block">
                Execution halted at {item.executionTime}
              </span>
            </div>
          </div>

          {/* Simulated Sandbox Terminal Logs */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-label-caps text-on-surface-variant uppercase font-semibold">
                Sandbox Execution Trace &amp; Taint Log
              </span>
              <span className="font-mono-sm text-outline">Runner ID: ephemeral-sbx-990</span>
            </div>
            <div className="p-3 rounded bg-[#0b1c30] text-[#eaf1ff] font-mono-sm text-xs space-y-1.5 overflow-x-auto max-h-56">
              {item.crashLogs && item.crashLogs.length > 0 ? (
                item.crashLogs.map((log, idx) => (
                  <div
                    key={idx}
                    className={`leading-relaxed ${
                      log.includes('FAIL') || log.includes('error') || log.includes('QUARANTINE')
                        ? 'text-red-400 font-semibold'
                        : log.includes('PASS')
                        ? 'text-emerald-400'
                        : 'text-slate-300'
                    }`}
                  >
                    {log}
                  </div>
                ))
              ) : (
                <div className="text-slate-400">[runner] No detailed terminal dump available for this run.</div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 border-t border-outline-variant bg-surface-container-lowest flex items-center justify-between">
          <span className="font-body-sm text-on-surface-variant">
            Automated quarantine policy active. Pull request cannot merge until regressions are cleared.
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 rounded border border-outline-variant bg-surface-container-lowest hover:bg-surface-container text-on-surface font-body-sm transition-colors"
            >
              Close
            </button>
            <button
              disabled={isRerunning}
              onClick={() => onRerun(item.id)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-primary text-on-primary hover:bg-on-primary-fixed-variant font-body-sm font-medium transition-colors shadow-sm disabled:opacity-50"
            >
              <span className={`material-symbols-outlined text-base ${isRerunning ? 'animate-spin' : ''}`}>
                replay
              </span>
              <span>{isRerunning ? 'Rerunning in Sandbox...' : 'Rerun in Clean Sandbox'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
