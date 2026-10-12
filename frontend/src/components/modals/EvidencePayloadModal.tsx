import React from 'react';
import { SecurityEvidenceRecord } from '../../services/api';

interface EvidencePayloadModalProps {
  evidence: SecurityEvidenceRecord | null;
  onClose: () => void;
}

export const EvidencePayloadModal: React.FC<EvidencePayloadModalProps> = ({ evidence, onClose }) => {
  if (!evidence) return null;

  let checksList: string[] = [];
  if (evidence.checks_not_performed) {
    try {
      checksList = JSON.parse(evidence.checks_not_performed);
    } catch {
      checksList = [evidence.checks_not_performed];
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto font-sans">
      <div className="relative w-full max-w-3xl bg-white rounded-xl shadow-2xl border border-slate-200 my-8 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-2xs">
              <span className="material-symbols-outlined text-xl">fingerprint</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-base text-slate-900">
                  {evidence.title}
                </h3>
                <span className="font-mono text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-bold border border-slate-200">
                  {evidence.id}
                </span>
              </div>
              <p className="font-mono text-xs text-slate-500 mt-0.5">
                Tool: <span className="font-bold text-slate-800">{evidence.tool_name}</span> {evidence.tool_version && `v${evidence.tool_version}`} • Category: {evidence.evidence_category}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto text-xs">
          {/* Content Hash Bar */}
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between font-mono">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-bold block">
                Cryptographic Content Hash (SHA-256)
              </span>
              <span className="text-slate-800 font-bold text-xs select-all">
                {evidence.content_hash}
              </span>
            </div>
            <span className="text-[10px] text-slate-400 italic max-w-xs text-right font-sans">
              Assists in accidental alteration detection.
            </span>
          </div>

          {/* Checks Not Performed */}
          {checksList.length > 0 && (
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl space-y-1">
              <span className="font-bold text-amber-900 block text-xs">
                Checks Not Performed for this Evidence Scope:
              </span>
              <ul className="list-disc pl-4 space-y-0.5 text-amber-800 text-[11px] font-sans">
                {checksList.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Sanitized Payload Content */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase font-bold text-slate-700">
                Sanitized Payload Excerpt (Secrets Redacted)
              </span>
              <span className="font-mono text-[11px] text-slate-400">
                {evidence.provenance.toUpperCase()}
              </span>
            </div>
            <pre className="p-4 bg-slate-900 text-slate-100 rounded-xl font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed max-h-72 shadow-inner border border-slate-800">
              {evidence.sanitized_payload}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-50 border-t border-slate-200 flex items-center justify-between">
          <span className="font-mono text-xs text-slate-400">
            Recorded: {new Date(evidence.recorded_at).toLocaleString()}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-md text-xs font-semibold transition-all shadow-2xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
