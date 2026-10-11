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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto">
      <div className="relative w-full max-w-3xl bg-surface-container-lowest rounded-xl shadow-2xl border border-outline-variant/80 my-8 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-surface-container-low border-b border-outline-variant/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-primary/10 text-primary">
              <span className="material-symbols-outlined text-xl">fingerprint</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-headline-sm font-bold text-base text-on-surface">
                  {evidence.title}
                </h3>
                <span className="font-mono-sm text-xs px-2 py-0.5 rounded bg-slate-200 text-slate-800 font-bold">
                  {evidence.id}
                </span>
              </div>
              <p className="font-mono-sm text-xs text-on-surface-variant">
                Tool: <span className="font-bold">{evidence.tool_name}</span> {evidence.tool_version && `v${evidence.tool_version}`} • Category: {evidence.evidence_category}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-outline hover:text-on-surface hover:bg-surface-variant/40 transition-colors"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto text-xs">
          {/* Content Hash Bar */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between font-mono-sm">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-bold block">
                Cryptographic Content Hash (SHA-256)
              </span>
              <span className="text-slate-800 font-bold text-xs select-all">
                {evidence.content_hash}
              </span>
            </div>
            <span className="text-[10px] text-slate-500 italic max-w-xs text-right">
              Assists in accidental alteration detection.
            </span>
          </div>

          {/* Checks Not Performed */}
          {checksList.length > 0 && (
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg space-y-1">
              <span className="font-bold text-amber-900 block text-xs">
                Checks Not Performed for this Evidence Scope:
              </span>
              <ul className="list-disc pl-4 space-y-0.5 text-amber-800 text-[11px]">
                {checksList.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Sanitized Payload Content */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-label-caps uppercase font-bold text-slate-700">
                Sanitized Payload Excerpt (Secrets Redacted)
              </span>
              <span className="font-mono-sm text-[11px] text-outline">
                {evidence.provenance.toUpperCase()}
              </span>
            </div>
            <pre className="p-4 bg-slate-900 text-slate-100 rounded-lg font-mono-sm text-xs overflow-x-auto whitespace-pre leading-relaxed max-h-72">
              {evidence.sanitized_payload}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-surface-container-low border-t border-outline-variant/80 flex items-center justify-between">
          <span className="font-mono-sm text-[11px] text-outline">
            Recorded: {new Date(evidence.recorded_at).toLocaleString()}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs font-semibold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
