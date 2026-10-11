import React, { useState } from 'react';
import {
  FindingValidationResponse,
  FindingValidationRequest,
  ValidationStatusEnum,
  ValidationEvidenceItem,
} from '../../services/api';

export interface EvidenceReviewSectionProps {
  findingId: string;
  validation: FindingValidationResponse | null;
  isLoading: boolean;
  isValidating: boolean;
  error: string | null;
  onRunValidation: (payload: FindingValidationRequest) => Promise<void>;
}

export const EvidenceReviewSection: React.FC<EvidenceReviewSectionProps> = ({
  findingId,
  validation,
  isLoading,
  isValidating,
  error,
  onRunValidation,
}) => {
  const [useAiAssistant, setUseAiAssistant] = useState(false);
  const [showFullHash, setShowFullHash] = useState(false);

  const handleValidateClick = () => {
    onRunValidation({
      use_ai_assistant: useAiAssistant,
      user_authorized: true,
    });
  };

  const getStatusBadge = (status: ValidationStatusEnum | undefined) => {
    switch (status) {
      case 'SUPPORTED_BY_EVIDENCE':
        return {
          label: 'Supported by Evidence',
          icon: 'verified',
          bg: 'bg-emerald-50',
          text: 'text-emerald-800',
          border: 'border-emerald-300',
          badgeBg: 'bg-emerald-600',
        };
      case 'POSSIBLE_FALSE_POSITIVE':
        return {
          label: 'Possible False Positive',
          icon: 'published_with_changes',
          bg: 'bg-amber-50',
          text: 'text-amber-800',
          border: 'border-amber-300',
          badgeBg: 'bg-amber-600',
        };
      case 'INSUFFICIENT_EVIDENCE':
        return {
          label: 'Insufficient Evidence',
          icon: 'search_off',
          bg: 'bg-slate-100',
          text: 'text-slate-800',
          border: 'border-slate-300',
          badgeBg: 'bg-slate-600',
        };
      case 'HUMAN_REVIEW_REQUIRED':
        return {
          label: 'Human Review Required',
          icon: 'person_search',
          bg: 'bg-purple-50',
          text: 'text-purple-800',
          border: 'border-purple-300',
          badgeBg: 'bg-purple-600',
        };
      case 'UNREVIEWED':
      default:
        return {
          label: 'Unreviewed',
          icon: 'help_outline',
          bg: 'bg-blue-50',
          text: 'text-blue-800',
          border: 'border-blue-300',
          badgeBg: 'bg-blue-600',
        };
    }
  };

  const currentStatusBadge = getStatusBadge(validation?.assessment_status);

  return (
    <div className="rounded-lg bg-surface-container-lowest border border-outline-variant/80 shadow-xs overflow-hidden">
      {/* Module Header & Action Bar */}
      <div className="bg-slate-900 text-white px-5 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-primary-300 text-xl">fact_check</span>
            <h3 className="font-bold text-sm tracking-wide uppercase">
              Evidence-Driven Vulnerability Validation
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono-sm font-semibold bg-slate-800 text-slate-300 border border-slate-700">
              EPISTEMIC ASSESSMENT ENGINE
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Assesses existing scanner findings against observable code context, data-flow signals, and AST patterns without mutating original scanner results.
          </p>
        </div>

        {/* Validation Trigger Controls */}
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={useAiAssistant}
              onChange={(e) => setUseAiAssistant(e.target.checked)}
              className="rounded border-slate-700 bg-slate-800 text-primary focus:ring-primary h-3.5 w-3.5"
            />
            <span className="text-[11px] font-medium text-slate-300">
              Enable AI Assistant
            </span>
          </label>

          <button
            onClick={handleValidateClick}
            disabled={isValidating || isLoading}
            className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              isValidating || isLoading
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : 'bg-primary text-white hover:bg-blue-600 shadow-sm'
            }`}
          >
            {isValidating ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Evaluating Evidence...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-sm">play_arrow</span>
                <span>Evaluate Evidence</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Epistemic Boundary Notice */}
      <div className="bg-amber-500/10 border-b border-amber-500/20 px-5 py-2.5 flex items-center gap-2 text-xs text-amber-900">
        <span className="material-symbols-outlined text-amber-600 text-base">info</span>
        <span>
          <strong>Epistemic Boundary:</strong> Assessment statuses classify the strength of available evidence and do not constitute absolute mathematical proof of exploitability or harmlessness.
        </span>
      </div>

      <div className="p-5 space-y-6">
        {/* Loading Indicator */}
        {isLoading && !validation && (
          <div className="py-8 flex flex-col items-center justify-center space-y-2">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <p className="font-mono-sm text-xs text-slate-600">Loading validation state...</p>
          </div>
        )}

        {/* Error Notice */}
        {error && (
          <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-md text-rose-800 text-xs flex items-center gap-2">
            <span className="material-symbols-outlined text-base text-rose-600">error</span>
            <div>
              <span className="font-bold mr-1">Validation Notice:</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Main Assessment Presentation */}
        {validation && (
          <>
            {/* Assessment Status Banner */}
            <div className={`p-4 rounded-lg border ${currentStatusBadge.bg} ${currentStatusBadge.border} flex flex-col sm:flex-row sm:items-center justify-between gap-3`}>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-full text-white ${currentStatusBadge.badgeBg}`}>
                  <span className="material-symbols-outlined text-xl">{currentStatusBadge.icon}</span>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-600 font-mono-sm">
                      EPISTEMIC STATUS:
                    </span>
                    <span className={`font-bold text-sm ${currentStatusBadge.text}`}>
                      {validation.assessment_status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-700 mt-0.5">
                    {validation.evidence_summary}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono-sm self-start sm:self-auto">
                <div className="text-right">
                  <span className="text-slate-500 text-[10px] uppercase font-bold block">Confidence Level</span>
                  <span className="font-bold text-slate-800">
                    {validation.confidence_level} ({Math.round(validation.confidence_score * 100)}%)
                  </span>
                </div>
                {validation.ai_assisted && (
                  <div className="px-2 py-1 rounded bg-purple-100 text-purple-800 border border-purple-200 text-[11px] font-semibold flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">smart_toy</span>
                    AI Assisted ({validation.ai_model || 'Analysis Assistant'})
                  </div>
                )}
              </div>
            </div>

            {/* Assessment Detailed Explanation */}
            <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-xs space-y-2">
              <span className="font-bold uppercase tracking-wider text-slate-700 font-mono-sm text-[11px] block">
                Evidence-Based Rationale:
              </span>
              <p className="text-slate-800 leading-relaxed">
                {validation.explanation}
              </p>
            </div>

            {/* Preserved Original Scanner Finding (Strict Invariance) */}
            {validation.original_finding && (
              <div className="p-4 bg-white rounded-lg border border-slate-200 shadow-xs space-y-3">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-base text-slate-600">lock</span>
                    <h4 className="font-bold text-xs uppercase tracking-wide text-slate-800 font-mono-sm">
                      Original Scanner Finding (Preserved &amp; Unmodified)
                    </h4>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono-sm">
                    Severity Pristinely Preserved
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono-sm">
                  <div className="p-2.5 rounded bg-slate-50 border border-slate-100">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Scanner Tool</span>
                    <span className="font-semibold text-slate-900 mt-0.5 block">{validation.original_finding.scanner_name || 'N/A'}</span>
                  </div>

                  <div className="p-2.5 rounded bg-slate-50 border border-slate-100">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Scanner Severity</span>
                    <span className="font-bold text-rose-700 mt-0.5 block">{validation.original_finding.original_severity || 'UNKNOWN'}</span>
                  </div>

                  <div className="p-2.5 rounded bg-slate-50 border border-slate-100">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Rule Identifier</span>
                    <span className="font-semibold text-slate-900 mt-0.5 block truncate" title={validation.original_finding.rule_identifier}>
                      {validation.original_finding.rule_identifier || 'N/A'}
                    </span>
                  </div>

                  <div className="p-2.5 rounded bg-slate-50 border border-slate-100">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Target Code Location</span>
                    <span className="font-semibold text-slate-900 mt-0.5 block truncate" title={`${validation.original_finding.file_path}:${validation.original_finding.line_number}`}>
                      {validation.original_finding.file_path}:{validation.original_finding.line_number}
                    </span>
                  </div>
                </div>

                {validation.original_finding.scanner_message && (
                  <div className="p-2.5 rounded bg-slate-50 border border-slate-100 text-xs font-mono-sm text-slate-700">
                    <span className="text-[10px] text-slate-500 uppercase font-bold block mb-0.5">Original Scanner Message:</span>
                    <p>{validation.original_finding.scanner_message}</p>
                  </div>
                )}
              </div>
            )}


            {/* Inspected Code Context */}
            {validation.code_excerpt_inspected && (
              <div className="p-4 bg-white rounded-lg border border-slate-200 shadow-xs space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-base text-slate-600">code</span>
                    <h4 className="font-bold text-xs uppercase tracking-wide text-slate-800 font-mono-sm">
                      Inspected Source Context
                    </h4>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono-sm">
                    {validation.context_start_line && validation.context_end_line
                      ? `Lines ${validation.context_start_line} – ${validation.context_end_line}`
                      : 'Bounded Snippet'}
                    {validation.is_context_truncated ? ' (Truncated)' : ''}
                  </span>
                </div>
                <div className="p-3 bg-slate-950 text-slate-200 rounded font-mono-sm text-xs overflow-x-auto leading-relaxed">
                  <pre>{validation.code_excerpt_inspected}</pre>
                </div>
              </div>
            )}

            {/* Evidence Breakdown Grid: Supporting vs Refuting */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Supporting Evidence */}
              <div className="p-4 rounded-lg bg-emerald-50/50 border border-emerald-200/80 space-y-3">
                <div className="flex items-center gap-2 text-emerald-900">
                  <span className="material-symbols-outlined text-base text-emerald-700">check_circle</span>
                  <h4 className="font-bold text-xs uppercase tracking-wider font-mono-sm">
                    Supporting Evidence ({(validation.supporting_evidence || []).length})
                  </h4>
                </div>

                {(!validation.supporting_evidence || validation.supporting_evidence.length === 0) ? (
                  <p className="text-xs text-slate-500 italic">No positive supporting evidence recorded.</p>
                ) : (
                  <div className="space-y-2">
                    {validation.supporting_evidence.map((item, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-white border border-emerald-200 text-xs space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-mono-sm font-semibold text-emerald-800">
                          <span className="uppercase">{item.evidence_type}</span>
                          {item.line_number && <span>Line {item.line_number}</span>}
                        </div>
                        <p className="text-slate-700">{item.description}</p>
                        {item.code_snippet && (
                          <div className="p-1.5 bg-slate-900 text-slate-100 rounded text-[11px] font-mono-sm overflow-x-auto">
                            <code>{item.code_snippet}</code>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Refuting Evidence */}
              <div className="p-4 rounded-lg bg-amber-50/50 border border-amber-200/80 space-y-3">
                <div className="flex items-center gap-2 text-amber-900">
                  <span className="material-symbols-outlined text-base text-amber-700">cancel</span>
                  <h4 className="font-bold text-xs uppercase tracking-wider font-mono-sm">
                    Refuting Evidence / Mitigating Signals ({(validation.refuting_evidence || []).length})
                  </h4>
                </div>

                {(!validation.refuting_evidence || validation.refuting_evidence.length === 0) ? (
                  <p className="text-xs text-slate-500 italic">No refuting or mitigating signals recorded.</p>
                ) : (
                  <div className="space-y-2">
                    {validation.refuting_evidence.map((item, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-white border border-amber-200 text-xs space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-mono-sm font-semibold text-amber-800">
                          <span className="uppercase">{item.evidence_type}</span>
                          {item.line_number && <span>Line {item.line_number}</span>}
                        </div>
                        <p className="text-slate-700">{item.description}</p>
                        {item.code_snippet && (
                          <div className="p-1.5 bg-slate-900 text-slate-100 rounded text-[11px] font-mono-sm overflow-x-auto">
                            <code>{item.code_snippet}</code>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Missing Evidence Required for Stronger Conclusion */}
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-slate-800">
                <span className="material-symbols-outlined text-base text-slate-600">help</span>
                <h4 className="font-bold text-xs uppercase tracking-wider font-mono-sm">
                  Evidence Required to Reach Stronger Conclusion
                </h4>
              </div>
              {(!validation.missing_evidence || validation.missing_evidence.length === 0) ? (
                <p className="text-xs text-slate-500 italic">No additional evidence required for the current classification.</p>
              ) : (
                <ul className="list-disc pl-5 text-xs text-slate-700 space-y-1">
                  {validation.missing_evidence.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* Analysis Limitations & Unsupported Capabilities */}
            {validation.analysis_limitations && validation.analysis_limitations.length > 0 && (
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center gap-2 text-slate-800">
                  <span className="material-symbols-outlined text-base text-slate-600">warning</span>
                  <h4 className="font-bold text-xs uppercase tracking-wider font-mono-sm">
                    Analysis Limitations &amp; Unsupported Capabilities
                  </h4>
                </div>
                <ul className="list-disc pl-5 text-xs text-slate-600 space-y-1">
                  {validation.analysis_limitations.map((limitation, idx) => (
                    <li key={idx}>{limitation}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Suggested Next Steps */}
            {validation.suggested_next_steps && validation.suggested_next_steps.length > 0 && (
              <div className="p-4 rounded-lg bg-blue-50/60 border border-blue-200 space-y-2">
                <div className="flex items-center gap-2 text-blue-900">
                  <span className="material-symbols-outlined text-base text-blue-700">trending_flat</span>
                  <h4 className="font-bold text-xs uppercase tracking-wider font-mono-sm">
                    Suggested Next Steps
                  </h4>
                </div>
                <ul className="list-disc pl-5 text-xs text-blue-950 space-y-1">
                  {validation.suggested_next_steps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Cryptographic Tamper-Evident Footer */}
            {validation.evidence_hash && (
              <div className="pt-2 border-t border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono-sm text-slate-500">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-xs text-slate-400">fingerprint</span>
                  <span>Evidence SHA-256:</span>
                  <button
                    onClick={() => setShowFullHash(!showFullHash)}
                    className="text-primary hover:underline font-mono-sm"
                    title="Click to toggle full hash"
                  >
                    {showFullHash ? validation.evidence_hash : `${validation.evidence_hash.substring(0, 16)}...`}
                  </button>
                </div>
                <div>
                  <span>Recorded: {validation.recorded_at ? new Date(validation.recorded_at).toLocaleString() : 'N/A'}</span>
                </div>
              </div>
            )}
          </>
        )}

        {/* Empty state when finding is not yet validated */}
        {!validation && !isLoading && (
          <div className="py-8 px-4 text-center space-y-3">
            <span className="material-symbols-outlined text-4xl text-slate-400">policy</span>
            <div className="space-y-1">
              <h4 className="font-bold text-sm text-slate-800">
                No Evidence Validation Recorded
              </h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Click <strong>Evaluate Evidence</strong> above to inspect the source file AST, data-flow patterns, and context boundaries to classify this scanner finding.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
