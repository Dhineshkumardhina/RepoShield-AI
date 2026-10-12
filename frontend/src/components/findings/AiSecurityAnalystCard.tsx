import React from 'react';
import { AnalysisResult } from '../../services/api';

export interface AiSecurityAnalystCardProps {
  analysis: AnalysisResult | null;
  isLoading: boolean;
  error: string | null;
  userAuthorized: boolean;
  onToggleAuthorization: (authorized: boolean) => void;
  onRunAnalysis: () => void;
}

export const AiSecurityAnalystCard: React.FC<AiSecurityAnalystCardProps> = ({
  analysis,
  isLoading,
  error,
  userAuthorized,
  onToggleAuthorization,
  onRunAnalysis,
}) => {
  return (
    <div className="rounded-xl bg-white border border-slate-200 shadow-2xs overflow-hidden">
      {/* Header Warning Banner */}
      <div className="bg-slate-50 border-b border-slate-200 px-4 py-3 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-slate-700 text-lg">analytics</span>
          <div>
            <h4 className="font-semibold text-xs text-slate-900">
              AI-Generated Security Analysis — Requires Human Review
            </h4>
            <p className="text-[11px] text-slate-500">
              Remediation insights and root cause claims must be validated by security engineers prior to implementation.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-slate-700 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={userAuthorized}
              onChange={(e) => onToggleAuthorization(e.target.checked)}
              className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
            />
            <span className="font-medium text-xs">Authorize Code Analysis</span>
          </label>
          <button
            onClick={onRunAnalysis}
            disabled={!userAuthorized || isLoading}
            className={`px-3 py-1 rounded text-xs font-medium flex items-center gap-1 transition-colors ${
              !userAuthorized || isLoading
                ? 'bg-slate-100 text-slate-400 cursor-not-allowed'
                : 'bg-slate-900 text-white hover:bg-slate-800'
            }`}
          >
            {isLoading ? 'Analyzing...' : 'Generate Analysis'}
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Loading State */}
        {isLoading && (
          <div className="py-8 flex flex-col items-center justify-center space-y-3">
            <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <p className="font-mono-sm text-xs text-primary font-semibold">
              Synthesizing AI Security Assessment...
            </p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="p-3.5 bg-red-50 border border-red-200 rounded-md text-red-800 text-xs">
            <span className="font-bold mr-1">Analyst Service Notice:</span>
            <span>{error}</span>
          </div>
        )}

        {/* Authorization Hold State */}
        {!userAuthorized && !isLoading && (
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-md text-slate-700 text-xs flex items-start gap-2.5">
            <span className="material-symbols-outlined text-slate-500 text-base mt-0.5">lock</span>
            <div>
              <p className="font-semibold text-slate-800">
                Authorization Hold: Opt-in required
              </p>
              <p className="text-slate-600 mt-0.5">
                To safeguard intellectual property, private repository content will not be sent to external language models without explicit administrator authorization.
              </p>
            </div>
          </div>
        )}

        {/* Analysis Details */}
        {analysis && !isLoading && (
          <div className="space-y-4">
            {/* Meta bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-3">
              <div className="flex items-center gap-3">
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 font-mono text-xs font-medium">
                  {analysis.ai_model}
                </span>
                <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-mono text-xs font-semibold">
                  {analysis.confidence}
                </span>
              </div>
              <div>
                {analysis.is_exploitable_claim_supported ? (
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-medium flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                    Exploitability Supported by Static Flow
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 text-xs font-medium flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                    Exploitability Unproven / Context Incomplete
                  </span>
                )}
              </div>
            </div>

            {/* Explanation & Root cause */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3.5 bg-slate-50 rounded-md border border-slate-200/60">
                <h5 className="font-bold text-xs uppercase tracking-wider text-slate-700 mb-1">
                  Plain Language Explanation
                </h5>
                <p className="text-xs text-slate-800 leading-relaxed">
                  {analysis.plain_language_explanation}
                </p>
              </div>

              <div className="p-3.5 bg-slate-50 rounded-md border border-slate-200/60">
                <h5 className="font-bold text-xs uppercase tracking-wider text-slate-700 mb-1">
                  Likely Root Cause
                </h5>
                <p className="text-xs text-slate-800 leading-relaxed">
                  {analysis.likely_root_cause}
                </p>
              </div>
            </div>

            {/* Potential Impact */}
            <div className="p-3.5 bg-rose-50/50 rounded-md border border-rose-200/60">
              <h5 className="font-bold text-xs uppercase tracking-wider text-rose-800 mb-1">
                Potential Impact
              </h5>
              <p className="text-xs text-rose-900 leading-relaxed">
                {analysis.potential_impact}
              </p>
            </div>

            {/* Remediation & Targeted Tests */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-bold text-xs uppercase tracking-wider text-slate-700 mb-2">
                  Suggested Remediation
                </h5>
                <ul className="space-y-1.5 list-disc pl-4 text-xs text-slate-700">
                  {(analysis.suggested_remediation || analysis.recommended_remediation || []).map((item, idx) => (
                    <li key={idx} className="font-mono-sm text-[11px]">{item}</li>
                  ))}
                </ul>
              </div>

              <div>
                <h5 className="font-bold text-xs uppercase tracking-wider text-slate-700 mb-2">
                  Targeted Regression Tests
                </h5>
                <ul className="space-y-1.5 list-disc pl-4 text-xs text-slate-700">
                  {(analysis.suggested_targeted_tests || analysis.suggested_tests || []).map((item, idx) => (
                    <li key={idx} className="font-mono-sm text-[11px]">{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Caveats & Limitations */}
            <div className="pt-2 border-t border-slate-200 text-xs space-y-1 text-slate-600">
              {(analysis.missing_context || []).map((ctx, idx) => (
                <div key={idx} className="flex items-center gap-1.5 text-[11px]">
                  <span className="material-symbols-outlined text-xs text-slate-400">info</span>
                  <span>{ctx}</span>
                </div>
              ))}
              {(analysis.limitations || []).map((lim, idx) => (
                <div key={idx} className="flex items-center gap-1.5 text-[11px]">
                  <span className="material-symbols-outlined text-xs text-slate-400">warning</span>
                  <span>{lim}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Empty State when no analysis generated yet */}
        {!analysis && !isLoading && !error && userAuthorized && (
          <div className="py-8 flex flex-col items-center justify-center text-center space-y-2">
            <span className="material-symbols-outlined text-3xl text-slate-400">fact_check</span>
            <p className="font-semibold text-xs text-slate-800">No Remediation Analysis Generated</p>
            <p className="text-[11px] text-slate-500 max-w-sm">
              Click &quot;Generate Analysis&quot; above to evaluate root-cause patterns, exploitability boundaries, and candidate patches.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
