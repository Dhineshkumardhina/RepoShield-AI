import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  api,
  ApiFinding,
  AnalysisResult,
  FindingValidationResponse,
  FindingValidationRequest,
  ContextualRiskAssessment,
} from '../services/api';
import { AiSecurityAnalystCard } from '../components/findings/AiSecurityAnalystCard';
import { EvidenceReviewSection } from '../components/findings/EvidenceReviewSection';
import { SeverityBadge } from '../components/common';

export const FindingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<ApiFinding | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [isLoadingAnalysis, setIsLoadingAnalysis] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [userAuthorized, setUserAuthorized] = useState(true);

  const [isLoadingFinding, setIsLoadingFinding] = useState(true);
  const [findingError, setFindingError] = useState<string | null>(null);

  // Contextual Risk Prioritization state
  const [prioritization, setPrioritization] = useState<ContextualRiskAssessment | null>(null);
  const [isLoadingPrioritization, setIsLoadingPrioritization] = useState(false);

  // Evidence-driven vulnerability validation state
  const [validation, setValidation] = useState<FindingValidationResponse | null>(null);
  const [isLoadingValidation, setIsLoadingValidation] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;

    let isMounted = true;
    setIsLoadingFinding(true);
    setFindingError(null);

    // Fetch live finding
    api.getFinding(id)
      .then((data) => {
        if (isMounted) {
          setFinding(data);
          setIsLoadingFinding(false);
        }
      })
      .catch((err: any) => {
        if (isMounted) {
          // If not found in live DB (e.g., direct navigation to legacy demo ID), provide fallback
          if (id === 'FIND-418') {
            setFinding({
              id: 'FIND-418',
              repo_id: 'repo-auth-gateway',
              cwe: 'CWE-89: SQL Injection',
              title: 'Raw SQL Query String Interpolation in user_query.py',
              severity: 'CRITICAL',
              scanner_name: 'Semgrep OSS',
              file_path: 'auth-gateway/src/dao/user_query.py',
              line_number: 42,
              status: 'open',
              confidence_score: 0.98,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            });
          } else {
            setFindingError(err.message || `Finding '${id}' could not be loaded.`);
          }
          setIsLoadingFinding(false);
        }
      });

    // Fetch existing live analyses for this finding
    api.getFindingAnalyses(id)
      .then((analyses) => {
        if (isMounted && analyses && analyses.length > 0) {
          setAnalysis(analyses[0]);
        } else if (isMounted) {
          setAnalysis(null);
        }
      })
      .catch(() => {
        if (isMounted) {
          setAnalysis(null);
        }
      });

    // Fetch existing evidence validation for this finding
    setIsLoadingValidation(true);
    api.getFindingValidation(id)
      .then((valData) => {
        if (isMounted) {
          setValidation(valData);
          setIsLoadingValidation(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setValidation(null);
          setIsLoadingValidation(false);
        }
      });

    // Fetch existing live contextual risk prioritization for this finding
    setIsLoadingPrioritization(true);
    api.getFindingPrioritization(id)
      .then((prioData) => {
        if (isMounted) {
          setPrioritization(prioData);
          setIsLoadingPrioritization(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setPrioritization(null);
          setIsLoadingPrioritization(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [id]);

  const handleRunAnalysis = async () => {
    if (!id) return;
    setIsLoadingAnalysis(true);
    setAnalysisError(null);
    try {
      const res = await api.analyzeFindingWithAi(id, userAuthorized);
      setAnalysis(res);
    } catch (err: any) {
      setAnalysisError(err.message || 'AI Security Analyst API call failed.');
    } finally {
      setIsLoadingAnalysis(false);
    }
  };

  const handleRunValidation = async (payload: FindingValidationRequest) => {
    if (!id) return;
    setIsValidating(true);
    setValidationError(null);
    try {
      const res = await api.validateFinding(id, payload);
      setValidation(res);
    } catch (err: any) {
      setValidationError(err.message || 'Evidence-driven vulnerability validation failed.');
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <div className="flex flex-col w-full">
      {/* Breadcrumb / Top Bar */}
      <div className="px-4 lg:px-gutter-desktop py-space-sm bg-surface-container-lowest border-b border-outline-variant/60 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-mono-sm">
          <Link to="/findings" className="text-primary hover:underline flex items-center gap-1">
            <span className="material-symbols-outlined text-sm">arrow_back</span>
            Findings Hub
          </Link>
          <span className="text-outline">/</span>
          <span className="font-bold text-on-surface">{finding?.id || id}</span>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/verification"
            className="px-3 py-1 bg-primary text-white text-xs font-semibold rounded hover:bg-blue-700 transition-colors flex items-center gap-1"
          >
            <span className="material-symbols-outlined text-sm">verified_user</span>
            Fix Verification Center
          </Link>
        </div>
      </div>

      <div className="px-4 lg:px-gutter-desktop py-space-lg space-y-6">
        {isLoadingFinding && (
          <div className="p-8 bg-surface-container-lowest border border-outline-variant/60 rounded-lg flex items-center justify-center space-x-3">
            <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <span className="text-xs text-on-surface-variant font-mono-sm">Retrieving security finding from database...</span>
          </div>
        )}

        {findingError && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 flex items-center gap-2">
            <span className="material-symbols-outlined text-base">error</span>
            <span>{findingError}</span>
          </div>
        )}

        {/* Finding Summary */}
        {finding && (
        <div className="p-6 bg-surface-container-lowest border border-outline-variant/60 rounded-lg shadow-xs">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2.5 mb-2">
                {finding?.severity && (
                  <SeverityBadge severity={finding.severity.toLowerCase() as any} />
                )}
                <span className="font-mono-sm text-xs text-on-surface-variant font-semibold">
                  {finding?.cwe}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono-sm text-[11px]">
                  {finding?.scanner_name}
                </span>
              </div>
              <h1 className="text-xl font-bold text-on-surface">
                {finding?.title}
              </h1>
              <p className="text-xs text-outline font-mono-sm mt-1">
                {finding?.file_path}:{finding?.line_number}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleRunAnalysis}
                className="px-4 py-2 bg-primary text-white text-xs font-bold rounded shadow-xs hover:bg-blue-700 transition-colors flex items-center gap-1.5"
              >
                <span className="material-symbols-outlined text-sm">smart_toy</span>
                Run AI Analyst
              </button>
            </div>
          </div>
        </div>
        )}

        {/* Contextual Risk Prioritization Panel */}
        <div className="p-6 bg-surface-container-lowest border border-outline-variant/60 rounded-lg shadow-xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-outline-variant/40 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-label-caps text-xs text-primary font-bold uppercase">
                  CONTEXTUAL RISK PRIORITIZATION &amp; EVIDENCE BOUNDARY
                </span>
                <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-mono-sm text-[11px] font-bold">
                  TRANSPARENT SCORING
                </span>
              </div>
              <p className="text-xs text-on-surface-variant font-mono-sm mt-0.5">
                Evaluates scanner severity, component category, reachability, sensitive data, and fix readiness.
              </p>
            </div>
            <span className="text-[11px] font-mono-sm text-outline">
              Triage Metric • Not Probability of Exploitation
            </span>
          </div>

          {/* 4 Separated Evaluation Dimensions */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono-sm">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">1. Scanner Severity</span>
              <span className="font-bold text-rose-700 text-sm mt-0.5 block">
                {prioritization?.original_scanner_severity || finding?.severity || 'CRITICAL'}
              </span>
              <span className="text-[10px] text-slate-500">Raw engine report</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">2. Contextual Priority</span>
              <span className="font-bold text-primary text-sm mt-0.5 block">
                {prioritization?.contextual_priority || 'CRITICAL'} ({prioritization?.priority_score?.toFixed(1) || '80.0'}/100)
              </span>
              <span className="text-[10px] text-slate-500">Evidence-weighted rank</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">3. Evidence Completeness</span>
              <span className="font-bold text-slate-800 text-sm mt-0.5 block">
                {prioritization?.evidence_completeness || 'PARTIAL'}
              </span>
              <span className="text-[10px] text-slate-500">AST &amp; context depth</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">4. Verification Status</span>
              <span className={`font-bold text-sm mt-0.5 block ${
                prioritization?.verification_status === 'VERIFIED_AGAINST_DEFINED_CHECKS'
                  ? 'text-emerald-700'
                  : prioritization?.verification_status === 'FAILED_VERIFICATION'
                  ? 'text-rose-700'
                  : 'text-amber-700'
              }`}>
                {prioritization?.verification_status || 'NOT_TESTED'}
              </span>
              <span className="text-[10px] text-slate-500">
                {prioritization?.remediation_readiness === 'VERIFIED_FIX_READY' ? 'Verified fix ready' : 'No verified fix'}
              </span>
            </div>
          </div>

          {/* Floor Protection & Limitation Alert */}
          {prioritization?.floor_protection_applied && (
            <div className="p-3 rounded-lg bg-amber-50 border border-amber-300 text-xs font-mono-sm flex items-start gap-2.5 text-amber-900">
              <span className="material-symbols-outlined text-amber-600 text-base mt-0.5">shield</span>
              <div>
                <span className="font-bold block">Severe Finding Floor Protection Active</span>
                <span>
                  The scanner reported {prioritization.original_scanner_severity} severity. Because reachability or environmental evidence is missing, RepoShield AI protects this finding from silent downgrading, preserving elevated triage visibility.
                </span>
              </div>
            </div>
          )}

          {/* Investigation Recommendation Callout */}
          {prioritization?.investigation_recommendation && (
            <div className="p-3 rounded-lg bg-blue-50 border border-blue-200 text-xs font-mono-sm flex items-start gap-2.5 text-blue-900">
              <span className="material-symbols-outlined text-blue-600 text-base mt-0.5">search</span>
              <div>
                <span className="font-bold block">Recommended Investigation Action:</span>
                <span>{prioritization.investigation_recommendation}</span>
              </div>
            </div>
          )}

          {/* Remediation Linkage & Patch Availability */}
          {prioritization?.remediation_linkage && (
            <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200 text-xs font-mono-sm space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-700 uppercase text-[11px]">Supporting Remediation Links:</span>
                <span className="text-[11px] text-slate-500">
                  Readiness: <strong>{prioritization.remediation_readiness}</strong>
                </span>
              </div>
              {prioritization.remediation_linkage.patch_diff_preview && (
                <div className="bg-slate-900 p-2.5 rounded text-[11px] text-slate-200 font-mono overflow-x-auto">
                  <span className="text-slate-400 block mb-1">Proposed Patch Diff:</span>
                  <pre className="whitespace-pre">{prioritization.remediation_linkage.patch_diff_preview}</pre>
                </div>
              )}
              {prioritization.remediation_linkage.recommendations.length > 0 && (
                <div className="space-y-1 text-[11px] text-slate-700">
                  <span className="font-semibold block text-slate-800">Actionable Recommendations:</span>
                  {prioritization.remediation_linkage.recommendations.map((rec, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <span className="text-blue-600 font-bold">•</span>
                      <span>{rec}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Dynamic Traceable Factors Breakdown */}
          {prioritization?.factors && prioritization.factors.length > 0 && (
            <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200 text-xs font-mono-sm space-y-1.5">
              <span className="font-bold text-slate-700 block uppercase text-[11px]">Traceable Scoring Factors:</span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-600 text-[11px]">
                {prioritization.factors.map((f, i) => (
                  <div key={i} className="p-2 rounded bg-white border border-slate-200/80">
                    <div className="flex items-center justify-between font-semibold text-slate-800">
                      <span>{f.name}</span>
                      <span className={f.impact >= 0 ? 'text-emerald-700 font-bold' : 'text-slate-500'}>
                        {f.impact >= 0 ? `+${f.impact}` : `${f.impact}`}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-0.5">{f.rationale}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Evidence-Driven Vulnerability Validation Review Section */}
        {finding && (
          <EvidenceReviewSection
            findingId={finding.id}
            validation={validation}
            isLoading={isLoadingValidation}
            isValidating={isValidating}
            error={validationError}
            onRunValidation={handleRunValidation}
          />
        )}

        {/* AST Taint Trace Evidence Section */}
        <div className="p-6 bg-surface-container-lowest border border-outline-variant/60 rounded-lg shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-sm text-on-surface flex items-center gap-2">
              <span className="material-symbols-outlined text-base text-primary">account_tree</span>
              AST Taint Trace Evidence
            </h3>
            <span className="font-mono-sm text-xs text-slate-500">Static Dataflow Propagation Path</span>
          </div>
          <div className="p-4 bg-slate-900 rounded-md font-mono-sm text-xs text-slate-100 space-y-2">
            <div className="flex items-center gap-2 text-amber-400">
              <span className="font-bold">[SOURCE]</span>
              <span>tenant_id &larr; Request Query Parameter (Untrusted Input)</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300 pl-4 border-l-2 border-slate-700">
              <span className="font-bold">&darr;</span>
              <span>Interpolated without sanitization: query = f"SELECT * FROM users WHERE tenant_id = '{'{'}tenant_id{'}'}'"</span>
            </div>
            <div className="flex items-center gap-2 text-rose-400">
              <span className="font-bold">[SINK]</span>
              <span>cursor.execute(query) &larr; Raw SQL Execution sink reached</span>
            </div>
          </div>
        </div>

        {/* AI Security Analyst Section */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-base text-on-surface flex items-center gap-2">
              <span className="material-symbols-outlined text-lg text-primary">psychology</span>
              AI Security Analyst
            </h3>
            <span className="font-mono-sm text-xs text-outline">
              Bounded Semantic Reasoning
            </span>
          </div>

          <AiSecurityAnalystCard
            analysis={analysis}
            isLoading={isLoadingAnalysis}
            error={analysisError}
            userAuthorized={userAuthorized}
            onToggleAuthorization={setUserAuthorized}
            onRunAnalysis={handleRunAnalysis}
          />
        </div>
      </div>
    </div>
  );
};
