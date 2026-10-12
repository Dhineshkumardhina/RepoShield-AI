import React, { useState } from 'react';
import { SecurityFinding, Severity } from '../../types';

interface FindingsScreenProps {
  findings: SecurityFinding[];
  initialCweFilter?: string;
  onOpenDiffForFinding: (finding: SecurityFinding) => void;
  onNavigateToAnalyzer?: (finding?: SecurityFinding) => void;
}

export const FindingsScreen: React.FC<FindingsScreenProps> = ({
  findings,
  initialCweFilter,
  onOpenDiffForFinding,
  onNavigateToAnalyzer
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<'all' | Severity>('all');
  const [cweFilter, setCweFilter] = useState<string>(initialCweFilter || 'all');
  const [activeFinding, setActiveFinding] = useState<SecurityFinding | null>(findings[0] || null);

  const filteredFindings = findings.filter(f => {
    const matchSev = selectedSeverity === 'all' || f.severity === selectedSeverity;
    const matchCwe = cweFilter === 'all' || f.cwe === cweFilter;
    return matchSev && matchCwe;
  });

  return (
    <div className="flex flex-col w-full">
      {/* Header */}
      <div className="px-6 py-4 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-rose-600 uppercase font-bold tracking-wider">
              APPSEC VULNERABILITY TRIAGE MATRIX
            </span>
            <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 font-mono text-[10px] font-bold border border-rose-200">
              14 CRITICAL / HIGH
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Security Findings &amp; AST Taint Traces
          </h1>
        </div>

        {/* Severity & CWE Filter */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="inline-flex p-0.5 rounded-lg bg-slate-100 font-mono text-xs border border-slate-200">
            <button
              onClick={() => setSelectedSeverity('all')}
              className={`px-3 py-1 rounded-md transition-colors ${
                selectedSeverity === 'all' ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setSelectedSeverity('critical')}
              className={`px-3 py-1 rounded-md transition-colors ${
                selectedSeverity === 'critical' ? 'bg-rose-600 text-white font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Critical (14)
            </button>
            <button
              onClick={() => setSelectedSeverity('high')}
              className={`px-3 py-1 rounded-md transition-colors ${
                selectedSeverity === 'high' ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              High (32)
            </button>
          </div>

          <select
            value={cweFilter}
            onChange={e => setCweFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 font-mono text-xs text-slate-800 focus:outline-none focus:ring-1 focus:ring-slate-900 shadow-2xs"
          >
            <option value="all">All Incident Vectors</option>
            <option value="CWE-79">CWE-79: Cross-Site Scripting</option>
            <option value="CWE-798">CWE-798: Hardcoded Secrets</option>
            <option value="CWE-89">CWE-89: SQL Injection</option>
            <option value="CWE-22">CWE-22: Path Traversal</option>
            <option value="CWE-400">CWE-400: Resource Consumption</option>
          </select>
        </div>
      </div>

      {/* Main Grid: Left Table, Right Deep Trace Inspector */}
      <div className="p-6 grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Left: Findings List (7 cols) */}
        <div className="xl:col-span-7 space-y-3">
          {filteredFindings.map(finding => {
            const isSelected = activeFinding?.id === finding.id;

            return (
              <div
                key={finding.id}
                onClick={() => setActiveFinding(finding)}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-slate-900 bg-white ring-1 ring-slate-900/10 shadow-xs'
                    : 'border-slate-200 bg-white hover:border-slate-300 shadow-2xs'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    {finding.severity === 'critical' ? (
                      <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-mono font-bold text-[10px] uppercase">
                        CRITICAL • CVSS {finding.cvss}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 font-mono font-bold text-[10px] uppercase">
                        HIGH • CVSS {finding.cvss}
                      </span>
                    )}
                    <span className="font-mono text-xs text-slate-500 font-medium">
                      {finding.cwe}: {finding.cweName}
                    </span>
                  </div>
                  <span className="font-mono text-xs text-blue-600 font-semibold">
                    {finding.cve}
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-slate-900 mb-1">
                  {finding.title}
                </h3>

                <div className="flex items-center gap-3 font-mono text-xs text-slate-500 mt-2">
                  <span className="flex items-center gap-1 font-semibold text-slate-800">
                    <span className="material-symbols-outlined text-xs text-slate-600">folder</span>
                    {finding.repo}
                  </span>
                  <span>•</span>
                  <span>{finding.filePath}:{finding.line}</span>
                  <span>•</span>
                  <span className="text-emerald-700 font-medium">
                    {finding.remediationStatus === 'verified_patch'
                      ? '✓ Verified Patch Available'
                      : finding.remediationStatus === 'failed_patch'
                      ? '⚠ Patch Regressed'
                      : 'Fix In Queue'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: AST Taint Path & Code Inspector (5 cols) */}
        <div className="xl:col-span-5">
          {activeFinding ? (
            <div className="sticky top-20 rounded-xl bg-white p-5 border border-slate-200 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                <div>
                  <span className="font-mono text-blue-600 uppercase font-bold text-[10px] tracking-wide">
                    INTER-PROCEDURAL TAINT TRACE
                  </span>
                  <h3 className="font-bold text-slate-900 text-base">
                    {activeFinding.cve} ({activeFinding.cwe})
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  {onNavigateToAnalyzer && (
                    <button
                      onClick={() => onNavigateToAnalyzer(activeFinding)}
                      className="px-2.5 py-1 rounded-lg bg-slate-100 text-slate-700 font-medium text-xs hover:bg-slate-200 transition-colors flex items-center gap-1 border border-slate-200"
                    >
                      <span className="material-symbols-outlined text-xs">psychology</span>
                      <span>AI Analysis</span>
                    </button>
                  )}
                  {activeFinding.prNumber && (
                    <button
                      onClick={() => onOpenDiffForFinding(activeFinding)}
                      className="px-3 py-1 rounded-lg bg-slate-900 text-white font-medium text-xs hover:bg-slate-800 shadow-2xs transition-colors"
                    >
                      Inspect AST Fix
                    </button>
                  )}
                </div>
              </div>

              {/* Taint Flow Step Pipeline */}
              <div>
                <span className="font-mono text-[10px] uppercase font-semibold text-slate-500 block mb-2">
                  AST Dataflow Pipeline (Source to Sink)
                </span>
                <div className="space-y-2 font-mono text-xs">
                  {/* Source */}
                  <div className="p-3 rounded-lg bg-rose-50/60 border border-rose-200">
                    <div className="font-bold text-rose-700 flex items-center gap-1 mb-1 text-[11px]">
                      <span className="material-symbols-outlined text-xs">input</span>
                      <span>TAINT SOURCE (Untrusted Entry)</span>
                    </div>
                    <code className="text-slate-900 bg-white/70 px-1.5 py-0.5 rounded border border-rose-100 block overflow-x-auto">{activeFinding.taintTrace.source}</code>
                  </div>

                  {/* Flow Steps */}
                  {activeFinding.taintTrace.flow.map((step, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                      <div className="text-slate-500 text-[10px] uppercase font-bold mb-1">
                        PROPAGATION HOP {idx + 1}
                      </div>
                      <code className="text-slate-800 block overflow-x-auto">{step}</code>
                    </div>
                  ))}

                  {/* Sink */}
                  <div className="p-3 rounded-lg bg-rose-50/60 border border-rose-300">
                    <div className="font-bold text-rose-800 flex items-center gap-1 mb-1 text-[11px]">
                      <span className="material-symbols-outlined text-xs">dangerous</span>
                      <span>EXECUTION SINK (Vulnerable Point)</span>
                    </div>
                    <code className="text-slate-900 bg-white/70 px-1.5 py-0.5 rounded border border-rose-200 block overflow-x-auto">{activeFinding.taintTrace.sink}</code>
                  </div>
                </div>
              </div>

              {/* Description & Engine Rule */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1.5">
                <span className="font-mono text-[10px] text-slate-500 uppercase block font-semibold">
                  Rule &amp; Remediator Details
                </span>
                <p className="text-slate-700 leading-relaxed">{activeFinding.description}</p>
                <div className="font-mono text-[11px] text-slate-500 pt-1 border-t border-slate-200 flex items-center gap-2">
                  <span>Engine: <strong className="text-slate-800 font-semibold">{activeFinding.engine}</strong></span>
                  <span>•</span>
                  <span>Rule: <code className="text-blue-700 font-semibold">{activeFinding.ruleId}</code></span>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-white border border-slate-200 text-center text-slate-500 text-xs">
              Select a security finding to inspect its taint graph and sandbox fix status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
