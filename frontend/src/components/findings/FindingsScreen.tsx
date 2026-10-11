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
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest border-b border-outline-variant/60 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-label-caps text-error uppercase font-bold tracking-wider">
              APPSEC VULNERABILITY TRIAGE MATRIX
            </span>
            <span className="px-1.5 py-0.5 rounded bg-error-container text-error font-mono-sm text-mono-sm font-bold">
              14 CRITICAL / HIGH
            </span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Security Findings &amp; AST Taint Traces
          </h1>
        </div>

        {/* Severity & CWE Filter */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="inline-flex p-0.5 rounded bg-surface-container-high font-mono-sm text-xs">
            <button
              onClick={() => setSelectedSeverity('all')}
              className={`px-2.5 py-1 rounded transition-colors ${
                selectedSeverity === 'all' ? 'bg-surface-container-lowest text-on-surface font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setSelectedSeverity('critical')}
              className={`px-2.5 py-1 rounded transition-colors ${
                selectedSeverity === 'critical' ? 'bg-error-container text-error font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              Critical (14)
            </button>
            <button
              onClick={() => setSelectedSeverity('high')}
              className={`px-2.5 py-1 rounded transition-colors ${
                selectedSeverity === 'high' ? 'bg-surface-container-lowest text-on-surface font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              High (32)
            </button>
          </div>

          <select
            value={cweFilter}
            onChange={e => setCweFilter(e.target.value)}
            className="px-2.5 py-1 rounded bg-surface-container-low border border-outline-variant/60 font-mono-sm text-xs text-on-surface focus:outline-none"
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
      <div className="px-4 lg:px-gutter-desktop py-space-lg grid grid-cols-1 xl:grid-cols-12 gap-space-lg">
        {/* Left: Findings List (7 cols) */}
        <div className="xl:col-span-7 space-y-3">
          {filteredFindings.map(finding => {
            const isSelected = activeFinding?.id === finding.id;

            return (
              <div
                key={finding.id}
                onClick={() => setActiveFinding(finding)}
                className={`p-4 rounded border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-primary bg-surface-container-lowest shadow-sm'
                    : 'border-outline-variant/60 bg-surface-container-lowest hover:border-outline'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    {finding.severity === 'critical' ? (
                      <span className="px-2 py-0.5 rounded bg-error-container text-error font-mono-sm font-bold text-xs uppercase">
                        CRITICAL • CVSS {finding.cvss}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-surface-container-high text-on-surface font-mono-sm font-bold text-xs uppercase">
                        HIGH • CVSS {finding.cvss}
                      </span>
                    )}
                    <span className="font-mono-sm text-xs text-on-surface-variant font-medium">
                      {finding.cwe}: {finding.cweName}
                    </span>
                  </div>
                  <span className="font-mono-sm text-xs text-primary font-bold">
                    {finding.cve}
                  </span>
                </div>

                <h3 className="font-headline-sm text-on-surface text-sm font-semibold mb-1">
                  {finding.title}
                </h3>

                <div className="flex items-center gap-3 text-mono-sm text-xs text-on-surface-variant mt-2">
                  <span className="flex items-center gap-1 font-semibold text-on-surface">
                    <span className="material-symbols-outlined text-xs text-primary">folder</span>
                    {finding.repo}
                  </span>
                  <span>•</span>
                  <span>{finding.filePath}:{finding.line}</span>
                  <span>•</span>
                  <span className="text-tertiary font-medium">
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
            <div className="sticky top-20 rounded bg-surface-container-lowest p-space-md border border-outline-variant/60 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-outline-variant/60">
                <div>
                  <span className="font-label-caps text-primary uppercase font-bold text-[10px]">
                    INTER-PROCEDURAL TAINT TRACE
                  </span>
                  <h3 className="font-headline-sm text-on-surface text-base">
                    {activeFinding.cve} ({activeFinding.cwe})
                  </h3>
                </div>
                <div className="flex items-center gap-1.5">
                  {onNavigateToAnalyzer && (
                    <button
                      onClick={() => onNavigateToAnalyzer(activeFinding)}
                      className="px-2.5 py-1 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-body-sm text-xs font-semibold hover:bg-tertiary-fixed-dim transition-colors flex items-center gap-1"
                    >
                      <span className="material-symbols-outlined text-xs">psychology</span>
                      <span>AI Analysis</span>
                    </button>
                  )}
                  {activeFinding.prNumber && (
                    <button
                      onClick={() => onOpenDiffForFinding(activeFinding)}
                      className="px-3 py-1 rounded bg-primary text-on-primary font-body-sm text-xs font-medium hover:bg-on-primary-fixed-variant shadow-xs"
                    >
                      Inspect AST Fix
                    </button>
                  )}
                </div>
              </div>

              {/* Taint Flow Step Pipeline */}
              <div>
                <span className="font-label-caps text-on-surface-variant uppercase font-semibold block mb-2">
                  AST Dataflow Pipeline (Source to Sink)
                </span>
                <div className="space-y-2 font-mono-sm text-xs">
                  {/* Source */}
                  <div className="p-2.5 rounded bg-error-container/30 border border-error/20">
                    <div className="font-bold text-error flex items-center gap-1 mb-0.5">
                      <span className="material-symbols-outlined text-xs">input</span>
                      <span>TAINT SOURCE (Untrusted Entry)</span>
                    </div>
                    <code className="text-on-surface">{activeFinding.taintTrace.source}</code>
                  </div>

                  {/* Flow Steps */}
                  {activeFinding.taintTrace.flow.map((step, idx) => (
                    <div key={idx} className="p-2 rounded bg-surface-container-low border border-outline-variant/60">
                      <div className="text-on-surface-variant text-[10px] uppercase font-bold mb-0.5">
                        PROPAGATION HOP {idx + 1}
                      </div>
                      <code className="text-on-surface">{step}</code>
                    </div>
                  ))}

                  {/* Sink */}
                  <div className="p-2.5 rounded bg-[#ba1a1a]/10 border border-error/40">
                    <div className="font-bold text-error flex items-center gap-1 mb-0.5">
                      <span className="material-symbols-outlined text-xs">dangerous</span>
                      <span>EXECUTION SINK (Vulnerable Point)</span>
                    </div>
                    <code className="text-on-surface">{activeFinding.taintTrace.sink}</code>
                  </div>
                </div>
              </div>

              {/* Description & Engine Rule */}
              <div className="p-3 rounded bg-surface-container-low border border-outline-variant/60 font-body-sm text-xs space-y-1.5">
                <span className="font-label-caps text-on-surface-variant uppercase block font-semibold">
                  Rule &amp; Remediator Details
                </span>
                <p className="text-on-surface">{activeFinding.description}</p>
                <p className="font-mono-sm text-outline pt-1">
                  Engine: <span className="text-on-surface font-semibold">{activeFinding.engine}</span> • Rule: <code className="text-primary font-bold">{activeFinding.ruleId}</code>
                </p>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded bg-surface-container-lowest border border-outline-variant/60 text-center text-on-surface-variant font-body-sm">
              Select a security finding to inspect its taint graph and sandbox fix status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
