import React, { useState } from 'react';
import { MOCK_COMPLIANCE_FRAMEWORKS } from '../../data/mockData';
import { SecurityEvidenceRecord, SecurityReportResponse } from '../../services/api';

interface EvidenceCenterScreenProps {
  evidenceList: SecurityEvidenceRecord[];
  onOpenExportModal: () => void;
  onInspectEvidence: (evidence: SecurityEvidenceRecord) => void;
  onExportReport: (type: 'findings' | 'verification', format: 'markdown' | 'json') => void;
  isExporting: boolean;
}

export const EvidenceCenterScreen: React.FC<EvidenceCenterScreenProps> = ({
  evidenceList,
  onOpenExportModal,
  onInspectEvidence,
  onExportReport,
  isExporting,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const filteredEvidence = selectedCategory === 'all'
    ? evidenceList
    : evidenceList.filter(e => e.evidence_category === selectedCategory);

  const getProvenanceBadge = (provenance: string) => {
    switch (provenance) {
      case 'scanner_observed':
        return (
          <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-mono-sm text-[11px] font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">biotech</span>
            <span>SCANNER OBSERVED</span>
          </span>
        );
      case 'sandbox_observed':
        return (
          <span className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-mono-sm text-[11px] font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">shield</span>
            <span>SANDBOX OBSERVED</span>
          </span>
        );
      case 'ai_generated_commentary':
        return (
          <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-mono-sm text-[11px] font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">psychology</span>
            <span>AI COMMENTARY (ADVISORY)</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono-sm text-[11px]">
            {provenance.replace('_', ' ').toUpperCase()}
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col w-full">
      {/* Header */}
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest border-b border-outline-variant/60 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-label-caps text-primary uppercase font-bold tracking-wider">
              CRYPTOGRAPHIC EVIDENCE &amp; AUDIT TRAIL
            </span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono-sm text-mono-sm font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              TAMPER EVIDENT (SHA-256)
            </span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Compliance Frameworks &amp; Cryptographic Proofs
          </h1>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={() => onExportReport('findings', 'markdown')}
            disabled={isExporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-variant text-slate-800 font-mono-sm text-xs font-semibold transition-colors border border-outline-variant/60 shadow-xs"
          >
            <span className="material-symbols-outlined text-sm text-primary">description</span>
            <span>Export Findings (MD)</span>
          </button>
          <button
            onClick={() => onExportReport('findings', 'json')}
            disabled={isExporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-variant text-slate-800 font-mono-sm text-xs font-semibold transition-colors border border-outline-variant/60 shadow-xs"
          >
            <span className="material-symbols-outlined text-sm text-primary">data_object</span>
            <span>Export Findings (JSON)</span>
          </button>
          <button
            onClick={onOpenExportModal}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-primary text-white hover:bg-blue-700 font-body-sm font-semibold transition-colors shadow-xs"
          >
            <span className="material-symbols-outlined text-base">download</span>
            <span>Auditor Bundle (SARIF)</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="px-4 lg:px-gutter-desktop py-space-lg space-y-space-lg">
        {/* Mandatory Evidence Integrity Notice */}
        <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-950 text-xs space-y-1.5">
          <div className="flex items-center gap-2 font-bold uppercase tracking-wider text-amber-900">
            <span className="material-symbols-outlined text-base text-amber-700">security_update_good</span>
            Evidence Integrity &amp; Provenance Notice
          </div>
          <p className="text-amber-800 leading-relaxed font-sans">
            Content hashes assist in detecting accidental alterations but do not alone prove authenticity or original provenance. Numerical priority scores represent contextual triage indices and are not validated probabilities of real-world exploitation. Scanner evidence is strictly isolated from AI-generated commentary.
          </p>
        </div>

        {/* Framework Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {MOCK_COMPLIANCE_FRAMEWORKS.map(fw => (
            <div
              key={fw.id}
              className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/60 flex flex-col justify-between shadow-xs"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-label-caps text-primary uppercase font-bold text-[10px]">
                    {fw.standard}
                  </span>
                  <span
                    className={`font-mono-sm text-[10px] px-1.5 py-0.5 rounded font-bold ${
                      fw.status === 'Audit Ready'
                        ? 'bg-emerald-100 text-emerald-800'
                        : fw.status === 'Compliant'
                        ? 'bg-surface-container-high text-on-surface'
                        : 'bg-rose-100 text-rose-800'
                    }`}
                  >
                    {fw.status}
                  </span>
                </div>
                <h3 className="font-headline-sm text-on-surface text-sm font-semibold mb-2">
                  {fw.name}
                </h3>
                <p className="font-body-sm text-xs text-on-surface-variant mb-3 leading-relaxed">
                  {fw.description}
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between font-mono-sm text-xs mb-1">
                  <span className="text-on-surface-variant">Passed Controls</span>
                  <span className="font-bold text-on-surface">
                    {fw.passedControls} / {fw.totalControls} ({fw.complianceScore}%)
                  </span>
                </div>
                <div className="w-full bg-surface-container h-1.5 rounded overflow-hidden">
                  <div
                    className="bg-primary h-full"
                    style={{ width: `${fw.complianceScore}%` }}
                  ></div>
                </div>
                <span className="text-[10px] font-mono-sm text-outline mt-1 block">
                  Last evaluated: {fw.lastEvaluated}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Checks Not Performed Section */}
        <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/60 shadow-xs space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="font-headline-sm text-on-surface text-sm font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-amber-600 text-base">checklist_rtl</span>
              Identified Checks Not Performed (Omission Auditing)
            </h3>
            <span className="font-mono-sm text-[11px] text-outline">Evaluated Security Scope</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono-sm">
            <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Dynamic Taint (DAST)</span>
              <span className="text-slate-700 font-semibold block mt-0.5">Not Configured</span>
              <p className="text-[10px] text-slate-500 mt-1">No live server agent attached to execute active payloads.</p>
            </div>
            <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Runtime IAST Agent</span>
              <span className="text-slate-700 font-semibold block mt-0.5">Not Attached</span>
              <p className="text-[10px] text-slate-500 mt-1">Bytecode instrumentation agent disabled in static evaluation.</p>
            </div>
            <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Database Privilege Audit</span>
              <span className="text-slate-700 font-semibold block mt-0.5">Unverified</span>
              <p className="text-[10px] text-slate-500 mt-1">Production database grant permissions could not be checked.</p>
            </div>
          </div>
        </div>

        {/* Granular Evidence Records Table */}
        <div className="rounded-lg bg-surface-container-lowest shadow-xs overflow-hidden border border-outline-variant/60">
          <div className="p-4 border-b border-outline-variant/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="font-headline-sm text-on-surface text-base font-bold flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-base">fact_check</span>
                Sanitized Evidence Records &amp; Content Hashes ({filteredEvidence.length} Artifacts)
              </h3>
              <p className="font-mono-sm text-xs text-outline mt-0.5">
                Multi-tenant isolated • Secrets redacted • SHA-256 tamper-evident
              </p>
            </div>

            {/* Category filter */}
            <div className="flex items-center gap-1.5 text-xs font-mono-sm">
              {['all', 'scanner_output', 'patch_diff', 'test_result', 'ai_commentary'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded-md transition-colors ${
                    selectedCategory === cat
                      ? 'bg-primary text-white font-bold'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {cat === 'all' ? 'All' : cat.replace('_', ' ').split(' ')[0]}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto w-full">
            <table className="w-full text-left border-collapse font-mono-sm text-xs">
              <thead>
                <tr className="bg-surface-container-low text-on-surface-variant font-label-caps uppercase border-b border-outline-variant/60 text-[11px]">
                  <th className="py-2.5 px-4">Artifact ID &amp; Title</th>
                  <th className="py-2.5 px-4">Provenance</th>
                  <th className="py-2.5 px-4">Tool &amp; Version</th>
                  <th className="py-2.5 px-4">Content Hash (SHA-256)</th>
                  <th className="py-2.5 px-4 text-right">Recorded At</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/60 font-body-sm text-xs">
                {filteredEvidence.map(ev => (
                  <tr key={ev.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-3 px-4 font-mono-sm">
                      <div className="font-bold text-primary">{ev.id}</div>
                      <div className="text-on-surface text-xs font-sans truncate max-w-xs">{ev.title}</div>
                    </td>
                    <td className="py-3 px-4">
                      {getProvenanceBadge(ev.provenance)}
                    </td>
                    <td className="py-3 px-4 font-mono-sm text-xs">
                      <span className="font-semibold text-slate-800">{ev.tool_name}</span>
                      {ev.tool_version && <span className="text-slate-500 block text-[11px]">{ev.tool_version}</span>}
                    </td>
                    <td className="py-3 px-4 font-mono-sm text-[11px] text-slate-600 truncate max-w-[150px]" title={ev.content_hash}>
                      {ev.content_hash?.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-right font-mono-sm text-[11px] text-outline">
                      {new Date(ev.recorded_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3 px-4 text-right font-mono-sm">
                      <button
                        onClick={() => onInspectEvidence(ev)}
                        className="px-2.5 py-1 rounded bg-blue-50 text-primary hover:bg-blue-100 font-semibold text-xs transition-colors"
                      >
                        Inspect Payload
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
