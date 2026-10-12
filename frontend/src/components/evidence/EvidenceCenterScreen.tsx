import React, { useState } from 'react';
import { MOCK_COMPLIANCE_FRAMEWORKS } from '../../data/mockData';
import { SecurityEvidenceRecord } from '../../services/api';

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
          <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-mono text-[11px] font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">biotech</span>
            <span>SCANNER OBSERVED</span>
          </span>
        );
      case 'sandbox_observed':
        return (
          <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[11px] font-bold flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">shield</span>
            <span>SANDBOX OBSERVED</span>
          </span>
        );
      case 'ai_generated_commentary':
        return (
          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[11px] font-medium flex items-center gap-1 border border-slate-200">
            <span className="material-symbols-outlined text-xs">fact_check</span>
            <span>Automated Analysis</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono text-[11px]">
            {provenance.replace('_', ' ').toUpperCase()}
          </span>
        );
    }
  };

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-500 uppercase font-semibold">
              Evidence Audit
            </span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[10px] font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
              SHA-256 Verifiable
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Compliance Frameworks &amp; Cryptographic Proofs
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Tamper-evident logs of scanner outputs, compiler AST proofs, and ephemeral test runs.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={() => onExportReport('findings', 'markdown')}
            disabled={isExporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-mono text-xs font-semibold transition-colors border border-slate-200 shadow-2xs"
          >
            <span className="material-symbols-outlined text-sm text-slate-500">description</span>
            <span>Export Findings (MD)</span>
          </button>
          <button
            onClick={() => onExportReport('findings', 'json')}
            disabled={isExporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-mono text-xs font-semibold transition-colors border border-slate-200 shadow-2xs"
          >
            <span className="material-symbols-outlined text-sm text-slate-500">data_object</span>
            <span>Export Findings (JSON)</span>
          </button>
          <button
            onClick={onOpenExportModal}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-slate-900 text-white hover:bg-slate-800 text-xs font-medium transition-colors shadow-2xs"
          >
            <span className="material-symbols-outlined text-sm">download</span>
            <span>Auditor Bundle (SARIF)</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="px-4 lg:px-8 py-6 space-y-6">
        {/* Mandatory Evidence Integrity Notice */}
        <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl text-amber-950 text-xs space-y-1 shadow-2xs">
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
              className="p-4 rounded-xl bg-white border border-slate-200 flex flex-col justify-between shadow-2xs"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-slate-800 uppercase font-bold text-[10px]">
                    {fw.standard}
                  </span>
                  <span
                    className={`font-mono text-[10px] px-1.5 py-0.5 rounded font-bold border ${
                      fw.status === 'Audit Ready'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : fw.status === 'Compliant'
                        ? 'bg-slate-100 text-slate-700 border-slate-200'
                        : 'bg-rose-50 text-rose-700 border-rose-200'
                    }`}
                  >
                    {fw.status}
                  </span>
                </div>
                <h3 className="text-slate-900 text-sm font-semibold mb-1">
                  {fw.name}
                </h3>
                <p className="text-xs text-slate-500 mb-3 leading-relaxed">
                  {fw.description}
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between font-mono text-xs mb-1">
                  <span className="text-slate-500">Passed Controls</span>
                  <span className="font-bold text-slate-900">
                    {fw.passedControls} / {fw.totalControls} ({fw.complianceScore}%)
                  </span>
                </div>
                <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-slate-900 h-full"
                    style={{ width: `${fw.complianceScore}%` }}
                  />
                </div>
                <span className="text-[10px] font-mono text-slate-400 mt-1 block">
                  Last evaluated: {fw.lastEvaluated}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Checks Not Performed Section */}
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-slate-900 text-sm font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-amber-600 text-base">checklist_rtl</span>
              Identified Checks Not Performed (Omission Auditing)
            </h3>
            <span className="font-mono text-[11px] text-slate-400">Evaluated Security Scope</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Dynamic Taint (DAST)</span>
              <span className="text-slate-800 font-semibold block mt-0.5">Not Configured</span>
              <p className="text-[10px] text-slate-500 mt-1 font-sans">No live server agent attached to execute active payloads.</p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Runtime IAST Agent</span>
              <span className="text-slate-800 font-semibold block mt-0.5">Not Attached</span>
              <p className="text-[10px] text-slate-500 mt-1 font-sans">Bytecode instrumentation agent disabled in static evaluation.</p>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Database Privilege Audit</span>
              <span className="text-slate-800 font-semibold block mt-0.5">Unverified</span>
              <p className="text-[10px] text-slate-500 mt-1 font-sans">Production database grant permissions could not be checked.</p>
            </div>
          </div>
        </div>

        {/* Granular Evidence Records Table */}
        <div className="rounded-xl bg-white shadow-2xs overflow-hidden border border-slate-200">
          <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50">
            <div>
              <h3 className="text-slate-900 text-sm font-bold flex items-center gap-2">
                <span className="material-symbols-outlined text-slate-700 text-base">fact_check</span>
                Sanitized Evidence Records &amp; Content Hashes ({filteredEvidence.length} Artifacts)
              </h3>
              <p className="font-mono text-xs text-slate-500 mt-0.5">
                Multi-tenant isolated • Secrets redacted • SHA-256 tamper-evident
              </p>
            </div>

            {/* Category filter */}
            <div className="flex items-center gap-1.5 text-xs font-mono">
              {['all', 'scanner_output', 'patch_diff', 'test_result', 'ai_commentary'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded-md transition-colors border ${
                    selectedCategory === cat
                      ? 'bg-slate-900 text-white border-slate-900 font-semibold shadow-2xs'
                      : 'bg-white text-slate-600 hover:text-slate-900 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {cat === 'all' ? 'All' : cat.replace('_', ' ').split(' ')[0]}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto w-full">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="bg-slate-50/80 text-slate-500 uppercase tracking-wider border-b border-slate-200 text-[10px]">
                  <th className="py-2.5 px-4 font-semibold">Artifact ID &amp; Title</th>
                  <th className="py-2.5 px-4 font-semibold">Provenance</th>
                  <th className="py-2.5 px-4 font-semibold">Tool &amp; Version</th>
                  <th className="py-2.5 px-4 font-semibold">Content Hash (SHA-256)</th>
                  <th className="py-2.5 px-4 text-right font-semibold">Recorded At</th>
                  <th className="py-2.5 px-4 text-right font-semibold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-sans text-xs">
                {filteredEvidence.map(ev => (
                  <tr key={ev.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3 px-4 font-mono">
                      <div className="font-bold text-slate-900">{ev.id}</div>
                      <div className="text-slate-600 text-xs font-sans truncate max-w-xs">{ev.title}</div>
                    </td>
                    <td className="py-3 px-4">
                      {getProvenanceBadge(ev.provenance)}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs">
                      <span className="font-semibold text-slate-800">{ev.tool_name}</span>
                      {ev.tool_version && <span className="text-slate-500 block text-[11px]">{ev.tool_version}</span>}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-600 truncate max-w-[150px]" title={ev.content_hash}>
                      {ev.content_hash?.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-right font-mono text-[11px] text-slate-400">
                      {new Date(ev.recorded_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      <button
                        onClick={() => onInspectEvidence(ev)}
                        className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold text-xs transition-colors border border-slate-200"
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
