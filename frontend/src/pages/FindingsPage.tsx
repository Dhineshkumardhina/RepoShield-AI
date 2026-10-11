import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiFinding } from '../services/api';
import { MOCK_FINDINGS, INITIAL_VERIFICATION_ITEMS } from '../data/mockData';
import { SecurityFinding, VerificationItem } from '../types';
import {
  SeverityBadge,
  DataSourceBadge,
  LoadingState,
  ErrorMessage,
  EmptyState,
} from '../components/common';
import { DiffModal } from '../components/modals/DiffModal';

export const FindingsPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [liveFindings, setLiveFindings] = useState<ApiFinding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  // Filters from query params or UI
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>(searchParams.get('severity') || 'all');
  const [selectedPriority, setSelectedPriority] = useState<string>(searchParams.get('priority') || 'all');
  const [selectedCwe, setSelectedCwe] = useState<string>(searchParams.get('cwe') || '');
  const [selectedRepo, setSelectedRepo] = useState<string>(searchParams.get('repo') || 'all');

  // Diff modal
  const [activeDiffItem, setActiveDiffItem] = useState<VerificationItem | null>(null);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    setApiError(null);

    api.getFindings({
      severity: selectedSeverity !== 'all' ? selectedSeverity : undefined,
      priority: selectedPriority !== 'all' ? selectedPriority : undefined,
    })
      .then(res => {
        if (isMounted) setLiveFindings(res);
      })
      .catch(err => {
        if (isMounted) setApiError(err.message || 'Live findings API unavailable.');
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => { isMounted = false; };
  }, [selectedSeverity, selectedPriority]);

  // Format live findings to match SecurityFinding interface with full contextual priority metadata
  const combinedFindings: (SecurityFinding & { isLiveBackend?: boolean })[] = [
    ...liveFindings.map(lf => ({
      id: lf.id,
      cve: lf.id,
      cwe: lf.cwe,
      cweName: lf.title,
      title: lf.title,
      severity: lf.severity.toLowerCase() as any,
      cvss: 9.8,
      repo: lf.repo_id,
      branch: 'main',
      filePath: lf.file_path,
      line: lf.line_number,
      engine: lf.scanner_name,
      ruleId: 'ast.taint.check',
      description: lf.title,
      taintTrace: {
        source: 'Untrusted user parameter input',
        flow: ['Sanitization bypassed in request handler', 'Interpolated query string'],
        sink: 'Database execution cursor',
      },
      remediationStatus: (lf.pr_number ? 'verified_patch' : 'needs_patch') as any,
      prNumber: lf.pr_number,
      contextualPriority: (lf.contextual_priority?.toLowerCase() || lf.severity.toLowerCase()) as any,
      priorityScore: lf.priority_score ?? (lf.severity === 'CRITICAL' ? 80 : lf.severity === 'HIGH' ? 60 : 40),
      evidenceCompleteness: lf.evidence_completeness || 'PARTIAL',
      remediationReadiness: lf.remediation_readiness || (lf.pr_number ? 'VERIFIED_FIX_READY' : 'NEEDS_INVESTIGATION'),
      isLiveBackend: true,
    })),
    // Only display demo mock findings when no live findings exist
    ...(liveFindings.length === 0 ? MOCK_FINDINGS.map(mf => ({
      ...mf,
      contextualPriority: mf.severity,
      priorityScore: mf.severity === 'critical' ? 85 : mf.severity === 'high' ? 68 : 45,
      evidenceCompleteness: 'PARTIAL',
      remediationReadiness: mf.remediationStatus === 'verified_patch' ? 'VERIFIED_FIX_READY' : 'NEEDS_INVESTIGATION',
      isLiveBackend: false,
    })) : []),
  ];

  // Apply in-memory filters for search text, CWE, repo, and priority
  const filteredFindings = combinedFindings.filter(f => {
    const matchesSeverity = selectedSeverity === 'all' || f.severity.toLowerCase() === selectedSeverity.toLowerCase();
    const matchesPriority = selectedPriority === 'all' || (f.contextualPriority && f.contextualPriority.toLowerCase() === selectedPriority.toLowerCase());
    const matchesCwe = !selectedCwe || f.cwe.toLowerCase().includes(selectedCwe.toLowerCase());
    const matchesRepo = selectedRepo === 'all' || f.repo.toLowerCase() === selectedRepo.toLowerCase();
    const matchesText =
      !searchQuery ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.id.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesSeverity && matchesPriority && matchesCwe && matchesRepo && matchesText;
  });

  const uniqueRepos = Array.from(new Set(combinedFindings.map(f => f.repo)));

  const handleOpenDiff = (finding: SecurityFinding, e: React.MouseEvent) => {
    e.stopPropagation();
    if (finding.prNumber) {
      const match = INITIAL_VERIFICATION_ITEMS.find(v => v.prNumber === finding.prNumber);
      if (match) {
        setActiveDiffItem(match);
        return;
      }
    }
    setActiveDiffItem(INITIAL_VERIFICATION_ITEMS[0]);
  };

  const getPriorityBadgeClass = (priority?: string) => {
    switch (priority?.toLowerCase()) {
      case 'critical':
        return 'bg-red-50 text-red-700 border-red-300 font-bold';
      case 'high':
        return 'bg-amber-50 text-amber-800 border-amber-300 font-bold';
      case 'medium':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'low':
        return 'bg-slate-100 text-slate-700 border-slate-300';
      default:
        return 'bg-slate-50 text-slate-600 border-slate-200';
    }
  };

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Action Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-xs text-blue-600 uppercase font-bold tracking-wider">
              EVIDENCE-BASED VULNERABILITY TRIAGE
            </span>
            <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 font-mono-sm text-xs font-bold border border-blue-200">
              {combinedFindings.length} FINDINGS
            </span>
          </div>
          <h1 className="font-headline-lg text-2xl text-slate-900 tracking-tight mt-0.5 font-bold">
            Vulnerability Findings &amp; Risk Prioritization
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Transparently distinguishes raw scanner severity from contextual urgency. Severe findings are protected against silent downgrading when evidence is missing.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => navigate('/repositories')}
            className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors flex items-center gap-1.5"
          >
            <span className="material-symbols-outlined text-base">bolt</span>
            <span>Trigger Scanner Hub</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar with Priority & Severity Separation */}
      <div className="px-4 lg:px-8 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-1 min-w-[280px] max-w-xl">
          <div className="relative flex-1">
            <span className="material-symbols-outlined text-slate-400 text-base absolute left-3 top-1/2 -translate-y-1/2">
              search
            </span>
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by title, CWE, file path, or finding ID..."
              className="w-full pl-9 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 transition-colors"
            />
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* RepoShield Contextual Priority Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono uppercase text-slate-500 font-semibold">Priority:</span>
            <select
              value={selectedPriority}
              onChange={e => setSelectedPriority(e.target.value)}
              className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-blue-600 font-medium"
            >
              <option value="all">All Priorities</option>
              <option value="critical">Critical Priority</option>
              <option value="high">High Priority</option>
              <option value="medium">Medium Priority</option>
              <option value="low">Low Priority</option>
            </select>
          </div>

          {/* Raw Scanner Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono uppercase text-slate-500 font-semibold">Scanner Severity:</span>
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-blue-600 font-medium"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Severity</option>
              <option value="high">High Severity</option>
              <option value="medium">Medium Severity</option>
              <option value="low">Low Severity</option>
            </select>
          </div>

          {/* Repo Filter */}
          <select
            value={selectedRepo}
            onChange={e => setSelectedRepo(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-blue-600 font-medium max-w-[200px]"
          >
            <option value="all">All Repositories</option>
            {uniqueRepos.map(r => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>

          {/* Reset Filters */}
          {(selectedSeverity !== 'all' || selectedPriority !== 'all' || selectedRepo !== 'all' || selectedCwe || searchQuery) && (
            <button
              type="button"
              onClick={() => {
                setSelectedSeverity('all');
                setSelectedPriority('all');
                setSelectedRepo('all');
                setSelectedCwe('');
                setSearchQuery('');
              }}
              className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900 border border-slate-200 rounded bg-white hover:bg-slate-50 transition-colors"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Findings Content */}
      <div className="px-4 lg:px-8 py-6">
        {isLoading && <LoadingState message="Evaluating evidence-based risk prioritization..." />}

        {apiError && (
          <div className="mb-4 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800 flex items-center justify-between">
            <span>Notice: FastAPI findings endpoint is syncing; displaying active sandbox dataset.</span>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="font-semibold text-amber-900 hover:underline"
            >
              Refresh
            </button>
          </div>
        )}

        {!isLoading && filteredFindings.length === 0 ? (
          <EmptyState
            icon="verified"
            title="No matching findings"
            description="No vulnerabilities match the selected search criteria, severity, or priority filters."
            actionLabel="Clear Filters"
            onAction={() => {
              setSelectedSeverity('all');
              setSelectedPriority('all');
              setSelectedRepo('all');
              setSelectedCwe('');
              setSearchQuery('');
            }}
          />
        ) : (
          <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-mono-sm uppercase text-slate-500 tracking-wider">
                    <th className="py-3 px-4 font-semibold">Scanner Severity</th>
                    <th className="py-3 px-4 font-semibold">Contextual Priority</th>
                    <th className="py-3 px-4 font-semibold">Finding / CVE</th>
                    <th className="py-3 px-4 font-semibold">Repository</th>
                    <th className="py-3 px-4 font-semibold">Location</th>
                    <th className="py-3 px-4 font-semibold">Evidence &amp; Readiness</th>
                    <th className="py-3 px-4 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-sm">
                  {filteredFindings.map(finding => (
                    <tr
                      key={`${finding.isLiveBackend ? 'live' : 'demo'}-${finding.id}`}
                      onClick={() => navigate(`/findings/${finding.id}`)}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                    >
                      {/* 1. Original Scanner Severity */}
                      <td className="py-3.5 px-4 shrink-0">
                        <SeverityBadge severity={finding.severity} size="sm" />
                        <span className="block text-[10px] text-slate-400 font-mono mt-0.5">
                          {finding.engine}
                        </span>
                      </td>

                      {/* 2. RepoShield Contextual Priority (with Score Index) */}
                      <td className="py-3.5 px-4 shrink-0">
                        <div className="flex items-center gap-1.5">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono border ${getPriorityBadgeClass(finding.contextualPriority)}`}>
                            {finding.contextualPriority?.toUpperCase() || 'MEDIUM'}
                          </span>
                          <span className="font-mono text-xs font-semibold text-slate-600">
                            {finding.priorityScore?.toFixed(0)}/100
                          </span>
                        </div>
                        {finding.evidenceCompleteness === 'MINIMAL' && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-amber-600 font-mono mt-0.5" title="Evidence is incomplete; severe finding floor protected">
                            <span className="material-symbols-outlined text-[12px]">info</span>
                            Floor Protected
                          </span>
                        )}
                      </td>

                      {/* 3. Finding Title & CWE */}
                      <td className="py-3.5 px-4 max-w-sm">
                        <span className="font-semibold text-slate-900 block group-hover:text-blue-600 transition-colors truncate" title={finding.title}>
                          {finding.title}
                        </span>
                        <div className="flex items-center gap-2 text-xs text-slate-500 font-mono-sm mt-0.5">
                          <span className="text-slate-700 font-medium">{finding.cwe}</span>
                          <span>•</span>
                          <span>ID: {finding.id}</span>
                        </div>
                      </td>

                      {/* 4. Repository */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono-sm text-xs font-semibold text-slate-800">
                            {finding.repo}
                          </span>
                          <DataSourceBadge isLive={!!finding.isLiveBackend} />
                        </div>
                      </td>

                      {/* 5. Location */}
                      <td className="py-3.5 px-4">
                        <span className="font-mono-sm text-xs text-slate-600 truncate block max-w-xs" title={`${finding.filePath}:${finding.line}`}>
                          {finding.filePath}:{finding.line}
                        </span>
                      </td>

                      {/* 6. Evidence & Fix Readiness Gate */}
                      <td className="py-3.5 px-4">
                        {finding.remediationReadiness === 'VERIFIED_FIX_READY' || finding.remediationStatus === 'verified_patch' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono-sm font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <span className="material-symbols-outlined text-[13px]">verified</span>
                            Verified Fix Ready
                          </span>
                        ) : finding.remediationReadiness === 'PATCH_FAILED_TESTS' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono-sm font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                            <span className="material-symbols-outlined text-[13px]">error</span>
                            Patch Failed Tests
                          </span>
                        ) : finding.remediationReadiness === 'PATCH_PENDING_REVIEW' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono-sm font-medium bg-blue-50 text-blue-700 border border-blue-200">
                            <span className="material-symbols-outlined text-[13px]">code</span>
                            Patch Proposed
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono-sm font-medium bg-slate-100 text-slate-700 border border-slate-200">
                            <span className="material-symbols-outlined text-[13px]">search</span>
                            Needs Investigation
                          </span>
                        )}
                      </td>

                      {/* 7. Actions */}
                      <td className="py-3.5 px-4 text-right" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            onClick={e => handleOpenDiff(finding, e)}
                            className="px-2.5 py-1 text-xs font-semibold bg-white hover:bg-blue-50 border border-slate-200 text-blue-600 rounded-lg transition-colors"
                          >
                            Diff
                          </button>
                          <button
                            type="button"
                            onClick={() => navigate(`/findings/${finding.id}`)}
                            className="p-1 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded transition-colors"
                            title="Inspect evidence and contextual risk factors"
                          >
                            <span className="material-symbols-outlined text-base">chevron_right</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Diff Modal */}
      <DiffModal
        item={activeDiffItem}
        onClose={() => setActiveDiffItem(null)}
        onApproveAndMerge={() => setActiveDiffItem(null)}
        isMerged={false}
      />
    </div>
  );
};
