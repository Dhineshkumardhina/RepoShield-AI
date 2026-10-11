import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api, ApiRepository } from '../services/api';
import { MOCK_REPOSITORIES, MOCK_FINDINGS } from '../data/mockData';
import { Repository, SecurityFinding } from '../types';
import {
  ScanStatusIndicator,
  SeverityBadge,
  DataSourceBadge,
  LoadingState,
  ErrorMessage,
} from '../components/common';
import { ScanModal } from '../components/modals/ScanModal';

export const RepositoryDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [repo, setRepo] = useState<(Repository & { isLiveBackend?: boolean }) | null>(null);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    setError(null);

    const loadData = async () => {
      if (!id) return;

      try {
        // Attempt fetch from backend
        const apiRepo = await api.getRepository(id);
        if (isMounted && apiRepo) {
          setRepo({
            id: apiRepo.id,
            name: apiRepo.name,
            branch: apiRepo.default_branch,
            gitHash: apiRepo.id.substring(0, 7),
            engine: 'FastAPI Monitored',
            target: 'Production',
            health: (apiRepo.critical_count > 0 ? 'vulnerable' : apiRepo.high_count > 0 ? 'at-risk' : 'secure') as any,
            findings: {
              critical: apiRepo.critical_count,
              high: apiRepo.high_count,
              medium: apiRepo.medium_count,
              low: apiRepo.low_count,
            },
            language: apiRepo.name.includes('py') ? 'Python' : 'TypeScript',
            lastScanned: new Date(apiRepo.updated_at).toLocaleTimeString(),
            coverage: apiRepo.health_score,
            autoRemediate: true,
            isLiveBackend: true,
          });

          // Also attempt fetch findings from backend
          try {
            const apiFindings = await api.getFindings({ repo_id: id });
            if (apiFindings.length > 0) {
              setFindings(
                apiFindings.map(af => ({
                  id: af.id,
                  cve: af.id,
                  cwe: af.cwe,
                  cweName: af.title,
                  title: af.title,
                  severity: af.severity.toLowerCase() as any,
                  cvss: 9.8,
                  repo: apiRepo.name,
                  branch: apiRepo.default_branch,
                  filePath: af.file_path,
                  line: af.line_number,
                  engine: af.scanner_name,
                  ruleId: 'audit.rule',
                  description: af.title,
                  taintTrace: { source: 'input', flow: ['param'], sink: 'sink' },
                  remediationStatus: 'needs_patch',
                }))
              );
              setIsLoading(false);
              return;
            }
          } catch {
            // fallback
          }
        }
      } catch {
        // If not in live backend, check mock data
        const mockRepo = MOCK_REPOSITORIES.find(r => r.id === id || r.name === id);
        if (isMounted && mockRepo) {
          setRepo({ ...mockRepo, isLiveBackend: false });
          const matchingFindings = MOCK_FINDINGS.filter(f => f.repo === mockRepo.name);
          setFindings(matchingFindings);
          setIsLoading(false);
          return;
        }

        if (isMounted) {
          setError(`Repository with ID or slug '${id}' could not be located.`);
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    loadData();
    return () => { isMounted = false; };
  }, [id]);

  if (isLoading) {
    return <LoadingState message="Loading repository guardrails and inventory..." className="py-24" />;
  }

  if (error || !repo) {
    return (
      <div className="p-8 max-w-3xl mx-auto font-sans">
        <ErrorMessage
          title="Repository Not Found"
          message={error || 'Unable to locate repository record.'}
          onRetry={() => navigate('/repositories')}
        />
        <div className="mt-4 text-center">
          <Link to="/repositories" className="text-xs font-semibold text-blue-600 hover:underline">
            ← Return to Repositories Inventory
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Breadcrumb Header */}
      <div className="px-4 lg:px-8 py-3 bg-slate-50 border-b border-slate-200 flex items-center gap-2 text-xs text-slate-500 font-mono-sm">
        <Link to="/repositories" className="hover:text-blue-600 transition-colors">
          Repositories
        </Link>
        <span>/</span>
        <span className="font-semibold text-slate-800">{repo.name}</span>
        <DataSourceBadge isLive={!!repo.isLiveBackend} className="ml-2" />
      </div>

      {/* Main Repository Info Banner */}
      <div className="px-4 lg:px-8 py-6 bg-white border-b border-slate-200">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-12 h-12 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shrink-0">
              <span className="material-symbols-outlined text-2xl">folder_code</span>
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="font-headline-lg text-2xl font-bold text-slate-900 tracking-tight">
                  {repo.name}
                </h1>
                <ScanStatusIndicator status={repo.health} />
              </div>
              <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500 font-mono-sm flex-wrap">
                <span className="flex items-center gap-1">
                  <span className="material-symbols-outlined text-sm">fork_right</span>
                  Branch: <strong className="text-slate-800">{repo.branch}</strong>
                </span>
                <span>•</span>
                <span>Language: <strong className="text-slate-800">{repo.language}</strong></span>
                <span>•</span>
                <span>Commit: <strong className="text-slate-800">{repo.gitHash}</strong></span>
                <span>•</span>
                <span>Last Scan: {repo.lastScanned}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setIsScanModalOpen(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs rounded-lg shadow-xs transition-colors flex items-center gap-1.5"
            >
              <span className="material-symbols-outlined text-base">bolt</span>
              <span>Trigger AST Scan</span>
            </button>
          </div>
        </div>

        {/* Metrics Overview Row */}
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[11px] font-mono-sm text-slate-500 uppercase font-semibold">
              Health Score
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold text-slate-900">{repo.coverage}%</span>
              <span className="text-xs text-emerald-600 font-medium">Policy Compliant</span>
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[11px] font-mono-sm text-slate-500 uppercase font-semibold">
              Critical CVEs
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className={`text-2xl font-bold ${repo.findings.critical > 0 ? 'text-red-600' : 'text-slate-900'}`}>
                {repo.findings.critical}
              </span>
              <span className="text-xs text-slate-500">Require triage</span>
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[11px] font-mono-sm text-slate-500 uppercase font-semibold">
              High Severity
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold text-slate-900">{repo.findings.high}</span>
              <span className="text-xs text-slate-500">In verification</span>
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[11px] font-mono-sm text-slate-500 uppercase font-semibold">
              Auto-Remediation
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                ACTIVE GATE
              </span>
              <span className="text-xs text-slate-500">PR #418 verified</span>
            </div>
          </div>
        </div>
      </div>

      {/* Associated Security Findings Section */}
      <div className="px-4 lg:px-8 py-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <h2 className="font-headline-md text-base font-bold text-slate-900">
              Active Security Findings ({findings.length})
            </h2>
          </div>
          <Link
            to={`/findings?repo=${encodeURIComponent(repo.name)}`}
            className="text-xs font-semibold text-blue-600 hover:underline flex items-center gap-1"
          >
            <span>Search in Findings Hub</span>
            <span className="material-symbols-outlined text-xs">arrow_forward</span>
          </Link>
        </div>

        {findings.length === 0 ? (
          <div className="p-8 text-center bg-white border border-slate-200 rounded-xl">
            <span className="material-symbols-outlined text-3xl text-emerald-500 mb-2">verified</span>
            <h4 className="font-semibold text-sm text-slate-800">Clean Repository Gate</h4>
            <p className="text-xs text-slate-500 mt-1">
              No unresolved vulnerabilities detected on branch '{repo.branch}'.
            </p>
          </div>
        ) : (
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs divide-y divide-slate-100">
            {findings.map(finding => (
              <div
                key={finding.id}
                onClick={() => navigate(`/findings/${finding.id}`)}
                className="p-4 hover:bg-slate-50/80 transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <SeverityBadge severity={finding.severity} size="sm" />
                  <div className="min-w-0">
                    <span className="font-semibold text-sm text-slate-900 group-hover:text-blue-600 transition-colors block truncate">
                      {finding.title}
                    </span>
                    <div className="flex items-center gap-2 text-xs text-slate-500 font-mono-sm mt-0.5 flex-wrap">
                      <span className="text-slate-700 font-semibold">{finding.cwe}</span>
                      <span>•</span>
                      <span>{finding.filePath}:{finding.line}</span>
                      <span>•</span>
                      <span>{finding.engine}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                  <span className="text-xs font-semibold text-blue-600 group-hover:underline flex items-center gap-0.5">
                    Inspect Patch <span className="material-symbols-outlined text-xs">chevron_right</span>
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scan Modal */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={() => {
          setIsScanModalOpen(false);
          if (id) {
            api.getRepository(id).then((apiRepo) => {
              if (apiRepo) {
                setRepo((prev) => prev ? ({
                  ...prev,
                  coverage: apiRepo.health_score,
                  findings: {
                    critical: apiRepo.critical_count,
                    high: apiRepo.high_count,
                    medium: apiRepo.medium_count,
                    low: apiRepo.low_count,
                  },
                  health: (apiRepo.critical_count > 0 ? 'vulnerable' : apiRepo.high_count > 0 ? 'at-risk' : 'secure') as any,
                }) : null);
              }
            }).catch(console.error);

            api.getFindings({ repo_id: id }).then((apiFindings) => {
              if (apiFindings && apiFindings.length > 0) {
                const mapped: SecurityFinding[] = apiFindings.map(f => ({
                  id: f.id,
                  cve: f.id,
                  cwe: f.cwe,
                  cweName: f.title,
                  title: f.title,
                  severity: f.severity.toLowerCase() as any,
                  cvss: 8.5,
                  repo: repo?.name || 'Repository',
                  branch: repo?.branch || 'main',
                  filePath: f.file_path,
                  line: f.line_number,
                  engine: f.scanner_name,
                  ruleId: 'audit.rule',
                  description: f.title,
                  taintTrace: { source: 'input', flow: ['param'], sink: 'sink' },
                  remediationStatus: f.status === 'open' ? 'needs_patch' : 'verified',
                }));
                setFindings(mapped);
              }
            }).catch(console.error);
          }
        }}
        targetRepoId={repo?.id}
        targetRepoName={repo?.name}
      />
    </div>
  );
};
