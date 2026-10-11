import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiRepository } from '../services/api';
import { MOCK_REPOSITORIES } from '../data/mockData';
import { Repository, RepoHealth } from '../types';
import {
  ScanStatusIndicator,
  DataSourceBadge,
  LoadingState,
  ErrorMessage,
  EmptyState,
} from '../components/common';
import { ScanModal } from '../components/modals/ScanModal';

type IngestionTab = 'zip' | 'git' | 'manual';

export const RepositoriesPage: React.FC = () => {
  const navigate = useNavigate();

  const [liveRepos, setLiveRepos] = useState<ApiRepository[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const [errorRequestId, setErrorRequestId] = useState<string | undefined>();

  // Filter and search
  const [search, setSearch] = useState('');
  const [healthFilter, setHealthFilter] = useState<'all' | 'secure' | 'at-risk' | 'vulnerable'>('all');
  const [viewType, setViewType] = useState<'table' | 'cards'>('table');

  // Ingestion Modal State
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<IngestionTab>('zip');
  const [newRepoName, setNewRepoName] = useState('');
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [newRepoBranch, setNewRepoBranch] = useState('main');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [uploadSuccessMsg, setUploadSuccessMsg] = useState<string | null>(null);

  // Scan modal
  const [scanModalTarget, setScanModalTarget] = useState<{ id: string; name: string } | null>(null);

  // Load repositories from Backend API
  const loadRepositories = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const repos = await api.getRepositories();
      setLiveRepos(repos);
    } catch (err: any) {
      setApiError(err.message || 'Unable to connect to backend repository API.');
      setErrorRequestId(err.requestId);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadRepositories();
  }, []);

  // Combine live repositories with mock repositories for complete view
  const combinedRepos: (Repository & {
    isLiveBackend?: boolean;
    sourceType?: string;
    ingestionStatus?: string;
    fileCount?: number;
    totalBytes?: number;
  })[] = [
    ...liveRepos.map(lr => ({
      id: lr.id,
      name: lr.name,
      branch: lr.default_branch,
      gitHash: lr.id.substring(0, 7),
      engine: lr.source_type === 'zip_upload' ? 'ZIP Archive' : lr.source_type === 'public_git' ? 'Git Clone' : 'FastAPI Monitored',
      target: 'Production',
      health: (lr.critical_count > 0 ? 'vulnerable' : lr.high_count > 0 ? 'at-risk' : 'secure') as RepoHealth,
      findings: {
        critical: lr.critical_count,
        high: lr.high_count,
        medium: lr.medium_count,
        low: lr.low_count,
      },
      language: lr.language_metadata || (lr.name.includes('py') ? 'Python' : lr.name.includes('gateway') ? 'TypeScript' : 'Go'),
      lastScanned: new Date(lr.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      coverage: lr.health_score,
      autoRemediate: true,
      isLiveBackend: true,
      sourceType: lr.source_type,
      ingestionStatus: lr.ingestion_status,
      fileCount: lr.file_count,
      totalBytes: lr.total_size_bytes,
    })),
    ...MOCK_REPOSITORIES.map(mr => ({ ...mr, isLiveBackend: false })),
  ];

  const filteredRepos = combinedRepos.filter(repo => {
    const matchesSearch =
      repo.name.toLowerCase().includes(search.toLowerCase()) ||
      repo.language.toLowerCase().includes(search.toLowerCase()) ||
      repo.branch.toLowerCase().includes(search.toLowerCase());
    const matchesHealth = healthFilter === 'all' || repo.health === healthFilter;
    return matchesSearch && matchesHealth;
  });

  const resetModalForm = () => {
    setNewRepoName('');
    setZipFile(null);
    setNewRepoUrl('');
    setNewRepoBranch('main');
    setRegisterError(null);
    setUploadSuccessMsg(null);
  };

  const handleIngestRepo = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setRegisterError(null);
    setUploadSuccessMsg(null);

    try {
      if (activeTab === 'zip') {
        if (!zipFile) {
          throw new Error('Please select a valid ZIP archive containing source code.');
        }
        const created = await api.ingestZipArchive(zipFile, newRepoName.trim() || undefined);
        setUploadSuccessMsg(`Repository "${created.name}" ingested successfully with ${created.file_count ?? 0} files.`);
      } else if (activeTab === 'git') {
        if (!newRepoUrl.trim()) {
          throw new Error('Please enter a valid HTTPS Git repository URL.');
        }
        const created = await api.ingestGitRepository({
          git_url: newRepoUrl.trim(),
          name: newRepoName.trim() || undefined,
          default_branch: newRepoBranch.trim() || 'main',
        });
        setUploadSuccessMsg(`Repository "${created.name}" cloned and verified successfully.`);
      } else {
        if (!newRepoName.trim()) {
          throw new Error('Repository identifier is required.');
        }
        await api.createRepository({
          name: newRepoName.trim(),
          git_url: newRepoUrl.trim() || undefined,
          default_branch: newRepoBranch.trim() || 'main',
          health_score: 95,
        });
        setUploadSuccessMsg(`Repository "${newRepoName}" registered in database.`);
      }

      await loadRepositories();
      setTimeout(() => {
        setIsRegisterModalOpen(false);
        resetModalForm();
      }, 1200);

    } catch (err: any) {
      setRegisterError(err.message || 'Repository ingestion failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col w-full pb-12 font-sans">
      {/* Action Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-xs text-blue-600 uppercase font-bold tracking-wider">
              WORKSPACE REPOSITORY INVENTORY
            </span>
            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-800 font-mono-sm text-xs font-bold border border-slate-200">
              {combinedRepos.length} TOTAL
            </span>
          </div>
          <h1 className="font-headline-lg text-2xl text-slate-900 tracking-tight mt-0.5 font-bold">
            Production Repositories &amp; Guardrails
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Monitored source repositories with active AST taint verification, secure isolated workspaces, and regression gates.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <button
            type="button"
            onClick={() => {
              resetModalForm();
              setIsRegisterModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-colors"
          >
            <span className="material-symbols-outlined text-base">cloud_upload</span>
            <span>Ingest Repository</span>
          </button>
        </div>
      </div>

      {/* Filters & Search Strip */}
      <div className="px-4 lg:px-8 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-3 w-full sm:w-auto flex-1 max-w-lg">
          <div className="relative flex-1">
            <span className="material-symbols-outlined text-slate-400 text-base absolute left-3 top-1/2 -translate-y-1/2">
              search
            </span>
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search repository, language, or branch..."
              className="w-full pl-9 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 transition-colors"
            />
          </div>

          <div className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 text-xs font-mono-sm shrink-0">
            {(['all', 'secure', 'at-risk', 'vulnerable'] as const).map(f => (
              <button
                key={f}
                type="button"
                onClick={() => setHealthFilter(f)}
                className={`px-2.5 py-1 rounded capitalize transition-colors ${
                  healthFilter === f
                    ? 'bg-blue-50 text-blue-700 font-bold border border-blue-200'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* View Toggle */}
        <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
          <div className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setViewType('table')}
              className={`p-1.5 rounded transition-colors ${
                viewType === 'table' ? 'bg-slate-100 text-slate-900 font-semibold' : 'text-slate-500 hover:text-slate-900'
              }`}
              title="Table view"
            >
              <span className="material-symbols-outlined text-base">table_rows</span>
            </button>
            <button
              type="button"
              onClick={() => setViewType('cards')}
              className={`p-1.5 rounded transition-colors ${
                viewType === 'cards' ? 'bg-slate-100 text-slate-900 font-semibold' : 'text-slate-500 hover:text-slate-900'
              }`}
              title="Card view"
            >
              <span className="material-symbols-outlined text-base">grid_view</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="px-4 lg:px-8 py-6">
        {isLoading && <LoadingState message="Fetching repositories from FastAPI backend..." />}

        {apiError && (
          <ErrorMessage
            title="Backend Connection Notice"
            message={apiError}
            requestId={errorRequestId}
            onRetry={loadRepositories}
            className="mb-6"
          />
        )}

        {!isLoading && filteredRepos.length === 0 ? (
          <EmptyState
            icon="folder_off"
            title="No repositories found"
            description={search ? `No repositories match your filter "${search}".` : 'No repositories are currently monitored.'}
            actionLabel="Ingest Repository"
            onAction={() => {
              resetModalForm();
              setIsRegisterModalOpen(true);
            }}
          />
        ) : (
          viewType === 'table' ? (
            /* Table Layout */
            <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-mono-sm uppercase text-slate-500 tracking-wider">
                      <th className="py-3 px-4 font-semibold">Repository</th>
                      <th className="py-3 px-4 font-semibold">Source</th>
                      <th className="py-3 px-4 font-semibold">Status</th>
                      <th className="py-3 px-4 font-semibold">Branch</th>
                      <th className="py-3 px-4 font-semibold">Open Findings</th>
                      <th className="py-3 px-4 font-semibold">Health Score</th>
                      <th className="py-3 px-4 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-sm">
                    {filteredRepos.map(repo => (
                      <tr
                        key={`${repo.isLiveBackend ? 'live' : 'demo'}-${repo.id}`}
                        onClick={() => navigate(`/repositories/${repo.id}`)}
                        className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                      >
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2.5">
                            <span className="material-symbols-outlined text-slate-400 group-hover:text-blue-600 transition-colors text-lg">
                              folder_code
                            </span>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-slate-900 block group-hover:text-blue-600 transition-colors">
                                  {repo.name}
                                </span>
                                {repo.fileCount !== undefined && repo.fileCount > 0 && (
                                  <span className="text-[10px] font-mono-sm px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 border border-slate-200">
                                    {repo.fileCount} files
                                  </span>
                                )}
                              </div>
                              <span className="text-[11px] text-slate-500 font-mono-sm">
                                {repo.language}
                              </span>
                            </div>
                          </div>
                        </td>

                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5">
                            <DataSourceBadge isLive={!!repo.isLiveBackend} />
                            {repo.sourceType === 'zip_upload' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono-sm bg-purple-50 text-purple-700 border border-purple-200">
                                ZIP
                              </span>
                            )}
                            {repo.sourceType === 'public_git' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono-sm bg-sky-50 text-sky-700 border border-sky-200">
                                GIT
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-3 px-4">
                          <ScanStatusIndicator status={repo.health} />
                        </td>

                        <td className="py-3 px-4">
                          <span className="inline-flex items-center gap-1 font-mono-sm text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                            <span className="material-symbols-outlined text-xs">fork_right</span>
                            {repo.branch}
                          </span>
                        </td>

                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5 font-mono-sm text-xs">
                            {repo.findings.critical > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-red-50 text-red-700 font-bold border border-red-200">
                                {repo.findings.critical} Crit
                              </span>
                            )}
                            {repo.findings.high > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-orange-50 text-orange-700 font-semibold border border-orange-200">
                                {repo.findings.high} High
                              </span>
                            )}
                            {repo.findings.critical === 0 && repo.findings.high === 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-medium border border-emerald-200">
                                Clean
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-slate-100 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  repo.coverage >= 90 ? 'bg-emerald-500' : repo.coverage >= 70 ? 'bg-amber-500' : 'bg-red-500'
                                }`}
                                style={{ width: `${repo.coverage}%` }}
                              />
                            </div>
                            <span className="font-mono-sm text-xs font-semibold text-slate-700">
                              {repo.coverage}%
                            </span>
                          </div>
                        </td>

                        <td className="py-3 px-4 text-right" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => setScanModalTarget({ id: repo.id, name: repo.name })}
                              className="px-2.5 py-1 text-xs font-medium text-slate-700 hover:text-blue-600 hover:bg-blue-50 border border-slate-200 rounded-lg transition-colors flex items-center gap-1"
                              title="Trigger AppSec Scan"
                            >
                              <span className="material-symbols-outlined text-xs">bolt</span>
                              <span className="hidden sm:inline">Scan</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => navigate(`/repositories/${repo.id}`)}
                              className="p-1 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100"
                              title="View Guardrails"
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
          ) : (
            /* Card Grid Layout */
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredRepos.map(repo => (
                <div
                  key={repo.id}
                  onClick={() => navigate(`/repositories/${repo.id}`)}
                  className="p-5 rounded-xl bg-white border border-slate-200 hover:border-blue-400 hover:shadow-xs transition-all cursor-pointer flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2 mb-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="material-symbols-outlined text-blue-600 text-xl">folder_code</span>
                        <h3 className="font-semibold text-slate-900 text-sm truncate" title={repo.name}>
                          {repo.name}
                        </h3>
                      </div>
                      <div className="flex items-center gap-1">
                        <DataSourceBadge isLive={!!repo.isLiveBackend} />
                        {repo.sourceType === 'zip_upload' && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono-sm bg-purple-50 text-purple-700 border border-purple-200">
                            ZIP
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 mb-3">
                      <ScanStatusIndicator status={repo.health} />
                      <span className="font-mono-sm text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                        {repo.branch}
                      </span>
                      {repo.fileCount !== undefined && repo.fileCount > 0 && (
                        <span className="font-mono-sm text-[11px] text-slate-500">
                          {repo.fileCount} files
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-500 font-mono-sm mb-4">
                      Language: {repo.language} • Target: {repo.target}
                    </p>
                  </div>

                  <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-mono-sm text-xs">
                      {repo.findings.critical > 0 ? (
                        <span className="text-red-600 font-bold">{repo.findings.critical} Critical</span>
                      ) : (
                        <span className="text-emerald-600 font-medium">0 Critical</span>
                      )}
                    </div>
                    <span className="text-xs font-semibold text-blue-600 hover:underline flex items-center gap-0.5">
                      View Guardrails <span className="material-symbols-outlined text-xs">arrow_forward</span>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </div>

      {/* Ingest Repository Modal */}
      {isRegisterModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-lg w-full p-6 animate-in fade-in duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-blue-600">shield_lock</span>
                <h3 className="font-semibold text-base text-slate-900">
                  Ingest Code Repository
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setIsRegisterModalOpen(false)}
                className="text-slate-400 hover:text-slate-600"
              >
                <span className="material-symbols-outlined text-lg">close</span>
              </button>
            </div>

            {/* Source Type Selector Tabs */}
            <div className="flex items-center gap-2 mt-4 p-1 bg-slate-100 rounded-lg text-xs font-semibold">
              <button
                type="button"
                onClick={() => setActiveTab('zip')}
                className={`flex-1 py-1.5 px-3 rounded-md transition-colors flex items-center justify-center gap-1.5 ${
                  activeTab === 'zip'
                    ? 'bg-white text-blue-700 shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <span className="material-symbols-outlined text-sm">folder_zip</span>
                <span>ZIP Archive</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('git')}
                className={`flex-1 py-1.5 px-3 rounded-md transition-colors flex items-center justify-center gap-1.5 ${
                  activeTab === 'git'
                    ? 'bg-white text-blue-700 shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <span className="material-symbols-outlined text-sm">terminal</span>
                <span>Public Git URL</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('manual')}
                className={`flex-1 py-1.5 px-3 rounded-md transition-colors flex items-center justify-center gap-1.5 ${
                  activeTab === 'manual'
                    ? 'bg-white text-blue-700 shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <span className="material-symbols-outlined text-sm">edit_note</span>
                <span>Manual Meta</span>
              </button>
            </div>

            {/* Security Guardrail Policies Callout */}
            <div className="mt-3 p-3 bg-slate-50 border border-slate-200 rounded-lg text-[11px] text-slate-600 space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-slate-800">
                <span className="material-symbols-outlined text-xs text-blue-600">verified_user</span>
                <span>RepoShield Ingestion Policies &amp; Quotas</span>
              </div>
              {activeTab === 'zip' && (
                <ul className="list-disc list-inside space-y-0.5 text-slate-500 pl-1">
                  <li><strong>Upload limit:</strong> 50 MB max archive size; 200 MB expansion quota.</li>
                  <li><strong>Safety guards:</strong> Path traversal (Zip Slip) and Zip bombs rejected.</li>
                  <li><strong>Filtration:</strong> Binary executables (.exe, .dll, .so) excluded.</li>
                  <li><strong>Zero code execution:</strong> Static AST inspection only.</li>
                </ul>
              )}
              {activeTab === 'git' && (
                <ul className="list-disc list-inside space-y-0.5 text-slate-500 pl-1">
                  <li><strong>Protocols:</strong> HTTPS only; embedded credentials prohibited.</li>
                  <li><strong>SSRF Protection:</strong> Localhost, private RFC1918, and AWS metadata blocked.</li>
                  <li><strong>Execution sandbox:</strong> Client-side Git hooks disabled.</li>
                </ul>
              )}
              {activeTab === 'manual' && (
                <p className="text-slate-500">
                  Registers remote repository metadata into the platform catalog.
                </p>
              )}
            </div>

            {registerError && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 flex items-center gap-2">
                <span className="material-symbols-outlined text-sm text-red-600">error</span>
                <span>{registerError}</span>
              </div>
            )}

            {uploadSuccessMsg && (
              <div className="mt-3 p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-xs text-emerald-700 flex items-center gap-2">
                <span className="material-symbols-outlined text-sm text-emerald-600">check_circle</span>
                <span>{uploadSuccessMsg}</span>
              </div>
            )}

            <form onSubmit={handleIngestRepo} className="mt-4 space-y-4">
              {/* Tab 1: ZIP Archive Upload */}
              {activeTab === 'zip' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                      Select Source ZIP Archive *
                    </label>
                    <div className="mt-1 border-2 border-dashed border-slate-300 rounded-lg p-4 text-center hover:border-blue-500 transition-colors bg-slate-50">
                      <input
                        type="file"
                        accept=".zip,application/zip"
                        required
                        onChange={e => {
                          if (e.target.files && e.target.files[0]) {
                            const file = e.target.files[0];
                            setZipFile(file);
                            if (!newRepoName) {
                              setNewRepoName(file.name.replace(/\.zip$/i, ''));
                            }
                          }
                        }}
                        className="block w-full text-xs text-slate-500 file:mr-4 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 cursor-pointer"
                      />
                      <p className="text-[11px] text-slate-400 mt-2">
                        {zipFile ? `Selected: ${zipFile.name} (${(zipFile.size / (1024 * 1024)).toFixed(2)} MB)` : 'Accepts .zip archives up to 50 MB'}
                      </p>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                      Repository Display Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={newRepoName}
                      onChange={e => setNewRepoName(e.target.value)}
                      placeholder="e.g. xerova/auth-gateway"
                      className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                    />
                  </div>
                </>
              )}

              {/* Tab 2: Public Git Repository */}
              {activeTab === 'git' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                      Public Git Clone URL (HTTPS) *
                    </label>
                    <input
                      type="url"
                      required
                      value={newRepoUrl}
                      onChange={e => setNewRepoUrl(e.target.value)}
                      placeholder="https://github.com/xerova/billing-service.git"
                      className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                        Repository Name
                      </label>
                      <input
                        type="text"
                        value={newRepoName}
                        onChange={e => setNewRepoName(e.target.value)}
                        placeholder="billing-service"
                        className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                        Branch
                      </label>
                      <input
                        type="text"
                        value={newRepoBranch}
                        onChange={e => setNewRepoBranch(e.target.value)}
                        placeholder="main"
                        className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                      />
                    </div>
                  </div>
                </>
              )}

              {/* Tab 3: Manual Metadata */}
              {activeTab === 'manual' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                      Repository Identifier *
                    </label>
                    <input
                      type="text"
                      required
                      value={newRepoName}
                      onChange={e => setNewRepoName(e.target.value)}
                      placeholder="xerova/payments-service"
                      className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                      Git Remote URL (Optional)
                    </label>
                    <input
                      type="text"
                      value={newRepoUrl}
                      onChange={e => setNewRepoUrl(e.target.value)}
                      placeholder="https://github.com/xerova/payments-service.git"
                      className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 uppercase font-mono-sm">
                      Default Target Branch
                    </label>
                    <input
                      type="text"
                      value={newRepoBranch}
                      onChange={e => setNewRepoBranch(e.target.value)}
                      placeholder="main"
                      className="mt-1 w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs text-slate-900 font-mono-md focus:bg-white focus:border-blue-600 focus:outline-none"
                    />
                  </div>
                </>
              )}

              <div className="pt-3 border-t border-slate-200 flex items-center justify-end gap-3">
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => setIsRegisterModalOpen(false)}
                  className="px-4 py-2 border border-slate-300 rounded-lg text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  {isSubmitting && <span className="material-symbols-outlined text-sm animate-spin">progress_activity</span>}
                  <span>
                    {isSubmitting
                      ? activeTab === 'zip' ? 'Extracting & Scanning...' : activeTab === 'git' ? 'Cloning & Verifying...' : 'Registering...'
                      : activeTab === 'zip' ? 'Upload & Ingest' : activeTab === 'git' ? 'Clone Repository' : 'Register Metadata'}
                  </span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Trigger Scan Modal */}
      {scanModalTarget && (
        <ScanModal
          isOpen={!!scanModalTarget}
          targetRepoId={scanModalTarget.id}
          targetRepoName={scanModalTarget.name}
          onClose={() => setScanModalTarget(null)}
          onScanComplete={() => {
            setScanModalTarget(null);
            loadRepositories();
          }}
        />
      )}
    </div>
  );
};
