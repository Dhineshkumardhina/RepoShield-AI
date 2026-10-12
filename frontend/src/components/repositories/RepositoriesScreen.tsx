import React, { useState } from 'react';
import { Repository, RepoHealth } from '../../types';

interface RepositoriesScreenProps {
  repositories: Repository[];
  onTriggerScanRepo: (repo: Repository) => void;
  onNavigateToFindings: (cwe?: string) => void;
}

export const RepositoriesScreen: React.FC<RepositoriesScreenProps> = ({
  repositories,
  onTriggerScanRepo,
  onNavigateToFindings
}) => {
  const [search, setSearch] = useState('');
  const [healthFilter, setHealthFilter] = useState<'all' | RepoHealth>('all');
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);

  const filteredRepos = repositories.filter(repo => {
    const matchesSearch =
      repo.name.toLowerCase().includes(search.toLowerCase()) ||
      repo.language.toLowerCase().includes(search.toLowerCase()) ||
      repo.branch.toLowerCase().includes(search.toLowerCase());
    const matchesHealth = healthFilter === 'all' || repo.health === healthFilter;
    return matchesSearch && matchesHealth;
  });

  return (
    <div className="flex flex-col w-full">
      {/* Action Header */}
      <div className="px-6 py-4 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-500 uppercase font-semibold">
              Repository Inventory
            </span>
            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] font-semibold border border-slate-200">
              42 Total
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Monitored Repositories
          </h1>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-50 rounded-lg font-mono text-xs text-slate-900 placeholder:text-slate-400 border border-slate-200 focus:outline-none focus:ring-1 focus:ring-slate-900 focus:bg-white transition-all shadow-2xs"
              placeholder="Search repository or language..."
              type="text"
            />
            <span className="material-symbols-outlined text-sm text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2">
              search
            </span>
          </div>

          <div className="inline-flex p-0.5 rounded-lg bg-slate-100 font-mono text-xs border border-slate-200">
            <button
              onClick={() => setHealthFilter('all')}
              className={`px-3 py-1 rounded-md transition-colors ${
                healthFilter === 'all' ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All (42)
            </button>
            <button
              onClick={() => setHealthFilter('secure')}
              className={`px-3 py-1 rounded-md transition-colors ${
                healthFilter === 'secure' ? 'bg-white text-emerald-700 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Secure (26)
            </button>
            <button
              onClick={() => setHealthFilter('at-risk')}
              className={`px-3 py-1 rounded-md transition-colors ${
                healthFilter === 'at-risk' ? 'bg-white text-amber-700 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              At Risk (11)
            </button>
            <button
              onClick={() => setHealthFilter('vulnerable')}
              className={`px-3 py-1 rounded-md transition-colors ${
                healthFilter === 'vulnerable' ? 'bg-white text-rose-700 font-semibold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Vulnerable (5)
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-6 space-y-6">
        {/* Table of Repositories */}
        <div className="rounded-xl bg-white shadow-2xs overflow-hidden border border-slate-200">
          <div className="overflow-x-auto w-full">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 text-slate-500 font-mono text-[10px] uppercase border-b border-slate-200">
                  <th className="py-3 px-4 font-semibold">Repository</th>
                  <th className="py-3 px-4 font-semibold">Health Status</th>
                  <th className="py-3 px-4 font-semibold">Open Vulnerabilities</th>
                  <th className="py-3 px-4 font-semibold">Language &amp; Coverage</th>
                  <th className="py-3 px-4 font-semibold">Security Target</th>
                  <th className="py-3 px-4 font-semibold text-right">Last Scan &amp; Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-xs">
                {filteredRepos.map(repo => {
                  const totalFindings =
                    repo.findings.critical +
                    repo.findings.high +
                    repo.findings.medium +
                    repo.findings.low;

                  return (
                    <tr
                      key={repo.id}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer"
                      onClick={() => setSelectedRepo(repo)}
                    >
                      {/* Name & Branch */}
                      <td className="py-3 px-4 font-sans">
                        <div className="flex items-center gap-2.5">
                          <span className="material-symbols-outlined text-slate-700 text-base">folder_code</span>
                          <div>
                            <div className="font-semibold text-slate-900 hover:text-blue-600">
                              {repo.name}
                            </div>
                            <div className="font-mono text-slate-500 text-xs">
                              {repo.branch} ({repo.gitHash}) {repo.activePr && `• ${repo.activePr}`}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Health */}
                      <td className="py-3 px-4">
                        {repo.health === 'secure' && (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold text-[10px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                            SECURE
                          </span>
                        )}
                        {repo.health === 'at-risk' && (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 font-bold text-[10px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                            AT RISK
                          </span>
                        )}
                        {repo.health === 'vulnerable' && (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 font-bold text-[10px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                            VULNERABLE
                          </span>
                        )}
                      </td>

                      {/* Findings */}
                      <td className="py-3 px-4">
                        {totalFindings === 0 ? (
                          <span className="text-emerald-700 font-semibold text-xs">0 Open (Clean)</span>
                        ) : (
                          <div className="flex items-center gap-1.5 text-xs">
                            {repo.findings.critical > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-bold">
                                {repo.findings.critical} Crit
                              </span>
                            )}
                            {repo.findings.high > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 font-bold">
                                {repo.findings.high} High
                              </span>
                            )}
                            {repo.findings.medium > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                                {repo.findings.medium} Med
                              </span>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Language & Coverage */}
                      <td className="py-3 px-4 text-xs">
                        <div className="text-slate-900 font-medium">{repo.language}</div>
                        <div className="text-slate-500">Taint Coverage: {repo.coverage}%</div>
                      </td>

                      {/* Target */}
                      <td className="py-3 px-4 text-xs">
                        <div className="text-slate-900 font-medium">{repo.engine}</div>
                        <div className="text-slate-500 uppercase text-[10px]">{repo.target}</div>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right text-xs">
                        <div className="flex items-center justify-end gap-2">
                          <span className="text-slate-400 hidden sm:inline">{repo.lastScanned}</span>
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              onTriggerScanRepo(repo);
                            }}
                            className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-900 font-semibold transition-colors border border-slate-200"
                          >
                            Scan
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Repo Drawer / Detail Inspector */}
        {selectedRepo && (
          <div className="rounded-xl bg-white p-5 shadow-xs border border-slate-200 animate-in fade-in duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 mb-4">
              <div className="flex items-center gap-2.5">
                <span className="material-symbols-outlined text-slate-700 text-xl">folder_managed</span>
                <div>
                  <h3 className="font-bold text-slate-900 text-sm">
                    Repository Security Profile: {selectedRepo.name}
                  </h3>
                  <p className="font-mono text-slate-500 text-xs">
                    Commit Head: {selectedRepo.gitHash} • Default: {selectedRepo.branch}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedRepo(null)}
                className="p-1 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
              >
                <span className="material-symbols-outlined text-lg">close</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="font-mono text-[10px] uppercase text-slate-500 font-semibold block mb-1">
                  Branch Protection &amp; Hooks
                </span>
                <p className="font-mono text-slate-800">
                  ✓ Required AST taint status checks enabled
                </p>
                <p className="font-mono text-slate-800 mt-1">
                  ✓ Automated PR auto-remediation gate active
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="font-mono text-[10px] uppercase text-slate-500 font-semibold block mb-1">
                  Active Findings &amp; SLA
                </span>
                <p className="font-mono text-slate-800">
                  Critical SLA Target: &lt; 48 hours
                </p>
                <p className="font-mono text-slate-800 mt-1">
                  High SLA Target: &lt; 5.0 days
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col justify-between">
                <div>
                  <span className="font-mono text-[10px] uppercase text-slate-500 font-semibold block mb-1">
                    Continuous Remediation
                  </span>
                  <p className="font-mono text-slate-800">
                    Auto-remediation PR creation: Enabled
                  </p>
                </div>
                <button
                  onClick={() => onNavigateToFindings()}
                  className="mt-2 text-blue-600 font-mono text-xs font-semibold hover:underline text-left"
                >
                  View Repo Findings Matrix →
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
