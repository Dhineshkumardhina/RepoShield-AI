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
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest border-b border-outline-variant/60 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
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

        <div className="flex items-center gap-space-sm flex-wrap">
          <div className="relative">
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-surface-container-low rounded font-mono-sm text-mono-sm text-on-surface placeholder:text-outline border border-outline-variant/60 focus:outline-none focus:border-primary"
              placeholder="Search repository or language..."
              type="text"
            />
            <span className="material-symbols-outlined text-sm text-outline absolute left-2.5 top-1/2 -translate-y-1/2">
              search
            </span>
          </div>

          <div className="inline-flex p-0.5 rounded bg-surface-container-high font-mono-sm text-mono-sm">
            <button
              onClick={() => setHealthFilter('all')}
              className={`px-2.5 py-1 rounded transition-colors ${
                healthFilter === 'all' ? 'bg-surface-container-lowest text-on-surface font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              All (42)
            </button>
            <button
              onClick={() => setHealthFilter('secure')}
              className={`px-2.5 py-1 rounded transition-colors ${
                healthFilter === 'secure' ? 'bg-surface-container-lowest text-tertiary font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              Secure (26)
            </button>
            <button
              onClick={() => setHealthFilter('at-risk')}
              className={`px-2.5 py-1 rounded transition-colors ${
                healthFilter === 'at-risk' ? 'bg-surface-container-lowest text-secondary font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              At Risk (11)
            </button>
            <button
              onClick={() => setHealthFilter('vulnerable')}
              className={`px-2.5 py-1 rounded transition-colors ${
                healthFilter === 'vulnerable' ? 'bg-surface-container-lowest text-error font-bold shadow-xs' : 'text-on-surface-variant'
              }`}
            >
              Vulnerable (5)
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="px-4 lg:px-gutter-desktop py-space-lg space-y-space-lg">
        {/* Table of Repositories */}
        <div className="rounded bg-surface-container-lowest shadow-xs overflow-hidden border border-outline-variant/60">
          <div className="overflow-x-auto w-full">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-surface-container-low text-on-surface-variant font-label-caps text-label-caps uppercase border-b border-outline-variant/60">
                  <th className="py-2.5 px-space-md">Repository</th>
                  <th className="py-2.5 px-space-md">Health Status</th>
                  <th className="py-2.5 px-space-md">Open Vulnerabilities</th>
                  <th className="py-2.5 px-space-md">Language &amp; Coverage</th>
                  <th className="py-2.5 px-space-md">Security Target</th>
                  <th className="py-2.5 px-space-md text-right">Last Scan &amp; Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-outline-variant/60 font-body-sm text-body-sm">
                {filteredRepos.map(repo => {
                  const totalFindings =
                    repo.findings.critical +
                    repo.findings.high +
                    repo.findings.medium +
                    repo.findings.low;

                  return (
                    <tr
                      key={repo.id}
                      className="hover:bg-surface-container-low transition-colors cursor-pointer"
                      onClick={() => setSelectedRepo(repo)}
                    >
                      {/* Name & Branch */}
                      <td className="py-space-sm px-space-md">
                        <div className="flex items-center gap-2">
                          <span className="material-symbols-outlined text-primary text-base">folder_code</span>
                          <div>
                            <div className="font-mono-md font-semibold text-on-surface hover:text-primary">
                              {repo.name}
                            </div>
                            <div className="font-mono-sm text-outline text-xs">
                              {repo.branch} ({repo.gitHash}) {repo.activePr && `• ${repo.activePr}`}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Health */}
                      <td className="py-space-sm px-space-md">
                        {repo.health === 'secure' && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm font-bold text-xs">
                            <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                            SECURE
                          </span>
                        )}
                        {repo.health === 'at-risk' && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-secondary-container text-on-secondary-fixed-variant font-mono-sm font-bold text-xs">
                            <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
                            AT RISK
                          </span>
                        )}
                        {repo.health === 'vulnerable' && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-error-container text-error font-mono-sm font-bold text-xs">
                            <span className="w-1.5 h-1.5 rounded-full bg-error"></span>
                            VULNERABLE
                          </span>
                        )}
                      </td>

                      {/* Findings */}
                      <td className="py-space-sm px-space-md">
                        {totalFindings === 0 ? (
                          <span className="font-mono-sm text-tertiary font-semibold text-xs">0 Open (Clean)</span>
                        ) : (
                          <div className="flex items-center gap-1.5 font-mono-sm text-xs">
                            {repo.findings.critical > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-error-container text-error font-bold">
                                {repo.findings.critical} Crit
                              </span>
                            )}
                            {repo.findings.high > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface font-bold">
                                {repo.findings.high} High
                              </span>
                            )}
                            {repo.findings.medium > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-surface-container text-on-surface-variant">
                                {repo.findings.medium} Med
                              </span>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Language & Coverage */}
                      <td className="py-space-sm px-space-md font-mono-sm text-xs">
                        <div className="text-on-surface font-medium">{repo.language}</div>
                        <div className="text-outline">Taint Coverage: {repo.coverage}%</div>
                      </td>

                      {/* Target */}
                      <td className="py-space-sm px-space-md font-mono-sm text-xs">
                        <div className="text-on-surface font-medium">{repo.engine}</div>
                        <div className="text-outline uppercase text-[10px]">{repo.target}</div>
                      </td>

                      {/* Actions */}
                      <td className="py-space-sm px-space-md text-right font-mono-sm text-xs">
                        <div className="flex items-center justify-end gap-2">
                          <span className="text-outline hidden sm:inline">{repo.lastScanned}</span>
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              onTriggerScanRepo(repo);
                            }}
                            className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-high text-primary font-semibold transition-colors"
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
          <div className="rounded bg-surface-container-lowest p-space-md shadow-xs border border-outline-variant/60 animate-in fade-in duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-outline-variant/60 mb-3">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-xl">folder_managed</span>
                <div>
                  <h3 className="font-headline-sm text-on-surface">
                    Repository Security Profile: {selectedRepo.name}
                  </h3>
                  <p className="font-mono-sm text-on-surface-variant text-xs">
                    Commit Head: {selectedRepo.gitHash} • Default: {selectedRepo.branch}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedRepo(null)}
                className="p-1 rounded text-on-surface-variant hover:text-on-surface hover:bg-surface-container"
              >
                <span className="material-symbols-outlined text-lg">close</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-body-sm">
              <div className="p-3 rounded bg-surface-container-low border border-outline-variant/60">
                <span className="font-label-caps text-on-surface-variant uppercase block mb-1">
                  Branch Protection &amp; Hooks
                </span>
                <p className="font-mono-sm text-xs text-on-surface">
                  ✓ Required AST taint status checks enabled
                </p>
                <p className="font-mono-sm text-xs text-on-surface mt-1">
                  ✓ Automated PR auto-remediation gate active
                </p>
              </div>

              <div className="p-3 rounded bg-surface-container-low border border-outline-variant/60">
                <span className="font-label-caps text-on-surface-variant uppercase block mb-1">
                  Active Findings &amp; SLA
                </span>
                <p className="font-mono-sm text-xs text-on-surface">
                  Critical SLA Target: &lt; 48 hours
                </p>
                <p className="font-mono-sm text-xs text-on-surface mt-1">
                  High SLA Target: &lt; 5.0 days
                </p>
              </div>

              <div className="p-3 rounded bg-surface-container-low border border-outline-variant/60 flex flex-col justify-between">
                <div>
                  <span className="font-label-caps text-on-surface-variant uppercase block mb-1">
                    Continuous Remediation
                  </span>
                  <p className="font-mono-sm text-xs text-on-surface">
                    Auto-remediation PR creation: Enabled
                  </p>
                </div>
                <button
                  onClick={() => onNavigateToFindings()}
                  className="mt-2 text-primary font-mono-sm text-xs font-semibold hover:underline text-left"
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
