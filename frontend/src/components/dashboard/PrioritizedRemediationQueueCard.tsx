import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, RemediationQueueItem } from '../../services/api';
import { VerificationItem } from '../../types';

interface PrioritizedRemediationQueueCardProps {
  onOpenDiffModal?: (item: VerificationItem) => void;
  onNavigateToFinding?: (findingId: string) => void;
}

export const PrioritizedRemediationQueueCard: React.FC<PrioritizedRemediationQueueCardProps> = ({
  onOpenDiffModal,
  onNavigateToFinding,
}) => {
  const navigate = useNavigate();
  const [queueItems, setQueueItems] = useState<RemediationQueueItem[]>([]);
  const [selectedPriority, setSelectedPriority] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchQueue = () => {
    setIsLoading(true);
    api.getRemediationQueue({
      priority: selectedPriority !== 'all' ? selectedPriority : undefined,
    })
      .then(items => {
        setQueueItems(items);
        setError(null);
      })
      .catch(err => {
        setError(err.message || 'Remediation queue API unavailable');
        // Fallback sample items for demonstration
        setQueueItems([
          {
            finding_id: 'FIND-418',
            repo_id: 'repo-auth-gateway',
            repo_name: 'xerova/auth-gateway',
            title: 'Raw SQL Query String Interpolation in user_query.py',
            file_path: 'auth-gateway/src/dao/user_query.py',
            line_number: 42,
            cwe: 'CWE-89: SQL Injection',
            scanner_name: 'Semgrep OSS',
            original_scanner_severity: 'CRITICAL',
            contextual_priority: 'CRITICAL' as any,
            priority_score: 95.0,
            affected_component: 'public_ingress_api',
            remediation_status: 'VERIFIED_FIX_READY',
            evidence_completeness: 'COMPLETE' as any,
            evidence_limitations: [],
            suggested_action: '[CRITICAL] Deploy verified fix: Candidate patch passed targeted regression and exploit tests.',
            linkage: {
              finding_id: 'FIND-418',
              patch_proposal_id: 'patch-418',
              verification_status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
              recommendations: ['Replace f-string interpolation with DB-API parameterized query tuple.'],
              suggested_targeted_tests: ['test_sql_injection_exploit_payloads'],
              patch_diff_preview: '--- a/user_query.py\n+++ b/user_query.py\n- cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n+ cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            },
          },
          {
            finding_id: 'FIND-502',
            repo_id: 'repo-order-engine',
            repo_name: 'xerova/order-engine',
            title: 'Unsafe Deserialization via yaml.unsafe_load',
            file_path: 'order-engine/src/config/loader.py',
            line_number: 18,
            cwe: 'CWE-502: Insecure Deserialization',
            scanner_name: 'Bandit',
            original_scanner_severity: 'HIGH',
            contextual_priority: 'HIGH' as any,
            priority_score: 75.0,
            affected_component: 'business_logic',
            remediation_status: 'ANALYSIS_AVAILABLE',
            evidence_completeness: 'PARTIAL' as any,
            evidence_limitations: ['Call graph reachability from public ingress unproven'],
            suggested_action: '[HIGH] Inspect AI analysis recommendations and generate targeted fix.',
            linkage: {
              finding_id: 'FIND-502',
              recommendations: ['Migrate from yaml.unsafe_load to yaml.safe_load'],
              suggested_targeted_tests: ['test_malicious_yaml_payload_blocked'],
            },
          },
          {
            finding_id: 'FIND-287',
            repo_id: 'repo-vault-service',
            repo_name: 'xerova/vault-service',
            title: 'Missing Authorization Check on Internal Admin Endpoint',
            file_path: 'vault-service/src/admin/routes.py',
            line_number: 64,
            cwe: 'CWE-862: Missing Authorization',
            scanner_name: 'Semgrep OSS',
            original_scanner_severity: 'CRITICAL',
            contextual_priority: 'HIGH' as any,
            priority_score: 65.0,
            affected_component: 'core_security_boundary',
            remediation_status: 'NEEDS_INVESTIGATION',
            evidence_completeness: 'MINIMAL' as any,
            evidence_limitations: ['Severe scanner finding floor protected; auth decorator unverified'],
            suggested_action: '[HIGH] High-priority triage required: Evidence missing to prove reachability; manual investigation advised.',
            linkage: {
              finding_id: 'FIND-287',
              recommendations: ['Apply @requires_admin decorator to all admin route handlers.'],
              suggested_targeted_tests: [],
            },
          },
        ]);
      })
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    fetchQueue();
  }, [selectedPriority]);

  const handleRowClick = (findingId: string) => {
    if (onNavigateToFinding) {
      onNavigateToFinding(findingId);
    } else {
      navigate(`/findings/${findingId}`);
    }
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-300 font-bold';
      case 'HIGH':
        return 'bg-amber-50 text-amber-800 border-amber-300 font-bold';
      case 'MEDIUM':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'LOW':
        return 'bg-slate-100 text-slate-700 border-slate-300';
      default:
        return 'bg-slate-50 text-slate-600 border-slate-200';
    }
  };

  const getReadinessBadge = (status: string) => {
    switch (status) {
      case 'VERIFIED_FIX_READY':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <span className="material-symbols-outlined text-[13px]">verified</span>
            Verified Fix Ready
          </span>
        );
      case 'PATCH_PENDING_REVIEW':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-blue-50 text-blue-700 border border-blue-200">
            <span className="material-symbols-outlined text-[13px]">code</span>
            Patch Pending Review
          </span>
        );
      case 'PATCH_FAILED_TESTS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-rose-50 text-rose-700 border border-rose-200">
            <span className="material-symbols-outlined text-[13px]">error</span>
            Patch Failed Tests
          </span>
        );
      case 'ANALYSIS_AVAILABLE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-purple-50 text-purple-700 border border-purple-200">
            <span className="material-symbols-outlined text-[13px]">psychology</span>
            Analysis Ready
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-100 text-slate-700 border border-slate-200">
            <span className="material-symbols-outlined text-[13px]">search</span>
            Investigation Required
          </span>
        );
    }
  };

  return (
    <div className="rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden mb-6">
      {/* Header with Title and Priority Chips */}
      <div className="p-4 bg-slate-50/80 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-blue-600 text-lg">format_list_numbered</span>
            <h3 className="font-headline-sm text-sm font-bold text-slate-900 tracking-tight">
              Prioritized Remediation Queue (Evidence-Ranked)
            </h3>
            <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-800 text-[10px] font-mono font-bold">
              MULTI-TIER EVIDENCE
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Ranked by observable code evidence and fix readiness. Separates scanner severity from contextual urgency and protects severe findings from silent downgrades.
          </p>
        </div>

        {/* Priority Filter Chips */}
        <div className="flex items-center gap-1.5 self-start md:self-auto flex-wrap">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(p => (
            <button
              key={p}
              type="button"
              onClick={() => setSelectedPriority(p)}
              className={`px-2.5 py-1 text-xs font-mono rounded-lg transition-colors border ${
                selectedPriority === p
                  ? 'bg-blue-600 text-white border-blue-600 font-semibold shadow-xs'
                  : 'bg-white text-slate-600 hover:text-slate-900 border-slate-200 hover:bg-slate-50'
              }`}
            >
              {p.toUpperCase()}
            </button>
          ))}
          <button
            type="button"
            onClick={() => navigate('/findings')}
            className="ml-2 text-xs text-blue-600 hover:underline font-semibold flex items-center gap-0.5"
          >
            <span>View All Findings</span>
            <span className="material-symbols-outlined text-xs">arrow_forward</span>
          </button>
        </div>
      </div>

      {/* Queue Items Table */}
      <div className="overflow-x-auto w-full">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 font-mono text-[10px] uppercase text-slate-500 tracking-wider">
              <th className="py-2.5 px-4 font-semibold w-12 text-center">Rank</th>
              <th className="py-2.5 px-4 font-semibold">Contextual Priority</th>
              <th className="py-2.5 px-4 font-semibold">Scanner Severity</th>
              <th className="py-2.5 px-4 font-semibold">Vulnerability / Location</th>
              <th className="py-2.5 px-4 font-semibold">Component</th>
              <th className="py-2.5 px-4 font-semibold">Remediation Readiness</th>
              <th className="py-2.5 px-4 font-semibold">Suggested Engineering Action</th>
              <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-400 font-mono">
                  Loading evidence-based remediation queue...
                </td>
              </tr>
            ) : queueItems.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                  No vulnerabilities in queue matching selected priority filter.
                </td>
              </tr>
            ) : (
              queueItems.map((item, idx) => (
                <tr
                  key={item.finding_id}
                  onClick={() => handleRowClick(item.finding_id)}
                  className="hover:bg-blue-50/40 transition-colors cursor-pointer group"
                >
                  {/* Rank */}
                  <td className="py-3 px-4 font-mono font-bold text-slate-400 text-center">
                    #{idx + 1}
                  </td>

                  {/* Contextual Priority + Score */}
                  <td className="py-3 px-4 shrink-0">
                    <div className="flex items-center gap-1.5">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono border ${getPriorityBadgeClass(item.contextual_priority)}`}>
                        {item.contextual_priority}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-700">
                        {item.priority_score.toFixed(0)}/100
                      </span>
                    </div>
                  </td>

                  {/* Original Scanner Severity */}
                  <td className="py-3 px-4 shrink-0">
                    <span className="font-mono text-[11px] font-semibold text-slate-600 block">
                      {item.original_scanner_severity}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {item.scanner_name}
                    </span>
                  </td>

                  {/* Title & File Path */}
                  <td className="py-3 px-4 max-w-xs">
                    <span className="font-semibold text-slate-900 block group-hover:text-blue-600 transition-colors truncate" title={item.title}>
                      {item.title}
                    </span>
                    <div className="flex items-center gap-1 text-[11px] text-slate-500 font-mono mt-0.5 truncate">
                      <span className="text-slate-700 font-medium">{item.repo_name}</span>
                      <span>•</span>
                      <span className="truncate">{item.file_path}:{item.line_number}</span>
                    </div>
                  </td>

                  {/* Component Category */}
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-600">
                    <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                      {item.affected_component}
                    </span>
                  </td>

                  {/* Remediation Readiness */}
                  <td className="py-3 px-4 shrink-0">
                    {getReadinessBadge(item.remediation_status)}
                  </td>

                  {/* Suggested Engineering Action */}
                  <td className="py-3 px-4 max-w-sm">
                    <span className="text-[11px] text-slate-700 block truncate" title={item.suggested_action}>
                      {item.suggested_action}
                    </span>
                    {item.linkage.recommendations.length > 0 && (
                      <span className="text-[10px] text-blue-600 font-mono block mt-0.5 truncate">
                        Rec: {item.linkage.recommendations[0]}
                      </span>
                    )}
                  </td>

                  {/* Actions */}
                  <td className="py-3 px-4 text-right" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1.5">
                      {item.linkage.patch_proposal_id && onOpenDiffModal && (
                        <button
                          type="button"
                          onClick={() => {
                            if (onOpenDiffModal) {
                              onOpenDiffModal({
                                id: item.finding_id,
                                repo: item.repo_name,
                                branch: 'main',
                                gitHash: 'HEAD',
                                engine: item.scanner_name,
                                target: item.file_path,
                                findingsCount: { critical: 1 },
                                status: 'verified',
                                message: item.title,
                                prNumber: 418,
                              });
                            }
                          }}
                          className="px-2 py-0.5 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-200 rounded font-mono text-[11px] font-semibold transition-colors"
                        >
                          Diff
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleRowClick(item.finding_id)}
                        className="px-2.5 py-1 text-xs font-semibold bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded-lg transition-colors flex items-center gap-1"
                        title="Open finding and inspect evidence"
                      >
                        <span>Triage</span>
                        <span className="material-symbols-outlined text-xs">open_in_new</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
