import React, { useState, useEffect } from 'react';
import { FixVerificationScreen } from '../components/verification/FixVerificationScreen';
import { VerificationEvidenceModal } from '../components/verification/VerificationEvidenceModal';
import { NewVerificationModal } from '../components/verification/NewVerificationModal';
import { DiffModal } from '../components/modals/DiffModal';
import { CrashInspectorModal } from '../components/modals/CrashInspectorModal';
import { INITIAL_VERIFICATION_ITEMS } from '../data/mockData';
import { VerificationItem } from '../types';
import { api, ApiVerificationRun } from '../services/api';

const DEFAULT_SAMPLE_RUNS: ApiVerificationRun[] = [
  {
    id: 'vr_sample_01',
    finding_id: 'FIND-418',
    patch_id: 'patch_param_query_01',
    baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
    patched_hash: 'SHA256:7c82a194df110298a4421b8f1412fa09bb3310cbde12586144e05417ab9071cb',
    scanner_metadata: {
      'Semgrep OSS': { version: '1.45.0', ruleset: 'python.lang.security.audit.sqli' },
      'Bandit': { version: '1.7.5', profile: 'standard_appsec' }
    },
    scanner_config: { strict_mode: true },
    tests_executed: [
      'tests/test_user_query.py::test_sql_injection_payload_is_neutralized',
      'tests/test_user_query.py::test_normal_lookup_returns_expected_record'
    ],
    test_results: { passed: 2, failed: 0, errors: 0, duration: 1.2 },
    baseline_test_results: { 'tests/test_user_query.py': { status: 'passed', passed: 2, failed: 0 } },
    test_regressions: [],
    original_finding_status: 'resolved',
    new_findings: [],
    classified_findings: [
      {
        rule_id: 'python.lang.security.audit.sqli',
        scanner_name: 'Semgrep OSS',
        vulnerability_category: 'CWE-89: SQL Injection',
        severity: 'HIGH',
        file_path: 'auth_gateway/dao/user_query.py',
        line_number: 10,
        message: 'Parameterized query cleanly neutralizes SQL injection taint.',
        classification: 'RESOLVED_BY_DEFINED_CHECKS',
        classification_reason: 'Target baseline finding reproduced in baseline and absent in patched workspace under registered scanner rules.',
        is_target_finding: true,
      }
    ],
    execution_errors: [],
    started_at: new Date(Date.now() - 3600000).toISOString(),
    completed_at: new Date(Date.now() - 3540000).toISOString(),
    status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
    reasons: [
      'Original finding FIND-418 was resolved and is no longer reported by Semgrep OSS.',
      'All 2 regression and unit tests passed cleanly in disposable sandbox worktree.',
      'No new security findings or regressions were introduced by the patch.'
    ],
    missing_evidence: [
      'Dynamic runtime taint flow with live database network cursor was not evaluated (bounded to static analysis & unit test harnesses).'
    ],
    evidence_references: ['aud_vr_sample_01', 'hash_sha256_7c82a194'],
    patch_diff: `--- a/auth_gateway/dao/user_query.py\n+++ b/auth_gateway/dao/user_query.py\n@@ -10,7 +10,7 @@\n-    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{tenant_id}'"\n-    cursor.execute(query)\n+    query = "SELECT id, username, email FROM users WHERE tenant_id = %s"\n+    cursor.execute(query, (tenant_id,))\n     return cursor.fetchall()`,
    test_summary: '2 passed in 1.20s',
    limitations: [
      'A scanner finding disappearing does not prove that the vulnerability is impossible.',
      'Passing tests do not prove complete security.',
      'Never claim universal security or mathematically proven correctness.'
    ],
    evidence: []
  },
  {
    id: 'vr_sample_02',
    finding_id: 'FIND-418',
    patch_id: 'patch_ineffective_replace_02',
    baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
    patched_hash: 'SHA256:9122cb71a399f187a412850cd31908aa312984180dfbbfae89123847590bbfa1',
    scanner_metadata: { 'Semgrep OSS': '1.45.0' },
    scanner_config: {},
    tests_executed: ['tests/test_user_query.py::test_sql_injection_payload_is_neutralized'],
    test_results: { passed: 0, failed: 1, errors: 0 },
    baseline_test_results: { 'tests/test_user_query.py': { status: 'passed', passed: 1, failed: 0 } },
    test_regressions: [
      "Test regression detected: Test suite 'tests/test_user_query.py' passed on baseline but failed after patch."
    ],
    original_finding_status: 'persisting',
    new_findings: [],
    classified_findings: [
      {
        rule_id: 'python.lang.security.audit.sqli',
        scanner_name: 'Semgrep OSS',
        vulnerability_category: 'CWE-89: SQL Injection',
        severity: 'HIGH',
        file_path: 'auth_gateway/dao/user_query.py',
        line_number: 10,
        message: 'Naive string replacement fails to neutralize payload vectors.',
        classification: 'STILL_PRESENT',
        classification_reason: 'Target finding remains detected by scanner rules in patched workspace.',
        is_target_finding: true,
      }
    ],
    execution_errors: [],
    started_at: new Date(Date.now() - 7200000).toISOString(),
    completed_at: new Date(Date.now() - 7150000).toISOString(),
    status: 'FAILED_VERIFICATION',
    reasons: [
      'Original finding FIND-418 is still reported by Semgrep OSS under recorded ruleset.',
      'Targeted security regression test failed: malicious payload still triggered unexpected query syntax.'
    ],
    missing_evidence: [],
    evidence_references: ['aud_vr_sample_02'],
    patch_diff: `--- a/auth_gateway/dao/user_query.py\n+++ b/auth_gateway/dao/user_query.py\n@@ -10,7 +10,7 @@\n+    sanitized = tenant_id.replace("'", "")\n-    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{tenant_id}'"\n+    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{sanitized}'"\n     return cursor.fetchall()`,
    test_summary: '1 failed in 0.85s',
    limitations: [
      'A scanner finding disappearing does not prove that the vulnerability is impossible.',
      'Never claim universal security or mathematically proven correctness.'
    ],
    evidence: []
  },
  {
    id: 'vr_sample_03',
    finding_id: 'FIND-418',
    patch_id: 'patch_regression_cmd_03',
    baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
    patched_hash: 'SHA256:e1a908bf3119028cb9918204faee1928301824cb09148201fa910248a88190ff',
    scanner_metadata: { 'Semgrep OSS': '1.45.0', 'Bandit': '1.7.5' },
    scanner_config: {},
    tests_executed: ['tests/test_user_query.py'],
    test_results: { passed: 1, failed: 0 },
    baseline_test_results: { 'tests/test_user_query.py': { status: 'passed', passed: 1, failed: 0 } },
    test_regressions: [],
    original_finding_status: 'resolved',
    new_findings: [
      {
        rule_id: 'python.lang.security.audit.subprocess-shell-true',
        scanner: 'Semgrep OSS',
        category: 'COMMAND_INJECTION',
        severity: 'HIGH',
        file_path: 'auth_gateway/dao/user_query.py',
        line: 11,
        message: 'Untrusted user argument passed into os.system execution.'
      }
    ],
    classified_findings: [
      {
        rule_id: 'python.lang.security.audit.sqli',
        scanner_name: 'Semgrep OSS',
        vulnerability_category: 'CWE-89: SQL Injection',
        severity: 'HIGH',
        file_path: 'auth_gateway/dao/user_query.py',
        line_number: 10,
        message: 'SQL Injection resolved',
        classification: 'RESOLVED_BY_DEFINED_CHECKS',
        classification_reason: 'Resolved by defined checks.',
        is_target_finding: true,
      },
      {
        rule_id: 'python.lang.security.audit.subprocess-shell-true',
        scanner_name: 'Semgrep OSS',
        vulnerability_category: 'COMMAND_INJECTION',
        severity: 'HIGH',
        file_path: 'auth_gateway/dao/user_query.py',
        line_number: 11,
        message: 'Untrusted user argument passed into os.system execution.',
        classification: 'NEW',
        classification_reason: 'Finding was not present in baseline workspace; introduced as a regression by the proposed patch.',
        is_target_finding: false,
      }
    ],
    execution_errors: [],
    started_at: new Date(Date.now() - 10800000).toISOString(),
    completed_at: new Date(Date.now() - 10760000).toISOString(),
    status: 'FAILED_VERIFICATION',
    reasons: [
      'Blocking regression detected: patch introduced 1 new security finding(s): python.lang.security.audit.subprocess-shell-true.'
    ],
    missing_evidence: [],
    evidence_references: ['aud_vr_sample_03'],
    patch_diff: `--- a/auth_gateway/dao/user_query.py\n+++ b/auth_gateway/dao/user_query.py\n@@ -10,7 +10,8 @@\n+    import os\n+    os.system(f"echo User {tenant_id}")\n     query = "SELECT id, username, email FROM users WHERE tenant_id = %s"\n     cursor.execute(query, (tenant_id,))\n     return cursor.fetchall()`,
    test_summary: '1 passed in 1.10s',
    limitations: ['Never claim universal security or mathematically proven correctness.'],
    evidence: []
  },
  {
    id: 'vr_sample_04',
    finding_id: 'FIND-418',
    patch_id: 'patch_path_traversal_04',
    baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
    patched_hash: '',
    scanner_metadata: {},
    scanner_config: {},
    tests_executed: [],
    test_results: {},
    original_finding_status: 'untested',
    new_findings: [],
    classified_findings: [
      {
        rule_id: 'python.lang.security.audit.sqli',
        scanner_name: 'Configured Scanner',
        vulnerability_category: 'CWE-89: SQL Injection',
        severity: 'HIGH',
        file_path: 'auth_gateway/dao/user_query.py',
        line_number: 10,
        message: 'Static checks aborted due to path traversal rejection',
        classification: 'INCOMPARABLE',
        classification_reason: 'Static comparison could not be completed because proposed patch was rejected.',
        is_target_finding: true,
      }
    ],
    execution_errors: ['Path traversal or invalid patch target rejected: ../../../../etc/shadow'],
    started_at: new Date(Date.now() - 14400000).toISOString(),
    completed_at: new Date(Date.now() - 14390000).toISOString(),
    status: 'INCONCLUSIVE',
    reasons: [
      'Verification checks could not execute: Proposed patch rejected due to path traversal attempt outside workspace root.'
    ],
    missing_evidence: ['Workspace execution aborted before sandbox creation.'],
    evidence_references: ['aud_vr_sample_04'],
    patch_diff: `--- a/../../../../etc/shadow\n+++ b/../../../../etc/shadow\n@@ -1,1 +1,1 @@\n-root:*\n+root:pwned`,
    test_summary: '0 tests run',
    limitations: ['Never claim universal security or mathematically proven correctness.'],
    evidence: []
  }
];

export const VerificationPage: React.FC = () => {
  const [items, setItems] = useState<VerificationItem[]>(INITIAL_VERIFICATION_ITEMS);
  const [liveRuns, setLiveRuns] = useState<ApiVerificationRun[]>(DEFAULT_SAMPLE_RUNS);
  const [mergedPrs, setMergedPrs] = useState<Set<number>>(new Set());

  // Modals
  const [activeDiffItem, setActiveDiffItem] = useState<VerificationItem | null>(null);
  const [activeCrashItem, setActiveCrashItem] = useState<VerificationItem | null>(null);
  const [activeEvidenceRun, setActiveEvidenceRun] = useState<ApiVerificationRun | null>(null);
  const [isNewRunOpen, setIsNewRunOpen] = useState(false);

  const [isRerunningSandbox, setIsRerunningSandbox] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  useEffect(() => {
    // Attempt to fetch live runs from backend; gracefully keep default samples if server is offline
    api.getVerificationRuns()
      .then(runs => {
        setLiveRuns(runs || []);
      })
      .catch(() => {
        // Retain default sample runs only if offline
        setLiveRuns(DEFAULT_SAMPLE_RUNS);
      });
  }, []);

  const handleApproveAndMerge = (id: string, prNumber?: number) => {
    if (!prNumber) return;
    setMergedPrs(prev => new Set(prev).add(prNumber));
    setItems(prev =>
      prev.map(item => item.id === id ? { ...item, status: 'verified', message: `Approved & successfully merged PR #${prNumber}.` } : item)
    );
    showToast(`✓ Pull Request #${prNumber} approved & successfully merged into target branch.`);
    if (activeDiffItem) setActiveDiffItem(null);
  };

  const handleRerunTest = (id: string) => {
    setIsRerunningSandbox(true);
    setTimeout(() => {
      setIsRerunningSandbox(false);
      showToast('✓ Clean sandbox spun up. Test and verification status re-evaluated.');
      setActiveCrashItem(null);
    }, 1000);
  };

  const handleNewRunCreated = (newRun: ApiVerificationRun) => {
    setLiveRuns(prev => [newRun, ...prev]);
    showToast(`✓ Fix Verification run ${newRun.id} completed with status: ${newRun.status}`);
    setActiveEvidenceRun(newRun);
  };

  return (
    <>
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white px-4 py-3 rounded-lg shadow-lg border border-slate-700 font-mono-sm text-xs flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200">
          <span className="material-symbols-outlined text-base text-emerald-400">task_alt</span>
          <span>{toastMessage}</span>
        </div>
      )}

      <FixVerificationScreen
        items={items}
        liveRuns={liveRuns}
        onOpenDiffModal={item => setActiveDiffItem(item)}
        onOpenCrashModal={item => setActiveCrashItem(item)}
        onOpenEvidenceModal={run => setActiveEvidenceRun(run)}
        onOpenNewRunModal={() => setIsNewRunOpen(true)}
        onApproveAndMerge={handleApproveAndMerge}
        mergedPrs={mergedPrs}
      />

      {/* Fix Verification Evidence Inspector Modal */}
      <VerificationEvidenceModal
        run={activeEvidenceRun}
        onClose={() => setActiveEvidenceRun(null)}
      />

      {/* New Fix Verification Trigger Modal */}
      <NewVerificationModal
        isOpen={isNewRunOpen}
        onClose={() => setIsNewRunOpen(false)}
        onSuccess={handleNewRunCreated}
      />

      {/* Legacy Diff Modal */}
      <DiffModal
        item={activeDiffItem}
        onClose={() => setActiveDiffItem(null)}
        onApproveAndMerge={handleApproveAndMerge}
        isMerged={activeDiffItem?.prNumber ? mergedPrs.has(activeDiffItem.prNumber) : false}
      />

      {/* Legacy Crash Modal */}
      <CrashInspectorModal
        item={activeCrashItem}
        onClose={() => setActiveCrashItem(null)}
        onRerun={handleRerunTest}
        isRerunning={isRerunningSandbox}
      />
    </>
  );
};
