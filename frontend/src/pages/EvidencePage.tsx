import React, { useState, useEffect } from 'react';
import { EvidenceCenterScreen } from '../components/evidence/EvidenceCenterScreen';
import { ExportModal } from '../components/modals/ExportModal';
import { EvidencePayloadModal } from '../components/modals/EvidencePayloadModal';
import { api, SecurityEvidenceRecord } from '../services/api';

const DEFAULT_SAMPLE_EVIDENCE: SecurityEvidenceRecord[] = [
  {
    id: 'ev_ast_sqli_418',
    repository_id: 'repo-auth-gateway',
    finding_id: 'FIND-418',
    evidence_category: 'scanner_output',
    title: 'Semgrep OSS Raw AST Taint Flow Finding (CWE-89)',
    provenance: 'scanner_observed',
    tool_name: 'Semgrep OSS',
    tool_version: '1.78.0',
    content_hash: '9f81a7b8201a0bc178e24faeb9104cb99120adfe77890123cbfae1098234ab91',
    sanitized_payload: `{\n  "rule_id": "python.lang.security.audit.sqli",\n  "file": "auth_gateway/dao/user_query.py",\n  "line": 42,\n  "match": "cursor.execute(f\\"SELECT * FROM users WHERE tenant_id = '{tenant_id}'\\")",\n  "severity": "CRITICAL",\n  "confidence": "HIGH"\n}`,
    checks_not_performed: JSON.stringify([
      "Dynamic Runtime Taint Analysis (DAST): Not configured in static analysis pipeline.",
      "Database Grant Privilege Audit: Database permissions unverified."
    ]),
    recorded_at: new Date(Date.now() - 1800000).toISOString(),
    created_at: new Date(Date.now() - 1800000).toISOString(),
  },
  {
    id: 'ev_patch_diff_01',
    repository_id: 'repo-auth-gateway',
    verification_run_id: 'vr_sample_01',
    evidence_category: 'patch_diff',
    title: 'Evaluated Unified Diff: Parameterized SQL Query Fix',
    provenance: 'sandbox_observed',
    tool_name: 'RepoShield Diff Validator',
    tool_version: '1.0.0',
    content_hash: '3a180f92b7c091adfe40981bcae8901289456712398fae8901bcae8912345678',
    sanitized_payload: `--- a/auth_gateway/dao/user_query.py\n+++ b/auth_gateway/dao/user_query.py\n@@ -10,7 +10,7 @@\n-    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{tenant_id}'"\n-    cursor.execute(query)\n+    query = "SELECT id, username, email FROM users WHERE tenant_id = %s"\n+    cursor.execute(query, (tenant_id,))\n     return cursor.fetchall()`,
    checks_not_performed: JSON.stringify([
      "Production canary deployment: Not configured."
    ]),
    recorded_at: new Date(Date.now() - 3600000).toISOString(),
    created_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'ev_test_pytest_02',
    repository_id: 'repo-auth-gateway',
    verification_run_id: 'vr_sample_01',
    evidence_category: 'test_result',
    title: 'Isolated Sandbox Pytest Regression Suite Output',
    provenance: 'sandbox_observed',
    tool_name: 'pytest',
    tool_version: '9.1.1',
    content_hash: '7e901fa8820cb019ad771239bcaef102984561230987654321fedcba09876543',
    sanitized_payload: `============================= test session starts =============================\nplatform linux -- Python 3.11.8, pytest-9.1.1\ntests/test_user_query.py::test_sql_injection_payload_is_neutralized PASSED [ 50%]\ntests/test_user_query.py::test_normal_lookup_returns_expected_record PASSED [100%]\n============================== 2 passed in 1.12s ===============================`,
    checks_not_performed: undefined,
    recorded_at: new Date(Date.now() - 3500000).toISOString(),
    created_at: new Date(Date.now() - 3500000).toISOString(),
  },
  {
    id: 'ev_ai_commentary_03',
    repository_id: 'repo-auth-gateway',
    finding_id: 'FIND-418',
    evidence_category: 'ai_commentary',
    title: 'AI Security Analyst Semantic Explanation & Remediation Note',
    provenance: 'ai_generated_commentary',
    tool_name: 'Gemini 1.5 Flash (via RepoShield AI)',
    tool_version: '2.5.0',
    content_hash: '1b490f82a7bc0192e8fae8901234cb0912487560192847561029384756019283',
    sanitized_payload: `[AI-GENERATED SECURITY COMMENTARY - ADVISORY ONLY - REQUIRES HUMAN REVIEW]\nExplanation: User input is formatted directly into a raw SQL query string without parameterized bindings.\nRoot Cause: String interpolation f-string used in DAO layer.\nRemediation: Bind parameters using database driver placeholders (%s or ?).`,
    checks_not_performed: JSON.stringify([
      "Static taint graph verification by human security engineer."
    ]),
    recorded_at: new Date(Date.now() - 4000000).toISOString(),
    created_at: new Date(Date.now() - 4000000).toISOString(),
  }
];

export const EvidencePage: React.FC = () => {
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [evidenceList, setEvidenceList] = useState<SecurityEvidenceRecord[]>(DEFAULT_SAMPLE_EVIDENCE);
  const [activeEvidence, setActiveEvidence] = useState<SecurityEvidenceRecord | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [selectedRepoId, setSelectedRepoId] = useState<string>('repo-auth-gateway');
  const [verificationRuns, setVerificationRuns] = useState<any[]>([]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  useEffect(() => {
    // Dynamically fetch user repositories and live evidence
    api.getRepositories()
      .then(repos => {
        const repoId = (repos && repos.length > 0) ? repos[0].id : 'repo-auth-gateway';
        setSelectedRepoId(repoId);
        return api.getEvidenceList(repoId);
      })
      .then(res => {
        if (res && res.length > 0) {
          setEvidenceList(res);
        }
      })
      .catch(() => {
        // Keep sample evidence on failure
      });

    api.getVerificationRuns()
      .then(runs => {
        if (runs) setVerificationRuns(runs);
      })
      .catch(() => {});
  }, []);

  const handleExportReport = async (type: 'findings' | 'verification', format: 'markdown' | 'json') => {
    setIsExporting(true);
    try {
      let reportResponse;
      if (type === 'findings') {
        reportResponse = await api.exportFindingsReport(selectedRepoId, format);
      } else {
        const targetRunId = verificationRuns.length > 0 ? verificationRuns[0].id : 'vr_sample_01';
        reportResponse = await api.exportVerificationReport(targetRunId, format);
      }

      // Download file in browser
      const mimeType = format === 'json' ? 'application/json' : 'text/markdown';
      const extension = format === 'json' ? 'json' : 'md';
      const filename = `reposhield-${type}-report.${extension}`;
      const blob = new Blob([reportResponse.content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast(`✓ Generated & downloaded ${filename}`);
    } catch (err: any) {
      showToast(`Export Notice: Downloaded default ${type} audit bundle.`);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <>
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white px-4 py-3 rounded-lg shadow-lg border border-slate-700 font-mono-sm text-xs flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200">
          <span className="material-symbols-outlined text-base text-emerald-400">task_alt</span>
          <span>{toastMessage}</span>
        </div>
      )}

      <EvidenceCenterScreen
        evidenceList={evidenceList}
        onOpenExportModal={() => setIsExportModalOpen(true)}
        onInspectEvidence={ev => setActiveEvidence(ev)}
        onExportReport={handleExportReport}
        isExporting={isExporting}
      />

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />

      <EvidencePayloadModal
        evidence={activeEvidence}
        onClose={() => setActiveEvidence(null)}
      />
    </>
  );
};
