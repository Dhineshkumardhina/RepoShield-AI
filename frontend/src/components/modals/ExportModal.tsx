import React, { useState } from 'react';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ExportModal: React.FC<ExportModalProps> = ({ isOpen, onClose }) => {
  const [format, setFormat] = useState<'sarif' | 'json' | 'pdf'>('sarif');
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  if (!isOpen) return null;

  const mockSarifData = JSON.stringify(
    {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'RepoShield AI by Xerova',
              version: '4.2.8',
              informationUri: 'https://xerova.internal/appsec',
              rules: [
                {
                  id: 'python.sqlalchemy.security.audit.raw-sql-format',
                  name: 'SQLInjectionRawQuery',
                  shortDescription: { text: 'Untrusted user input formatted directly into cursor.execute' },
                  defaultConfiguration: { level: 'error' }
                }
              ]
            }
          },
          results: [
            {
              ruleId: 'python.sqlalchemy.security.audit.raw-sql-format',
              level: 'error',
              message: { text: 'SQL injection detected in auth-gateway/src/dao/user_query.py' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'auth-gateway/src/dao/user_query.py' },
                    region: { startLine: 41, startColumn: 1 }
                  }
                }
              ],
              fixes: [
                {
                  description: { text: 'AST-verified parameterized query tuple' }
                }
              ]
            }
          ]
        }
      ]
    },
    null,
    2
  );

  const handleDownload = () => {
    let content = '';
    let mimeType = '';
    let filename = '';

    if (format === 'sarif') {
      content = mockSarifData;
      mimeType = 'application/json';
      filename = 'reposhield-compliance-report.sarif';
    } else if (format === 'json') {
      content = JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          workspace: 'Xerova Production CI/CD',
          engineStatus: 'Online v4.2.8',
          postureScore: 84.2,
          openVulnerabilities: { total: 148, critical: 14, high: 32, med: 68, low: 34 },
          verifiedPatchesSafe: 34,
          regressionsQuarantined: 9,
          commitCoverage: 98.4
        },
        null,
        2
      );
      mimeType = 'application/json';
      filename = 'reposhield-compliance-report.json';
    } else {
      content = `RepoShield AI Compliance & Audit Summary\nGenerated: ${new Date().toUTCString()}\nWorkspace: Xerova Production CI/CD\nSecurity Posture Score: 84.2/100 (Grade B+)\nOpen Findings: 148\nAST Verified Patches: 34\nCommit Coverage: 98.4% Enforced\nStandards: SOC 2 Type II, ISO 27001:2022, PCI-DSS v4.0`;
      mimeType = 'text/plain';
      filename = 'reposhield-executive-summary.txt';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => {
      setDownloadSuccess(false);
    }, 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs font-sans">
      <div className="relative w-full max-w-2xl bg-white rounded-xl shadow-2xl border border-slate-200 flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-2xs">
              <span className="material-symbols-outlined text-xl">download</span>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">Export AppSec Compliance &amp; Audit Trail</h3>
              <p className="font-mono text-xs text-slate-500 mt-0.5">
                Standardized artifact generation for SecOps, DevSecOps &amp; external auditors
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase font-semibold block mb-2">
              Select Output Format
            </label>
            <div className="grid grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setFormat('sarif')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  format === 'sarif'
                    ? 'border-slate-900 bg-slate-50 shadow-2xs ring-1 ring-slate-900'
                    : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-slate-900">OASIS SARIF</span>
                  <span className="font-mono text-[10px] text-blue-600 font-semibold uppercase">v2.1.0</span>
                </div>
                <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                  Industry standard for GitHub Advanced Security, GitLab, and DefectDojo.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setFormat('pdf')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  format === 'pdf'
                    ? 'border-slate-900 bg-slate-50 shadow-2xs ring-1 ring-slate-900'
                    : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-slate-900">Audit Summary</span>
                  <span className="font-mono text-[10px] text-emerald-600 font-semibold uppercase">SOC 2 / ISO</span>
                </div>
                <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                  Executive overview with cryptographic verification timestamps.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setFormat('json')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  format === 'json'
                    ? 'border-slate-900 bg-slate-50 shadow-2xs ring-1 ring-slate-900'
                    : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-slate-900">Raw JSON</span>
                  <span className="font-mono text-[10px] text-slate-500 font-semibold uppercase">REST API</span>
                </div>
                <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                  Full programmatic machine telemetry and repository inventory.
                </p>
              </button>
            </div>
          </div>

          {/* Artifact Preview */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
                Payload Preview ({format.toUpperCase()})
              </span>
              <span className="font-mono text-xs text-slate-400">Deterministic Hash: 0x90fa3...</span>
            </div>
            <pre className="p-3.5 rounded-lg bg-slate-900 text-emerald-400 font-mono text-xs overflow-x-auto max-h-48 border border-slate-800 shadow-inner">
              {format === 'sarif'
                ? mockSarifData
                : format === 'json'
                ? '{\n  "workspace": "Xerova Production CI/CD",\n  "postureScore": 84.2,\n  "openVulnerabilities": 148,\n  "verifiedPatches": 34\n}'
                : 'RepoShield AI Executive Compliance Audit\n- 42 Monitored Codebases\n- Zero Tolerated Secrets Policy Enforced\n- SOC 2 Type II: Compliant (68/70 controls)'}
            </pre>
          </div>

          {downloadSuccess && (
            <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 font-mono text-xs flex items-center gap-1.5">
              <span className="material-symbols-outlined text-sm">check_circle</span>
              <span>Artifact downloaded successfully.</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors shadow-2xs"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-slate-900 text-white hover:bg-slate-800 text-xs font-semibold transition-all shadow-2xs"
          >
            <span className="material-symbols-outlined text-sm">download</span>
            <span>Download {format.toUpperCase()}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
