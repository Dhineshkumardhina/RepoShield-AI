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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs">
      <div className="relative w-full max-w-2xl bg-surface-container-lowest rounded shadow-xl border border-outline-variant flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-5 py-4 border-b border-outline-variant flex items-center justify-between bg-surface-container-low">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-primary text-xl">download</span>
            <div>
              <h3 className="font-headline-sm text-on-surface">Export AppSec Compliance &amp; Audit Trail</h3>
              <p className="font-mono-sm text-on-surface-variant">
                Standardized artifact generation for SecOps, DevSecOps &amp; external auditors
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4">
          <div>
            <label className="font-label-caps text-on-surface-variant uppercase font-semibold block mb-2">
              Select Output Format
            </label>
            <div className="grid grid-cols-3 gap-2.5">
              <button
                onClick={() => setFormat('sarif')}
                className={`p-3 rounded border text-left transition-all ${
                  format === 'sarif'
                    ? 'border-primary bg-surface-container text-on-surface shadow-xs'
                    : 'border-outline-variant hover:bg-surface-container-low text-on-surface-variant'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono-sm font-bold text-on-surface">OASIS SARIF</span>
                  <span className="font-label-caps text-primary uppercase">v2.1.0</span>
                </div>
                <p className="text-body-sm text-on-surface-variant text-xs">
                  Industry standard for GitHub Advanced Security, GitLab, and DefectDojo.
                </p>
              </button>

              <button
                onClick={() => setFormat('pdf')}
                className={`p-3 rounded border text-left transition-all ${
                  format === 'pdf'
                    ? 'border-primary bg-surface-container text-on-surface shadow-xs'
                    : 'border-outline-variant hover:bg-surface-container-low text-on-surface-variant'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono-sm font-bold text-on-surface">Audit Summary</span>
                  <span className="font-label-caps text-tertiary uppercase">SOC 2 / ISO</span>
                </div>
                <p className="text-body-sm text-on-surface-variant text-xs">
                  Executive overview with cryptographic verification timestamps.
                </p>
              </button>

              <button
                onClick={() => setFormat('json')}
                className={`p-3 rounded border text-left transition-all ${
                  format === 'json'
                    ? 'border-primary bg-surface-container text-on-surface shadow-xs'
                    : 'border-outline-variant hover:bg-surface-container-low text-on-surface-variant'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono-sm font-bold text-on-surface">Raw JSON Dump</span>
                  <span className="font-label-caps text-secondary uppercase">REST Telemetry</span>
                </div>
                <p className="text-body-sm text-on-surface-variant text-xs">
                  Full programmatic machine telemetry and repository inventory.
                </p>
              </button>
            </div>
          </div>

          {/* Artifact Preview */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-label-caps text-on-surface-variant uppercase font-semibold">
                Payload Preview ({format.toUpperCase()})
              </span>
              <span className="font-mono-sm text-outline">Deterministic Hash: 0x90fa3...</span>
            </div>
            <pre className="p-3 rounded bg-[#0b1c30] text-emerald-400 font-mono-sm text-xs overflow-x-auto max-h-48 border border-slate-700">
              {format === 'sarif'
                ? mockSarifData
                : format === 'json'
                ? '{\n  "workspace": "Xerova Production CI/CD",\n  "postureScore": 84.2,\n  "openVulnerabilities": 148,\n  "verifiedPatches": 34\n}'
                : 'RepoShield AI Executive Compliance Audit\n- 42 Monitored Codebases\n- Zero Tolerated Secrets Policy Enforced\n- SOC 2 Type II: Compliant (68/70 controls)'}
            </pre>
          </div>

          {downloadSuccess && (
            <div className="p-2.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-xs flex items-center gap-1.5">
              <span className="material-symbols-outlined text-sm">check_circle</span>
              <span>Artifact downloaded successfully.</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 border-t border-outline-variant bg-surface-container-lowest flex items-center justify-end gap-2.5">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded border border-outline-variant bg-surface-container-lowest hover:bg-surface-container text-on-surface font-body-sm transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-primary text-on-primary hover:bg-on-primary-fixed-variant font-body-sm font-medium transition-colors shadow-sm"
          >
            <span className="material-symbols-outlined text-base">download</span>
            <span>Download {format.toUpperCase()}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
