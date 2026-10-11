import React, { useState, useEffect } from 'react';
import { api, ScannerToolInfo, ScanResultDetail, ApiRepository } from '../../services/api';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: () => void;
  targetRepoName?: string;
  targetRepoId?: string;
}

export const ScanModal: React.FC<ScanModalProps> = ({
  isOpen,
  onClose,
  onScanComplete,
  targetRepoName,
  targetRepoId,
}) => {
  const [repositories, setRepositories] = useState<ApiRepository[]>([]);
  const [selectedRepoId, setSelectedRepoId] = useState<string>(targetRepoId || '');
  const [tools, setTools] = useState<ScannerToolInfo[]>([]);
  const [selectedToolNames, setSelectedToolNames] = useState<string[]>([]);
  
  const [isLoadingTools, setIsLoadingTools] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResultDetail | null>(null);

  useEffect(() => {
    if (isOpen) {
      setErrorMessage(null);
      setScanResult(null);
      setIsScanning(false);
      
      // Load available tools from backend
      setIsLoadingTools(true);
      api.getScannerTools()
        .then((fetchedTools) => {
          setTools(fetchedTools);
          // Default: select all currently available tools
          const available = fetchedTools.filter(t => t.is_available).map(t => t.name);
          setSelectedToolNames(available);
        })
        .catch((err) => {
          console.error('Failed to load scanner tools:', err);
          setErrorMessage('Could not load scanner tool availability. Ensure backend is running.');
        })
        .finally(() => {
          setIsLoadingTools(false);
        });

      // Load repositories if targetRepoId not provided
      if (!targetRepoId) {
        api.getRepositories()
          .then((repos) => {
            setRepositories(repos);
            if (repos.length > 0 && !selectedRepoId) {
              setSelectedRepoId(repos[0].id);
            }
          })
          .catch((err) => {
            console.error('Failed to load repositories:', err);
          });
      } else {
        setSelectedRepoId(targetRepoId);
      }
    }
  }, [isOpen, targetRepoId]);

  const toggleTool = (toolName: string) => {
    setSelectedToolNames((prev) =>
      prev.includes(toolName) ? prev.filter((t) => t !== toolName) : [...prev, toolName]
    );
  };

  const handleStartScan = async () => {
    if (!selectedRepoId) {
      setErrorMessage('Please select a repository to scan.');
      return;
    }
    if (selectedToolNames.length === 0) {
      setErrorMessage('Please select at least one security scanner to run.');
      return;
    }

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);

    try {
      // Trigger scan via real scanning API
      const scan = await api.triggerScan({
        repository_id: selectedRepoId,
        tools: selectedToolNames,
        summary: `Manual security audit executed from dashboard`,
      });

      // Retrieve full execution details & normalized results
      const results = await api.getScanResults(scan.id);
      setScanResult(results);
    } catch (err: any) {
      console.error('Scan execution error:', err);
      setErrorMessage(err.message || 'Scan execution failed. Check repository workspace status.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleFinish = () => {
    onScanComplete();
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
      <div className="relative w-full max-w-2xl bg-white rounded-lg shadow-2xl border border-slate-200 flex flex-col max-h-[90vh] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-md bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <span className="material-symbols-outlined text-xl">security</span>
            </div>
            <div>
              <h3 className="font-semibold text-slate-900 text-lg">Execute AppSec Security Scan</h3>
              <p className="text-xs text-slate-500">
                Run verified static analysis, dependency SCA, and credential detectors
              </p>
            </div>
          </div>
          {!isScanning && (
            <button
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors"
            >
              <span className="material-symbols-outlined text-xl">close</span>
            </button>
          )}
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5">
          {errorMessage && (
            <div className="p-3.5 rounded-md bg-red-50 border border-red-200 text-red-700 text-sm flex items-start gap-2.5">
              <span className="material-symbols-outlined text-red-500 text-base mt-0.5">error</span>
              <div className="flex-1">{errorMessage}</div>
            </div>
          )}

          {/* Configuration View (Before Scan) */}
          {!isScanning && !scanResult && (
            <>
              {/* Repository Target Selection */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
                  Target Repository
                </label>
                {targetRepoName ? (
                  <div className="px-3.5 py-2.5 rounded-md bg-slate-50 border border-slate-200 text-sm font-medium text-slate-900 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-base text-blue-600">folder</span>
                      <span>{targetRepoName}</span>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">Workspace isolated</span>
                  </div>
                ) : (
                  <select
                    value={selectedRepoId}
                    onChange={(e) => setSelectedRepoId(e.target.value)}
                    className="w-full px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  >
                    {repositories.map((repo) => (
                      <option key={repo.id} value={repo.id}>
                        {repo.name} ({repo.source_type || 'local'}) — Health: {repo.health_score}%
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Security Scanner Engines */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
                    Scanning Engines to Execute
                  </label>
                  <span className="text-xs text-slate-500">
                    {selectedToolNames.length} selected
                  </span>
                </div>

                {isLoadingTools ? (
                  <div className="p-4 text-center text-sm text-slate-500 bg-slate-50 rounded border border-slate-200">
                    Discovering installed scanner binaries...
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-2.5">
                    {tools.map((tool) => {
                      const isSelected = selectedToolNames.includes(tool.name);
                      return (
                        <div
                          key={tool.name}
                          onClick={() => tool.is_available && toggleTool(tool.name)}
                          className={`p-3 rounded-lg border flex items-center justify-between transition-all ${
                            !tool.is_available
                              ? 'bg-slate-50 border-slate-200 opacity-60 cursor-not-allowed'
                              : isSelected
                              ? 'bg-blue-50/50 border-blue-400 cursor-pointer shadow-xs'
                              : 'bg-white border-slate-200 hover:border-slate-300 cursor-pointer'
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <input
                              type="checkbox"
                              checked={isSelected}
                              disabled={!tool.is_available}
                              onChange={() => {}}
                              className="h-4 w-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500"
                            />
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-sm text-slate-900">
                                  {tool.display_name}
                                </span>
                                <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                                  tool.category === 'sast'
                                    ? 'bg-purple-100 text-purple-700'
                                    : tool.category === 'sca'
                                    ? 'bg-emerald-100 text-emerald-700'
                                    : 'bg-amber-100 text-amber-700'
                                }`}>
                                  {tool.category}
                                </span>
                              </div>
                              <p className="text-xs text-slate-500 font-mono mt-0.5">
                                {tool.is_available ? tool.version || 'Ready' : 'Binary not installed on host'}
                              </p>
                            </div>
                          </div>

                          <div>
                            {tool.is_available ? (
                              <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                                <span className="material-symbols-outlined text-xs">check_circle</span>
                                Available
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">
                                Not Installed
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="p-3.5 rounded-md bg-blue-50 border border-blue-100 flex items-start gap-2.5 text-xs text-blue-900">
                <span className="material-symbols-outlined text-blue-600 text-base shrink-0">verified_user</span>
                <div>
                  <strong>Enterprise Execution Isolation:</strong> Repositories are scanned statically without executing repository scripts or mounting application secrets. All credentials detected are automatically redacted.
                </div>
              </div>
            </>
          )}

          {/* Running State */}
          {isScanning && (
            <div className="py-8 flex flex-col items-center justify-center text-center space-y-4">
              <div className="w-12 h-12 border-3 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
              <div>
                <h4 className="font-semibold text-slate-900 text-base">Running Real Security Scanners...</h4>
                <p className="text-xs text-slate-500 mt-1 max-w-md">
                  Executing AST taint rules, dependency vulnerability checks, and secret probers against repository workspace.
                </p>
              </div>
              <div className="px-3 py-1 rounded bg-slate-100 text-xs font-mono text-slate-600">
                Running: {selectedToolNames.join(', ')}
              </div>
            </div>
          )}

          {/* Results View (After Scan) */}
          {scanResult && !isScanning && (
            <div className="space-y-4">
              {/* Scan Status Summary Card */}
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded-full ${
                      scanResult.status === 'completed'
                        ? 'bg-emerald-100 text-emerald-700 border border-emerald-300'
                        : scanResult.status === 'partial'
                        ? 'bg-amber-100 text-amber-700 border border-amber-300'
                        : 'bg-red-100 text-red-700 border border-red-300'
                    }`}>
                      {scanResult.status}
                    </span>
                    <span className="text-xs text-slate-500">Scan ID: {scanResult.id}</span>
                  </div>
                  <div className="mt-1.5 flex items-center gap-4 text-sm text-slate-700">
                    <span>
                      Total Findings: <strong className="text-slate-900">{scanResult.total_findings}</strong>
                    </span>
                    {scanResult.health_score_after !== undefined && (
                      <span>
                        Health Score: <strong className="text-blue-600">{scanResult.health_score_after}%</strong>
                      </span>
                    )}
                  </div>
                </div>

                <div className="text-right">
                  <span className="material-symbols-outlined text-3xl text-emerald-600">task_alt</span>
                </div>
              </div>

              {/* Scanners Breakdown Table */}
              <div>
                <h4 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2">
                  Scanner Execution Details
                </h4>
                <div className="border border-slate-200 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-100 text-slate-600 font-semibold border-b border-slate-200">
                      <tr>
                        <th className="px-3.5 py-2.5">Engine</th>
                        <th className="px-3.5 py-2.5">Category</th>
                        <th className="px-3.5 py-2.5">Duration</th>
                        <th className="px-3.5 py-2.5">Findings</th>
                        <th className="px-3.5 py-2.5">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 font-mono">
                      {scanResult.scanners.map((s, idx) => (
                        <tr key={idx} className="hover:bg-slate-50">
                          <td className="px-3.5 py-2.5 font-sans font-medium text-slate-900">
                            {s.scanner_name}
                            {s.version && (
                              <span className="block text-[11px] text-slate-400 font-mono">
                                {s.version}
                              </span>
                            )}
                          </td>
                          <td className="px-3.5 py-2.5 uppercase text-slate-600">{s.category}</td>
                          <td className="px-3.5 py-2.5 text-slate-600">{s.execution_time_seconds}s</td>
                          <td className="px-3.5 py-2.5 font-bold text-slate-900">
                            {s.findings_count}
                          </td>
                          <td className="px-3.5 py-2.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              s.status === 'success' || s.status === 'no_findings'
                                ? 'bg-emerald-50 text-emerald-700'
                                : 'bg-red-50 text-red-700'
                            }`}>
                              {s.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-end gap-3">
          {!isScanning && !scanResult && (
            <>
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-md border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleStartScan}
                disabled={selectedToolNames.length === 0}
                className="flex items-center gap-2 px-5 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors shadow-xs disabled:opacity-50"
              >
                <span className="material-symbols-outlined text-base">play_arrow</span>
                <span>Execute Security Scan</span>
              </button>
            </>
          )}

          {scanResult && !isScanning && (
            <button
              onClick={handleFinish}
              className="px-5 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors shadow-xs"
            >
              View Findings &amp; Posture
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
