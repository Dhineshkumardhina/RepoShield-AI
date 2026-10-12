import React, { useState } from 'react';
import { api, PatchValidationResponse, ApiVerificationRun } from '../../services/api';

interface NewVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (run: ApiVerificationRun) => void;
}

const PRESET_PATCHES = {
  VALID_FIX: {
    label: 'Preset 1: Valid Parameterized Query Fix',
    expectedVerdict: 'VERIFIED_AGAINST_DEFINED_CHECKS',
    findingId: 'FIND-418',
    diff: `--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -10,7 +10,7 @@
     # Secure implementation using parameterized query binding
-    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{tenant_id}'"
-    cursor.execute(query)
+    query = "SELECT id, username, email FROM users WHERE tenant_id = %s"
+    cursor.execute(query, (tenant_id,))
     return cursor.fetchall()`,
  },
  INEFFECTIVE_FIX: {
    label: 'Preset 2: Ineffective Sanitization (Persisting)',
    expectedVerdict: 'FAILED_VERIFICATION',
    findingId: 'FIND-418',
    diff: `--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -10,7 +10,7 @@
     # Flawed attempt: weak string sanitization still using raw query formatting
     sanitized = tenant_id.replace("'", "")
-    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{tenant_id}'"
+    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{sanitized}'"
     cursor.execute(query)
     return cursor.fetchall()`,
  },
  REGRESSION_FIX: {
    label: 'Preset 3: Fix Introduces Regression (New Finding)',
    expectedVerdict: 'FAILED_VERIFICATION',
    findingId: 'FIND-418',
    diff: `--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -10,7 +10,8 @@
+    import os
+    os.system(f"echo Querying user {tenant_id}")
     query = "SELECT id, username, email FROM users WHERE tenant_id = %s"
     cursor.execute(query, (tenant_id,))
     return cursor.fetchall()`,
  },
  PATH_TRAVERSAL: {
    label: 'Preset 4: Malicious Path Traversal Attempt',
    expectedVerdict: 'REJECTED (INCONCLUSIVE)',
    findingId: 'FIND-418',
    diff: `--- a/../../../../etc/shadow
+++ b/../../../../etc/shadow
@@ -1,1 +1,1 @@
-root:*
+root:pwned`,
  },
};

export const NewVerificationModal: React.FC<NewVerificationModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [findingId, setFindingId] = useState('FIND-418');
  const [patchDiff, setPatchDiff] = useState(PRESET_PATCHES.VALID_FIX.diff);
  const [runScanners, setRunScanners] = useState(true);
  const [runExistingTests, setRunExistingTests] = useState(true);
  const [runRegressionTests, setRunRegressionTests] = useState(true);

  const [validationResult, setValidationResult] = useState<PatchValidationResponse | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const [isExecuting, setIsExecuting] = useState(false);
  const [executionError, setExecutionError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleApplyPreset = (key: keyof typeof PRESET_PATCHES) => {
    const preset = PRESET_PATCHES[key];
    setFindingId(preset.findingId);
    setPatchDiff(preset.diff);
    setValidationResult(null);
    setValidationError(null);
  };

  const handleValidatePatch = async () => {
    setIsValidating(true);
    setValidationError(null);
    try {
      const res = await api.validatePatch(patchDiff);
      setValidationResult(res);
    } catch (err: any) {
      setValidationError(err.message || 'Patch validation failed.');
      setValidationResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  const handleExecute = async () => {
    setIsExecuting(true);
    setExecutionError(null);
    try {
      const res = await api.triggerVerification({
        finding_id: findingId,
        proposed_patch: patchDiff,
        run_existing_tests: runExistingTests,
        run_regression_tests: runRegressionTests,
      });
      onSuccess(res);
      onClose();
    } catch (err: any) {
      setExecutionError(err.message || 'Fix Verification execution failed.');
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto font-sans">
      <div className="relative w-full max-w-3xl bg-white rounded-xl shadow-2xl border border-slate-200 my-8 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-2xs">
              <span className="material-symbols-outlined text-xl">play_arrow</span>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Trigger Fix Verification Engine
              </h3>
              <p className="font-mono text-xs text-slate-500 mt-0.5">
                Evaluate proposed patch in isolated, restricted workspace against defined security gates
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

        {/* Form Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {/* Controlled Preset Quick Select */}
          <div className="space-y-2">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold block">
              Load Controlled Sample Preset
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {(Object.keys(PRESET_PATCHES) as Array<keyof typeof PRESET_PATCHES>).map(key => {
                const preset = PRESET_PATCHES[key];
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleApplyPreset(key)}
                    className="p-2.5 rounded-lg border border-slate-200 text-left hover:border-slate-400 hover:bg-slate-50 transition-colors text-xs"
                  >
                    <div className="font-semibold text-slate-800">{preset.label}</div>
                    <div className="font-mono text-[10px] text-slate-500 mt-0.5">
                      Expected: <span className="font-bold text-slate-900">{preset.expectedVerdict}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Finding ID */}
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase font-bold block mb-1">
              Target Finding Identifier
            </label>
            <input
              type="text"
              value={findingId}
              onChange={e => setFindingId(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-200 rounded-md focus:border-slate-400 focus:outline-hidden"
              placeholder="e.g. FIND-418"
            />
          </div>

          {/* Proposed Patch Diff Textarea */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[10px] font-mono text-slate-500 uppercase font-bold">
                Proposed Patch (Unified Diff)
              </label>
              <button
                type="button"
                onClick={handleValidatePatch}
                disabled={isValidating || !patchDiff.trim()}
                className="px-2.5 py-1 text-xs font-semibold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center gap-1 transition-colors border border-slate-200"
              >
                <span className="material-symbols-outlined text-xs">rule</span>
                {isValidating ? 'Validating...' : 'Validate Patch Safely'}
              </button>
            </div>
            <textarea
              rows={8}
              value={patchDiff}
              onChange={e => {
                setPatchDiff(e.target.value);
                setValidationResult(null);
              }}
              className="w-full px-3 py-2 font-mono text-xs bg-slate-900 text-emerald-400 border border-slate-700 rounded-md focus:border-slate-400 focus:outline-hidden shadow-inner"
              placeholder="--- a/path/to/file.py&#10;+++ b/path/to/file.py&#10;@@ -1,3 +1,3 @@"
            />
          </div>

          {/* Patch Validation Results */}
          {validationResult && (
            <div className={`p-4 rounded-xl border text-xs ${
              validationResult.is_valid
                ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                : 'bg-rose-50 border-rose-200 text-rose-900'
            }`}>
              <div className="flex items-center justify-between font-bold mb-1">
                <span className="flex items-center gap-1">
                  <span className="material-symbols-outlined text-sm">
                    {validationResult.is_valid ? 'check_circle' : 'block'}
                  </span>
                  {validationResult.is_valid ? 'Patch Parsing & Path Validation Passed' : 'Patch Rejected'}
                </span>
                <span className="font-mono text-[11px]">
                  +{validationResult.total_added} / -{validationResult.total_deleted} lines
                </span>
              </div>
              {validationResult.errors.length > 0 && (
                <div className="mt-1 text-rose-800 text-[11px] space-y-0.5">
                  {validationResult.errors.map((err, i) => (
                    <div key={i}>• {err}</div>
                  ))}
                </div>
              )}
              {validationResult.files.length > 0 && (
                <div className="mt-2 pt-2 border-t border-emerald-200/60 font-mono text-[11px] text-emerald-800 space-y-1">
                  {validationResult.files.map((f, i) => (
                    <div key={i}>
                      Touched: <span className="font-bold">{f.new_path}</span> ({f.modified_lines_range})
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {validationError && (
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-xs">
              {validationError}
            </div>
          )}

          {/* Verification Checks Options */}
          <div className="space-y-2 pt-2 border-t border-slate-200">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold block">
              Defined Verification Gates to Execute
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
              <label className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100 transition-colors">
                <input
                  type="checkbox"
                  checked={runScanners}
                  onChange={e => setRunScanners(e.target.checked)}
                  className="rounded text-slate-900"
                />
                <span className="font-medium text-slate-800">Re-run Scanners (Semgrep)</span>
              </label>

              <label className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100 transition-colors">
                <input
                  type="checkbox"
                  checked={runExistingTests}
                  onChange={e => setRunExistingTests(e.target.checked)}
                  className="rounded text-slate-900"
                />
                <span className="font-medium text-slate-800">Existing Unit Tests</span>
              </label>

              <label className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100 transition-colors">
                <input
                  type="checkbox"
                  checked={runRegressionTests}
                  onChange={e => setRunRegressionTests(e.target.checked)}
                  className="rounded text-slate-900"
                />
                <span className="font-medium text-slate-800">Targeted Security Tests</span>
              </label>
            </div>
          </div>

          {executionError && (
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-xs">
              {executionError}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-50 border-t border-slate-200 flex items-center justify-between">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleExecute}
            disabled={isExecuting || !patchDiff.trim()}
            className={`px-5 py-2 rounded-md text-xs font-bold text-white shadow-2xs transition-all flex items-center gap-2 ${
              isExecuting || !patchDiff.trim()
                ? 'bg-slate-400 cursor-not-allowed'
                : 'bg-slate-900 hover:bg-slate-800'
            }`}
          >
            <span className="material-symbols-outlined text-sm">
              {isExecuting ? 'sync' : 'verified_user'}
            </span>
            {isExecuting ? 'Executing In Sandbox...' : 'Run Fix Verification'}
          </button>
        </div>
      </div>
    </div>
  );
};
