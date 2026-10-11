import React, { useState } from 'react';

export interface DiffLine {
  line: number;
  text: string;
}

interface CodeDiffViewerProps {
  filePath: string;
  ruleId?: string;
  oldCode: DiffLine[];
  newCode: DiffLine[];
  className?: string;
}

export const CodeDiffViewer: React.FC<CodeDiffViewerProps> = ({
  filePath,
  ruleId,
  oldCode,
  newCode,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<'split' | 'unified'>('unified');

  const handleCopy = () => {
    const rawPatch = newCode.map(n => `+ ${n.text}`).join('\n');
    navigator.clipboard.writeText(rawPatch);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`border border-slate-200 rounded-lg overflow-hidden bg-white shadow-xs ${className}`}>
      {/* File Header Bar */}
      <div className="bg-slate-50 px-4 py-2 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="material-symbols-outlined text-slate-500 text-base">code</span>
          <span className="font-mono-md text-xs font-semibold text-slate-800 truncate" title={filePath}>
            {filePath}
          </span>
          {ruleId && (
            <span className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-mono-sm text-[10px]">
              {ruleId}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* View Mode Toggle */}
          <div className="inline-flex rounded border border-slate-200 bg-white p-0.5 text-xs font-mono-sm">
            <button
              type="button"
              onClick={() => setViewMode('unified')}
              className={`px-2 py-0.5 rounded transition-colors ${
                viewMode === 'unified' ? 'bg-slate-100 font-semibold text-slate-900' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Unified
            </button>
            <button
              type="button"
              onClick={() => setViewMode('split')}
              className={`px-2 py-0.5 rounded transition-colors ${
                viewMode === 'split' ? 'bg-slate-100 font-semibold text-slate-900' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Split
            </button>
          </div>

          {/* Copy Patch Button */}
          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center gap-1 px-2.5 py-1 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-mono-sm text-xs transition-colors"
            title="Copy patch contents"
          >
            <span className="material-symbols-outlined text-xs">
              {copied ? 'check' : 'content_copy'}
            </span>
            <span>{copied ? 'Copied' : 'Copy Patch'}</span>
          </button>
        </div>
      </div>

      {/* Diff Content View */}
      {viewMode === 'unified' ? (
        <div className="overflow-x-auto font-mono-sm text-xs bg-white divide-y divide-slate-100">
          {/* Deletions (Old Code) */}
          {oldCode.map((item, idx) => (
            <div key={`old-${idx}`} className="flex items-stretch bg-red-50/60 hover:bg-red-50 text-red-900">
              <span className="w-12 py-1 px-2 text-right select-none text-red-400 bg-red-100/50 border-r border-red-200 shrink-0">
                {item.line}
              </span>
              <span className="w-8 py-1 text-center select-none text-red-600 font-bold shrink-0">-</span>
              <span className="py-1 px-3 whitespace-pre overflow-x-auto flex-1 font-mono">{item.text}</span>
            </div>
          ))}

          {/* Insertions (New Code) */}
          {newCode.map((item, idx) => (
            <div key={`new-${idx}`} className="flex items-stretch bg-emerald-50/70 hover:bg-emerald-50 text-emerald-950">
              <span className="w-12 py-1 px-2 text-right select-none text-emerald-600 bg-emerald-100/60 border-r border-emerald-200 shrink-0">
                {item.line}
              </span>
              <span className="w-8 py-1 text-center select-none text-emerald-700 font-bold shrink-0">+</span>
              <span className="py-1 px-3 whitespace-pre overflow-x-auto flex-1 font-mono font-medium">{item.text}</span>
            </div>
          ))}
        </div>
      ) : (
        /* Split View */
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-200 font-mono-sm text-xs overflow-x-auto">
          {/* Left Column: Original */}
          <div className="bg-red-50/30">
            <div className="bg-slate-50 px-3 py-1 font-semibold text-slate-600 border-b border-slate-200 text-[11px]">
              Vulnerable Source
            </div>
            {oldCode.map((item, idx) => (
              <div key={`split-old-${idx}`} className="flex items-stretch bg-red-50/60 text-red-900 border-b border-red-100">
                <span className="w-10 py-1 px-1.5 text-right select-none text-red-400 border-r border-red-200 shrink-0">
                  {item.line}
                </span>
                <span className="w-6 py-1 text-center select-none text-red-500 shrink-0">-</span>
                <span className="py-1 px-2 whitespace-pre overflow-x-auto flex-1">{item.text}</span>
              </div>
            ))}
          </div>

          {/* Right Column: Proposed Patch */}
          <div className="bg-emerald-50/30">
            <div className="bg-slate-50 px-3 py-1 font-semibold text-slate-600 border-b border-slate-200 text-[11px]">
              Verified Security Patch
            </div>
            {newCode.map((item, idx) => (
              <div key={`split-new-${idx}`} className="flex items-stretch bg-emerald-50/70 text-emerald-950 border-b border-emerald-100">
                <span className="w-10 py-1 px-1.5 text-right select-none text-emerald-600 border-r border-emerald-200 shrink-0">
                  {item.line}
                </span>
                <span className="w-6 py-1 text-center select-none text-emerald-700 shrink-0">+</span>
                <span className="py-1 px-2 whitespace-pre overflow-x-auto flex-1 font-medium">{item.text}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
