import React, { useState } from 'react';
import { VerificationItem } from '../../types';
import { PrioritizedRemediationQueueCard } from './PrioritizedRemediationQueueCard';

interface DashboardScreenProps {
  verificationItems: VerificationItem[];
  onOpenDiffModal: (item: VerificationItem) => void;
  onOpenCrashModal: (item: VerificationItem) => void;
  onOpenScanModal: () => void;
  onOpenExportModal: () => void;
  onNavigateToQueue: () => void;
  onNavigateToFindings: (cwe?: string) => void;
  onNavigateToRepositories: () => void;
  onApproveAndMerge: (id: string, prNumber?: number) => void;
  mergedPrs: Set<number>;
}

export const DashboardScreen: React.FC<DashboardScreenProps> = ({
  verificationItems,
  onOpenDiffModal,
  onOpenCrashModal,
  onOpenScanModal,
  onOpenExportModal,
  onNavigateToQueue,
  onNavigateToFindings,
  onNavigateToRepositories,
  onApproveAndMerge,
  mergedPrs,
}) => {
  const [period, setPeriod] = useState<'24h' | '7d' | '30d' | '90d'>('7d');
  const [isZeroState, setIsZeroState] = useState(false);
  const [engineFilter, setEngineFilter] = useState<'all' | 'critical' | 'sast-dast'>('all');
  const [tableSearch, setTableSearch] = useState('');
  const [currentPage, setCurrentPage] = useState(1);

  // Filter items for the table
  const filteredTableItems = verificationItems.filter(item => {
    if (!tableSearch) return true;
    const q = tableSearch.toLowerCase();
    return (
      item.repo.toLowerCase().includes(q) ||
      (item.prNumber && item.prNumber.toString().includes(q)) ||
      item.engine.toLowerCase().includes(q) ||
      item.message.toLowerCase().includes(q)
    );
  });

  const isPr418Merged = mergedPrs.has(418);

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Top Scope Strip */}
      <div className="px-4 lg:px-8 py-2.5 bg-slate-50 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-200">
        <div className="flex items-center flex-wrap gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-white text-slate-700 font-mono text-[11px] border border-slate-200 shadow-2xs font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
            US-East Production
          </span>
          <span className="text-slate-300">•</span>
          <button
            onClick={onNavigateToRepositories}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white font-mono text-xs text-slate-700 font-medium hover:bg-slate-100 border border-slate-200 transition-colors"
          >
            <span className="material-symbols-outlined text-xs text-slate-500">lan</span>
            <span>42 Repositories Monitored</span>
          </button>
          <span className="text-slate-300">•</span>
          <div className="inline-flex items-center gap-1 font-mono text-xs text-slate-500">
            <span className="material-symbols-outlined text-xs">merge_type</span>
            <span>main / default branches</span>
          </div>
        </div>

        {/* Right Controls: Period Selector & Zero State Toggle */}
        <div className="flex items-center gap-2 self-end md:self-auto">
          <div className="inline-flex p-0.5 rounded-lg bg-slate-200/80 border border-slate-200" role="group">
            {(['24h', '7d', '30d', '90d'] as const).map(p => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-2.5 py-1 text-xs font-mono rounded-md transition-colors ${
                  period === p
                    ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
                type="button"
              >
                {p}
              </button>
            ))}
          </div>

          <button
            onClick={() => setIsZeroState(!isZeroState)}
            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors text-xs font-mono border ${
              isZeroState
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white hover:bg-slate-50 text-slate-600 border-slate-200 shadow-2xs'
            }`}
            title="Toggle zero-state preview"
            type="button"
          >
            <span className="material-symbols-outlined text-sm">visibility</span>
            <span>{isZeroState ? 'Live View' : 'Empty View'}</span>
          </button>
        </div>
      </div>

      {/* Primary Workspace Action Ribbon */}
      <div className="px-4 lg:px-8 py-5 bg-white flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-500 uppercase font-semibold">
              Security Overview
            </span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-mono text-[10px] font-semibold border border-emerald-200">
              Active Monitored
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Automated AppSec &amp; Fix Verification Engine
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time static taint analysis, compiler checks, and regression verification across all services.
          </p>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          <button
            onClick={onOpenExportModal}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 shadow-2xs transition-colors"
          >
            <span className="material-symbols-outlined text-sm text-slate-500">download</span>
            <span>Export Compliance (PDF / SARIF / JSON)</span>
          </button>

          <button
            onClick={onNavigateToQueue}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 shadow-2xs transition-colors"
          >
            <span className="material-symbols-outlined text-sm text-slate-500">fact_check</span>
            <span>Verification Queue</span>
            <span className="px-1.5 py-0.5 rounded-full bg-slate-900 text-white font-mono text-[10px] font-bold">
              8
            </span>
          </button>

          <button
            onClick={onOpenScanModal}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs shadow-2xs transition-colors"
          >
            <span className="material-symbols-outlined text-sm">bolt</span>
            <span>Trigger Full Scan</span>
          </button>
        </div>
      </div>

      {/* Main Operational Canvas */}
      <div className="px-4 lg:px-8 py-6 space-y-6">
        {/* Zero State View (Toggleable) */}
        {isZeroState ? (
          <div className="rounded-xl bg-white p-12 shadow-2xs text-center flex flex-col items-center justify-center border border-slate-200">
            <div className="w-14 h-14 rounded-full bg-slate-100 flex items-center justify-center text-slate-700 mb-4 border border-slate-200">
              <span className="material-symbols-outlined text-2xl">account_tree</span>
            </div>
            <h3 className="text-base font-bold text-slate-900">
              No Repositories Connected
            </h3>
            <p className="text-xs text-slate-500 max-w-md mt-1 mb-6 leading-relaxed">
              Connect your GitHub Enterprise or GitLab organization, or upload an authorized source archive to initialize continuous vulnerability scanning and automated AST fix verification.
            </p>
            <div className="flex items-center flex-wrap gap-2.5 justify-center">
              <button
                onClick={() => setIsZeroState(false)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 text-white text-xs font-medium shadow-2xs hover:bg-slate-800"
              >
                <span className="material-symbols-outlined text-sm">cloud_sync</span>
                Connect GitHub Enterprise
              </button>
              <button
                onClick={() => setIsZeroState(false)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-white border border-slate-200 text-slate-700 text-xs font-medium hover:bg-slate-50 shadow-2xs"
              >
                <span className="material-symbols-outlined text-sm">folder_zip</span>
                Upload Source Archive (.zip / .tar.gz)
              </button>
              <button
                onClick={() => setIsZeroState(false)}
                className="px-3 py-2 rounded-lg bg-slate-100 text-slate-600 font-mono text-xs hover:text-slate-900 hover:bg-slate-200"
              >
                Return to Live Data
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* KPI Metric Matrix Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
              {/* Card 1: Posture Score */}
              <div className="p-4 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                    Security Posture Score
                  </span>
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-mono text-xs font-bold border border-emerald-200">
                    GRADE B+
                  </span>
                </div>
                <div className="my-3 flex items-baseline gap-2">
                  <span className="text-3xl font-bold tracking-tight text-slate-900">
                    84.2
                  </span>
                  <span className="text-xs font-mono text-slate-400">/ 100</span>
                  <span className="ml-auto inline-flex items-center text-emerald-600 font-mono text-xs font-bold">
                    <span className="material-symbols-outlined text-xs">trending_up</span>
                    +3.4 pts
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 leading-normal">
                  Density, exploitability index, and MTTR across 42 active codebases.
                </p>
              </div>

              {/* Card 2: Open Vulnerabilities Split */}
              <div className="p-4 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                    Open Vulnerabilities
                  </span>
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="font-mono text-xs text-blue-600 hover:underline font-semibold"
                  >
                    148 Total
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-1.5 my-3">
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="px-2 py-1 rounded bg-rose-50 text-rose-700 border border-rose-200 flex items-center justify-between hover:bg-rose-100 transition-colors"
                  >
                    <span className="font-mono text-[10px] uppercase font-semibold">Critical</span>
                    <span className="font-mono text-sm font-bold">14</span>
                  </button>
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="px-2 py-1 rounded bg-amber-50 text-amber-800 border border-amber-200 flex items-center justify-between hover:bg-amber-100 transition-colors"
                  >
                    <span className="font-mono text-[10px] uppercase font-semibold">High</span>
                    <span className="font-mono text-sm font-bold">32</span>
                  </button>
                  <div className="px-2 py-1 rounded bg-slate-50 text-slate-700 border border-slate-200 flex items-center justify-between">
                    <span className="font-mono text-[10px] uppercase font-medium">Med</span>
                    <span className="font-mono text-sm font-medium">68</span>
                  </div>
                  <div className="px-2 py-1 rounded bg-slate-50 text-slate-500 border border-slate-200 flex items-center justify-between">
                    <span className="font-mono text-[10px] uppercase font-medium">Low</span>
                    <span className="font-mono text-sm font-medium">34</span>
                  </div>
                </div>
                <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden flex">
                  <div className="bg-rose-500 h-full" style={{ width: '9.4%' }} />
                  <div className="bg-amber-500 h-full" style={{ width: '21.6%' }} />
                  <div className="bg-blue-500 h-full" style={{ width: '45.9%' }} />
                  <div className="bg-slate-300 h-full" style={{ width: '23.1%' }} />
                </div>
              </div>

              {/* Card 3: Fix Verification Matrix */}
              <div className="p-4 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200 xl:col-span-1">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                    Fix Verification Suite
                  </span>
                  <button
                    onClick={onNavigateToQueue}
                    className="font-mono text-xs text-blue-600 font-bold hover:underline"
                  >
                    58 Patches
                  </button>
                </div>
                <div className="my-2 space-y-1">
                  <div className="flex items-center justify-between px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-xs">
                    <span className="flex items-center gap-1 font-medium">
                      <span className="material-symbols-outlined text-[13px]">verified</span>
                      Verified Safe
                    </span>
                    <span className="font-bold">34 (58.6%)</span>
                  </div>
                  <div className="flex items-center justify-between px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-mono text-xs">
                    <span className="flex items-center gap-1 font-medium">
                      <span className="material-symbols-outlined text-[13px]">cancel</span>
                      Regression/Fail
                    </span>
                    <span className="font-bold">9 (15.5%)</span>
                  </div>
                  <div className="flex items-center justify-between px-2 py-0.5 rounded bg-slate-50 text-slate-700 border border-slate-200 font-mono text-xs">
                    <span className="font-medium">Inconclusive / Timeout</span>
                    <span className="font-semibold">7 (12.1%)</span>
                  </div>
                </div>
                <span className="text-[10px] text-slate-500 font-mono block leading-tight">
                  Verified via static analysis differentials and targeted tests.
                </span>
              </div>

              {/* Card 4: MTTR */}
              <div className="p-4 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                    MTTR (High/Critical)
                  </span>
                  <span className="inline-flex items-center gap-0.5 text-emerald-600 font-mono text-xs font-bold">
                    <span className="material-symbols-outlined text-xs">arrow_downward</span>
                    -1.2d
                  </span>
                </div>
                <div className="my-3 flex items-baseline gap-2">
                  <span className="text-3xl font-bold tracking-tight text-slate-900">
                    3.8
                  </span>
                  <span className="text-xs font-mono text-slate-500">days</span>
                </div>
                <div className="p-1.5 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-500 font-medium">
                    SLA Benchmark
                  </span>
                  <span className="font-mono text-[11px] text-slate-700 font-semibold">
                    &lt; 5.0 days SLA
                  </span>
                </div>
              </div>

              {/* Card 5: Scan Coverage */}
              <div className="p-4 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                    Commit Coverage
                  </span>
                  <span className="material-symbols-outlined text-sm text-slate-500">security</span>
                </div>
                <div className="my-3 flex items-baseline gap-2">
                  <span className="text-3xl font-bold tracking-tight text-slate-900">
                    98.4%
                  </span>
                  <span className="font-mono text-xs text-emerald-600 font-semibold">Enforced</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-normal">
                  348 PR gates analyzed with active pre-commit taint analysis hooks.
                </p>
              </div>
            </div>

            {/* Middle Visualization & Architecture Section */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Visual (7 of 12 cols): Trends */}
              <div className="lg:col-span-7 p-5 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-slate-700 text-base">insights</span>
                      <h2 className="text-sm font-bold text-slate-900">
                        Vulnerability Ingestion vs. Verified Remediation Trends
                      </h2>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Velocity delta over past 30 days across all continuous deployment pipelines.
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="inline-flex items-center gap-1.5 text-slate-600">
                      <span className="w-2 h-2 rounded-full bg-rose-500" /> New Ingested
                    </span>
                    <span className="inline-flex items-center gap-1.5 text-slate-600">
                      <span className="w-2 h-2 rounded-full bg-emerald-500" /> Verified Fixes
                    </span>
                  </div>
                </div>

                {/* SVG Dual Trend Chart */}
                <div className="relative w-full h-64 bg-slate-900 rounded-lg p-3 flex flex-col justify-between overflow-hidden shadow-inner">
                  {/* Background Axis Grid Lines */}
                  <div className="absolute inset-x-3 top-4 bottom-8 flex flex-col justify-between pointer-events-none opacity-20">
                    <div className="w-full h-px bg-slate-500" />
                    <div className="w-full h-px bg-slate-500" />
                    <div className="w-full h-px bg-slate-500" />
                    <div className="w-full h-px bg-slate-500" />
                  </div>

                  {/* Trend Lines SVG */}
                  <svg className="w-full h-full" fill="none" preserveAspectRatio="none" viewBox="0 0 600 200">
                    {/* Shaded Remediation Area (Velocity Delta) */}
                    <path
                      className="fill-emerald-500/10"
                      d="M 0,160 Q 50,140 100,120 T 200,90 T 300,110 T 400,60 T 500,45 T 600,30 L 600,24 T 500,35 T 400,50 T 300,95 T 200,110 T 100,150 Q 50,170 0,185 Z"
                    />

                    {/* Ingested Findings (Rose curve) */}
                    <path
                      className="text-rose-400"
                      d="M 0,160 Q 50,140 100,120 T 200,90 T 300,110 T 400,60 T 500,45 T 600,30"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.5"
                    />

                    {/* Verified Fixes (Emerald curve) */}
                    <path
                      className="text-emerald-400"
                      d="M 0,185 Q 50,170 100,150 T 200,110 T 300,95 T 400,50 T 500,35 T 600,24"
                      fill="none"
                      stroke="currentColor"
                      strokeDasharray="0"
                      strokeWidth="2.5"
                    />

                    {/* Key Milestones Points */}
                    <circle className="fill-rose-400" cx="300" cy="110" r="4" />
                    <circle className="fill-emerald-400" cx="300" cy="95" r="4" />
                    <circle className="fill-rose-400" cx="600" cy="30" r="4" />
                    <circle className="fill-emerald-400" cx="600" cy="24" r="4" />
                  </svg>

                  {/* Chart Bottom Axis Metadata */}
                  <div className="flex items-center justify-between text-slate-400 font-mono text-[10px] px-1 pt-1 select-none">
                    <span>Day 1 (Sprint Start)</span>
                    <span>Day 8</span>
                    <span>Day 15 (Kernel Patch)</span>
                    <span>Day 22</span>
                    <span className="text-emerald-400 font-bold">Today (Triage Parity: 94%)</span>
                  </div>
                </div>

                <div className="mt-3 pt-2 flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
                      Filters:
                    </span>
                    <button
                      onClick={() => setEngineFilter('all')}
                      className={`px-2 py-0.5 rounded font-mono text-xs transition-colors border ${
                        engineFilter === 'all'
                          ? 'bg-slate-900 text-white border-slate-900 font-medium'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      All Severities
                    </button>
                    <button
                      onClick={() => setEngineFilter('critical')}
                      className={`px-2 py-0.5 rounded font-mono text-xs transition-colors border ${
                        engineFilter === 'critical'
                          ? 'bg-slate-900 text-white border-slate-900 font-medium'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      Critical Only
                    </button>
                    <button
                      onClick={() => setEngineFilter('sast-dast')}
                      className={`px-2 py-0.5 rounded font-mono text-xs transition-colors border ${
                        engineFilter === 'sast-dast'
                          ? 'bg-slate-900 text-white border-slate-900 font-medium'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      SAST vs DAST
                    </button>
                  </div>
                  <span className="font-mono text-xs text-emerald-600 flex items-center gap-1 font-medium">
                    <span className="material-symbols-outlined text-xs">speed</span>
                    Velocity: +18.4% remediation speed
                  </span>
                </div>
              </div>

              {/* Right Visual (5 of 12 cols): Attack Surface & Health */}
              <div className="lg:col-span-5 p-5 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-slate-700 text-base">pie_chart</span>
                      <h2 className="text-sm font-bold text-slate-900">
                        Repository Health Distribution
                      </h2>
                    </div>
                    <button
                      onClick={onNavigateToRepositories}
                      className="font-mono text-xs text-blue-600 hover:underline font-medium"
                    >
                      42 Active
                    </button>
                  </div>
                  <p className="text-xs text-slate-500 mb-3">
                    Attack surface partition based on worst-case finding severity.
                  </p>

                  {/* Repository Health Distribution Stack */}
                  <div className="space-y-2 mb-4">
                    <div>
                      <div className="flex justify-between font-mono text-xs mb-1">
                        <span className="flex items-center gap-1.5 text-slate-700">
                          <span className="w-2 h-2 rounded-full bg-emerald-500" />
                          Secure (0 Critical / High)
                        </span>
                        <span className="font-bold text-slate-900">26 repos (61.9%)</span>
                      </div>
                      <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                        <div className="bg-emerald-500 h-full" style={{ width: '61.9%' }} />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between font-mono text-xs mb-1">
                        <span className="flex items-center gap-1.5 text-slate-700">
                          <span className="w-2 h-2 rounded-full bg-amber-500" />
                          At Risk (1-3 High, 0 Critical)
                        </span>
                        <span className="font-bold text-slate-900">11 repos (26.2%)</span>
                      </div>
                      <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                        <div className="bg-amber-500 h-full" style={{ width: '26.2%' }} />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between font-mono text-xs mb-1">
                        <span className="flex items-center gap-1.5 text-rose-700">
                          <span className="w-2 h-2 rounded-full bg-rose-500" />
                          Vulnerable (≥1 Critical)
                        </span>
                        <span className="font-bold text-rose-700">5 repos (11.9%)</span>
                      </div>
                      <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                        <div className="bg-rose-500 h-full" style={{ width: '11.9%' }} />
                      </div>
                    </div>
                  </div>

                  {/* Top Attack Surface Categories (CWEs) */}
                  <div className="pt-2 border-t border-slate-100">
                    <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block mb-2">
                      Top Incident Vectors (CVSS Weighted)
                    </span>
                    <div className="space-y-1.5">
                      <button
                        onClick={() => onNavigateToFindings('CWE-79')}
                        className="w-full p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors flex items-center justify-between text-xs font-mono text-left"
                      >
                        <span className="text-slate-800 font-medium truncate">
                          CWE-79: Cross-Site Scripting (XSS)
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-700 font-bold shrink-0 ml-2">
                          14 findings
                        </span>
                      </button>

                      <button
                        onClick={() => onNavigateToFindings('CWE-798')}
                        className="w-full p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors flex items-center justify-between text-xs font-mono text-left"
                      >
                        <span className="text-slate-800 font-medium truncate">
                          CWE-798: Hardcoded Secrets &amp; Tokens
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-rose-50 border border-rose-200 text-rose-700 font-bold shrink-0 ml-2">
                          11 findings
                        </span>
                      </button>

                      <button
                        onClick={() => onNavigateToFindings('CWE-89')}
                        className="w-full p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors flex items-center justify-between text-xs font-mono text-left"
                      >
                        <span className="text-slate-800 font-medium truncate">
                          CWE-89: SQL Injection Flaws
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-700 font-bold shrink-0 ml-2">
                          6 findings
                        </span>
                      </button>

                      <button
                        onClick={() => onNavigateToFindings('CWE-22')}
                        className="w-full p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors flex items-center justify-between text-xs font-mono text-left"
                      >
                        <span className="text-slate-800 font-medium truncate">
                          CWE-22: Path Traversal
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-700 font-bold shrink-0 ml-2">
                          4 findings
                        </span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="mt-3 pt-2 flex items-center justify-between text-xs text-slate-500 border-t border-slate-100">
                  <span className="flex items-center gap-1 font-mono text-[11px]">
                    <span className="material-symbols-outlined text-xs text-slate-600">policy</span>
                    Policy: Zero Tolerated Secrets
                  </span>
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="text-blue-600 hover:underline font-medium font-mono text-xs"
                  >
                    Audit Attack Map →
                  </button>
                </div>
              </div>
            </div>

            {/* Evidence-Based Prioritized Remediation Queue */}
            <PrioritizedRemediationQueueCard
              onOpenDiffModal={onOpenDiffModal}
              onNavigateToFinding={onNavigateToFindings}
            />

            {/* Lower Section: Main Scan Activity & Fix Verification Pipeline */}
            <div className="rounded-xl bg-white shadow-2xs overflow-hidden flex flex-col border border-slate-200">
              <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50 border-b border-slate-200">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-slate-700 text-base">rule</span>
                    <h3 className="text-sm font-bold text-slate-900">
                      Recent Security Scan Activity &amp; Automated Fix Pipeline
                    </h3>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Continuous verification of AI-recommended remediation diffs against AST and sandbox runners.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <input
                      value={tableSearch}
                      onChange={e => setTableSearch(e.target.value)}
                      className="pl-8 pr-3 py-1.5 bg-white rounded-md font-mono text-xs text-slate-800 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 border border-slate-200 shadow-2xs"
                      placeholder="Filter by repo, PR, or CWE..."
                      type="text"
                    />
                    <span className="material-symbols-outlined text-xs text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2">
                      filter_list
                    </span>
                  </div>
                  <button
                    onClick={() => setTableSearch('')}
                    className="px-2.5 py-1.5 rounded-md bg-white hover:bg-slate-50 font-mono text-xs text-slate-700 flex items-center gap-1 transition-colors border border-slate-200 shadow-2xs"
                  >
                    <span className="material-symbols-outlined text-xs">tune</span>
                    <span>Clear Filter</span>
                  </button>
                </div>
              </div>

              {/* High Density Data Table */}
              <div className="overflow-x-auto w-full">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50/80 text-slate-500 font-mono text-[10px] uppercase tracking-wider border-b border-slate-200">
                      <th className="py-2.5 px-4 font-semibold">Repository / Branch</th>
                      <th className="py-2.5 px-4 font-semibold">Engine &amp; Target</th>
                      <th className="py-2.5 px-4 font-semibold">Findings</th>
                      <th className="py-2.5 px-4 font-semibold">Fix Recommendation &amp; Verification Status</th>
                      <th className="py-2.5 px-4 font-semibold text-right">Execution &amp; Timestamp</th>
                      <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredTableItems.slice(0, 4).map(item => {
                      const isPrMerged = item.prNumber ? mergedPrs.has(item.prNumber) : false;

                      return (
                        <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                          {/* Repo / Branch */}
                          <td className="py-3 px-4">
                            <div className="flex flex-col">
                              <div className="flex items-center gap-1.5">
                                <span className="material-symbols-outlined text-sm text-slate-500">terminal</span>
                                <span className="font-mono text-xs font-semibold text-slate-900">
                                  {item.repo}
                                </span>
                              </div>
                              <span className="font-mono text-[11px] text-slate-500 ml-5">
                                branch: {item.branch} (git:{item.gitHash})
                              </span>
                            </div>
                          </td>

                          {/* Engine & Target */}
                          <td className="py-3 px-4">
                            <div className="flex flex-col">
                              <span className="font-mono text-xs text-slate-800 font-medium">
                                {item.engine}
                              </span>
                              <span className="font-mono text-[10px] text-slate-400 uppercase">
                                {item.target}
                              </span>
                            </div>
                          </td>

                          {/* Findings */}
                          <td className="py-3 px-4">
                            {item.status === 'clean' ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[11px] font-semibold">
                                0 Found (Clean)
                              </span>
                            ) : item.findingsCount.critical ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-mono text-[11px] font-bold">
                                {item.findingsCount.critical} Critical, {item.findingsCount.high || 0} High
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono text-[11px] font-bold">
                                {item.findingsCount.high || 0} High, {item.findingsCount.med || 0} Med
                              </span>
                            )}
                          </td>

                          {/* Fix Status */}
                          <td className="py-3 px-4">
                            <div className="flex flex-col gap-1 max-w-md">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {item.status === 'verified' && (
                                  <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[11px] font-bold flex items-center gap-1">
                                    <span className="material-symbols-outlined text-[13px]">verified</span>
                                    {isPrMerged ? 'Merged into Target' : 'Verified Against Defined Checks'}
                                  </span>
                                )}
                                {item.status === 'failed' && (
                                  <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-mono text-[11px] font-bold flex items-center gap-1">
                                    <span className="material-symbols-outlined text-[13px]">dangerous</span>
                                    Failed Verification
                                  </span>
                                )}
                                {item.status === 'inconclusive' && (
                                  <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono text-[11px] font-semibold flex items-center gap-1">
                                    <span className="material-symbols-outlined text-[13px]">help_outline</span>
                                    Inconclusive
                                  </span>
                                )}
                                {item.status === 'clean' && (
                                  <span className="text-xs text-emerald-700 font-medium flex items-center gap-1">
                                    <span className="material-symbols-outlined text-xs">shield</span>
                                    Passed all compliance rule gates. No patch required.
                                  </span>
                                )}
                                {item.prNumber && (
                                  <span className="font-mono text-xs text-slate-800 font-medium">
                                    PR #{item.prNumber}
                                  </span>
                                )}
                              </div>
                              {item.status !== 'clean' && (
                                <span
                                  className={`text-xs ${
                                    item.status === 'failed' ? 'text-rose-600' : 'text-slate-500'
                                  }`}
                                >
                                  {isPrMerged
                                    ? `PR #${item.prNumber} successfully merged. Branch deployed.`
                                    : item.message}
                                </span>
                              )}
                            </div>
                          </td>

                          {/* Execution & Timestamp */}
                          <td className="py-3 px-4 text-right font-mono text-xs text-slate-600">
                            <div>{item.executionTime}</div>
                            <div className="text-slate-400 text-[10px]">{item.timestamp}</div>
                          </td>

                          {/* Actions */}
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {item.status === 'verified' && (
                                <>
                                  <button
                                    onClick={() => onOpenDiffModal(item)}
                                    className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono text-xs font-semibold transition-colors"
                                  >
                                    Diff View
                                  </button>
                                  <button
                                    onClick={onOpenExportModal}
                                    className="p-1 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900 transition-colors"
                                    title="Download SARIF"
                                  >
                                    <span className="material-symbols-outlined text-sm">download</span>
                                  </button>
                                </>
                              )}

                              {item.status === 'failed' && (
                                <>
                                  <button
                                    onClick={() => onOpenCrashModal(item)}
                                    className="px-2 py-1 rounded bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 font-mono text-xs font-semibold transition-colors"
                                  >
                                    Inspect Crash
                                  </button>
                                  <button
                                    onClick={() => onOpenCrashModal(item)}
                                    className="p-1 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900"
                                    title="Rerun Runner"
                                  >
                                    <span className="material-symbols-outlined text-sm">replay</span>
                                  </button>
                                </>
                              )}

                              {item.status === 'inconclusive' && (
                                <>
                                  <button
                                    onClick={() => onOpenCrashModal(item)}
                                    className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono text-xs transition-colors"
                                  >
                                    Rerun Test
                                  </button>
                                  <button
                                    onClick={() => onOpenCrashModal(item)}
                                    className="p-1 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900"
                                    title="View Logs"
                                  >
                                    <span className="material-symbols-outlined text-sm">subject</span>
                                  </button>
                                </>
                              )}

                              {item.status === 'clean' && (
                                <button
                                  onClick={onOpenExportModal}
                                  className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-xs transition-colors"
                                >
                                  SARIF
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Table Footer / Pagination */}
              <div className="p-3 bg-slate-50 flex flex-col sm:flex-row items-center justify-between font-mono text-xs text-slate-500 gap-2 border-t border-slate-200">
                <div className="flex items-center gap-2">
                  <span>Showing 4 of 42 repository runs</span>
                  <span className="text-slate-300">•</span>
                  <span className="text-emerald-600 font-semibold">All engines operational</span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    disabled={currentPage === 1}
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    className="px-2.5 py-1 rounded bg-white border border-slate-200 text-slate-700 shadow-2xs disabled:opacity-50 hover:bg-slate-50"
                  >
                    ← Prev
                  </button>
                  <span className="px-2 py-1">Page {currentPage} of 11</span>
                  <button
                    disabled={currentPage === 11}
                    onClick={() => setCurrentPage(p => Math.min(11, p + 1))}
                    className="px-2.5 py-1 rounded bg-white border border-slate-200 text-slate-700 shadow-2xs hover:bg-slate-50"
                  >
                    Next →
                  </button>
                </div>
              </div>
            </div>

            {/* AST Verified Remediation Diff Preview */}
            <div className="rounded-xl bg-white shadow-2xs p-5 border border-slate-200">
              <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-200">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-emerald-600 text-lg">verified_user</span>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900">
                      AST Verified Remediation Diff Preview
                    </h4>
                    <p className="text-xs text-slate-500 mt-0.5">
                      PR #418 Fix Verification: SQL Injection (CWE-89) in{' '}
                      <code className="font-mono text-xs bg-slate-100 text-slate-800 px-1 py-0.5 rounded border border-slate-200">
                        auth-gateway/src/dao/user_query.py
                      </code>
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-xs font-bold">
                    AST TAINT CHECK: PASS
                  </span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono text-xs">
                    24 UNIT TESTS: PASS
                  </span>
                </div>
              </div>

              {/* Diff Container */}
              <div className="rounded-lg overflow-hidden bg-slate-900 font-mono text-xs border border-slate-800 shadow-inner">
                <div className="bg-slate-800/90 px-3 py-1.5 text-slate-400 flex items-center justify-between border-b border-slate-700/80">
                  <span className="text-slate-300">auth-gateway/src/dao/user_query.py</span>
                  <span className="text-slate-500">git:7f3a9b8 → patch:29ca90</span>
                </div>
                {/* Deletion lines */}
                <div className="flex bg-rose-950/40 text-rose-300">
                  <div className="w-10 px-2 py-1 text-right text-slate-600 select-none bg-slate-900/50">
                    41
                  </div>
                  <div className="w-6 py-1 text-center font-bold select-none text-rose-400">-</div>
                  <div className="py-1 pr-3 font-mono overflow-x-auto whitespace-pre">
                    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{'{tenant_id}'}' AND email = '{'{email}'}'")
                  </div>
                </div>
                {/* Addition lines */}
                <div className="flex bg-emerald-950/40 text-emerald-300">
                  <div className="w-10 px-2 py-1 text-right text-slate-600 select-none bg-slate-900/50">
                    41
                  </div>
                  <div className="w-6 py-1 text-center font-bold select-none text-emerald-400">+</div>
                  <div className="py-1 pr-3 font-mono overflow-x-auto whitespace-pre">
                    query = "SELECT * FROM users WHERE tenant_id = %s AND email = %s"
                  </div>
                </div>
                <div className="flex bg-emerald-950/40 text-emerald-300">
                  <div className="w-10 px-2 py-1 text-right text-slate-600 select-none bg-slate-900/50">
                    42
                  </div>
                  <div className="w-6 py-1 text-center font-bold select-none text-emerald-400">+</div>
                  <div className="py-1 pr-3 font-mono overflow-x-auto whitespace-pre">
                    cursor.execute(query, (tenant_id, email))  # AST-verified parameterized tuple
                  </div>
                </div>
              </div>

              <div className="mt-3 pt-2 flex items-center justify-between text-xs flex-wrap gap-2">
                <span className="text-slate-500 flex items-center gap-1 font-mono text-[11px]">
                  <span className="material-symbols-outlined text-xs text-slate-600">terminal</span>
                  Semgrep Rule: <code className="text-slate-800 font-semibold">python.sqlalchemy.security.audit.raw-sql-format</code> resolved.
                </span>
                <button
                  disabled={isPr418Merged}
                  onClick={() => onApproveAndMerge('run-01', 418)}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all shadow-2xs ${
                    isPr418Merged
                      ? 'bg-emerald-600 text-white cursor-default font-semibold'
                      : 'bg-slate-900 text-white hover:bg-slate-800'
                  }`}
                >
                  {isPr418Merged ? '✓ PR #418 Merged & Closed' : 'Approve & Merge PR #418'}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
