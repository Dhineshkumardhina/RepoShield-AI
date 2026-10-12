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
  const [tableSearch, setTableSearch] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;

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

  const totalPages = Math.ceil(filteredTableItems.length / itemsPerPage) || 1;
  const paginatedItems = filteredTableItems.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Top Scope Strip */}
      <div className="px-4 lg:px-8 py-2.5 bg-slate-50 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-200">
        <div className="flex items-center flex-wrap gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-white text-slate-700 font-mono text-[11px] border border-slate-200 shadow-2xs font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
            US-East Production Cluster
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
            <span>main / default branch guardrails</span>
          </div>
        </div>

        {/* Right Controls: Period Selector */}
        <div className="flex items-center gap-2 self-end md:self-auto">
          <span className="text-[11px] font-mono text-slate-400 uppercase mr-1">Timeframe:</span>
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
        </div>
      </div>

      {/* Primary Workspace Action Ribbon */}
      <div className="px-4 lg:px-8 py-5 bg-white flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-500 uppercase font-semibold">
              Security Overview
            </span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-mono text-[10px] font-semibold border border-emerald-200 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
              All 4 Scanners Operational
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Automated AppSec &amp; Fix Verification Engine
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time vulnerability detection, compiler taint tracing, and regression verification across production repos.
          </p>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          <button
            onClick={onOpenExportModal}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 shadow-2xs transition-colors"
          >
            <span className="material-symbols-outlined text-sm text-slate-500">download</span>
            <span>Export Compliance (PDF / SARIF / JSON)</span>
          </button>

          <button
            onClick={onNavigateToQueue}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs border border-slate-200 shadow-2xs transition-colors"
          >
            <span className="material-symbols-outlined text-sm text-slate-500">fact_check</span>
            <span>Verification Queue</span>
            <span className="px-1.5 py-0.5 rounded-full bg-slate-900 text-white font-mono text-[10px] font-bold">
              8
            </span>
          </button>

          <button
            onClick={onOpenScanModal}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs shadow-2xs transition-colors"
          >
            <span className="material-symbols-outlined text-sm">bolt</span>
            <span>Trigger Full Scan</span>
          </button>
        </div>
      </div>

      {/* Main Operational Canvas */}
      <div className="px-4 lg:px-8 py-6 space-y-6">
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
            <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
              <span>Coverage: 42 active services</span>
              <span className="text-emerald-700 font-medium">94% compliant</span>
            </div>
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
                148 Total →
              </button>
            </div>
            <div className="grid grid-cols-2 gap-1.5 my-3">
              <button
                onClick={() => onNavigateToFindings()}
                className="px-2 py-1 rounded bg-rose-50 text-rose-700 border border-rose-200 flex items-center justify-between hover:bg-rose-100 transition-colors"
                title="Filter Critical Findings"
              >
                <span className="font-mono text-[10px] uppercase font-semibold">Critical</span>
                <span className="font-mono text-sm font-bold">14</span>
              </button>
              <button
                onClick={() => onNavigateToFindings()}
                className="px-2 py-1 rounded bg-amber-50 text-amber-800 border border-amber-200 flex items-center justify-between hover:bg-amber-100 transition-colors"
                title="Filter High Findings"
              >
                <span className="font-mono text-[10px] uppercase font-semibold">High</span>
                <span className="font-mono text-sm font-bold">32</span>
              </button>
              <button
                onClick={() => onNavigateToFindings()}
                className="px-2 py-1 rounded bg-slate-50 text-slate-700 border border-slate-200 flex items-center justify-between hover:bg-slate-100 transition-colors"
                title="Filter Medium Findings"
              >
                <span className="font-mono text-[10px] uppercase font-medium">Med</span>
                <span className="font-mono text-sm font-medium">68</span>
              </button>
              <button
                onClick={() => onNavigateToFindings()}
                className="px-2 py-1 rounded bg-slate-50 text-slate-500 border border-slate-200 flex items-center justify-between hover:bg-slate-100 transition-colors"
                title="Filter Low Findings"
              >
                <span className="font-mono text-[10px] uppercase font-medium">Low</span>
                <span className="font-mono text-sm font-medium">34</span>
              </button>
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
                58 Patches →
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
                <span className="font-medium">Inconclusive</span>
                <span className="font-semibold">7 (12.1%)</span>
              </div>
            </div>
            <span className="text-[10px] text-slate-400 font-mono block">
              Checked via static AST &amp; sandbox tests
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
            <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
              <span>348 PR gates analyzed</span>
              <span className="text-slate-700 font-mono font-medium">Pre-commit hook</span>
            </div>
          </div>
        </div>

        {/* Operational Security Engine Overview Row */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Active Scanner Engine Fleet Status (7 of 12 cols) */}
          <div className="lg:col-span-7 p-5 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-slate-700 text-base">security</span>
                  <h2 className="text-sm font-bold text-slate-900">
                    Security Scanner Integrations &amp; Telemetry
                  </h2>
                </div>
                <button
                  onClick={onOpenScanModal}
                  className="text-xs font-mono text-blue-600 hover:underline font-semibold flex items-center gap-1"
                >
                  <span>Run Scan</span>
                  <span className="material-symbols-outlined text-xs">arrow_forward</span>
                </button>
              </div>
              <p className="text-xs text-slate-500 mb-4">
                Active automated static analysis and vulnerability scanning engines running on commit triggers.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* Engine 1: Semgrep */}
                <div
                  onClick={() => onNavigateToFindings()}
                  className="p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-900">Semgrep OSS</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[10px] font-semibold">
                      ACTIVE
                    </span>
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-lg font-bold text-slate-800">62 Findings</span>
                    <span className="font-mono text-[11px] text-rose-600 font-bold">14 Critical</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">
                    AST pattern matching &amp; taint tracking across Python &amp; Go.
                  </p>
                </div>

                {/* Engine 2: Bandit */}
                <div
                  onClick={() => onNavigateToFindings()}
                  className="p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-900">Bandit AST</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[10px] font-semibold">
                      ACTIVE
                    </span>
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-lg font-bold text-slate-800">48 Findings</span>
                    <span className="font-mono text-[11px] text-amber-600 font-bold">22 High</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">
                    Python code security analysis for unsafe eval, yaml, and subroutines.
                  </p>
                </div>

                {/* Engine 3: pip-audit */}
                <div
                  onClick={() => onNavigateToFindings()}
                  className="p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-900">pip-audit (SCA)</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[10px] font-semibold">
                      ACTIVE
                    </span>
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-lg font-bold text-slate-800">24 CVEs</span>
                    <span className="font-mono text-[11px] text-slate-600 font-medium">8 Remediable</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">
                    Open-source software supply chain dependencies via PyPI OSV.
                  </p>
                </div>

                {/* Engine 4: Gitleaks */}
                <div
                  onClick={() => onNavigateToFindings()}
                  className="p-3 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-900">Gitleaks</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[10px] font-semibold">
                      ACTIVE
                    </span>
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className="text-lg font-bold text-slate-800">14 Secrets</span>
                    <span className="font-mono text-[11px] text-rose-600 font-bold">Zero Tolerance</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">
                    API tokens, RSA private keys, and credential leak detector.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
              <span className="flex items-center gap-1 font-mono text-[11px]">
                <span className="material-symbols-outlined text-xs text-emerald-600">verified</span>
                All engines isolated in Docker sandbox containers
              </span>
              <button
                onClick={onOpenExportModal}
                className="text-slate-700 hover:text-slate-900 font-mono text-xs font-semibold"
              >
                Export SARIF →
              </button>
            </div>
          </div>

          {/* Right: Top Incident Vectors & Repository Surface (5 of 12 cols) */}
          <div className="lg:col-span-5 p-5 rounded-xl bg-white shadow-2xs flex flex-col justify-between border border-slate-200">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-slate-700 text-base">pie_chart</span>
                  <h2 className="text-sm font-bold text-slate-900">
                    Top Incident Vectors (CVSS Ranked)
                  </h2>
                </div>
                <button
                  onClick={() => onNavigateToFindings()}
                  className="font-mono text-xs text-blue-600 hover:underline font-medium"
                >
                  View All Findings
                </button>
              </div>
              <p className="text-xs text-slate-500 mb-3">
                Click any vulnerability category to filter the findings registry.
              </p>

              {/* Top Attack Surface Categories (CWEs) */}
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

            <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
              <span className="flex items-center gap-1 font-mono text-[11px]">
                <span className="material-symbols-outlined text-xs text-slate-600">policy</span>
                Policy: Zero Tolerated Secrets
              </span>
              <button
                onClick={onNavigateToRepositories}
                className="text-blue-600 hover:underline font-medium font-mono text-xs"
              >
                Inspect Repositories →
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
                Continuous verification of candidate patches against AST taint rules and disposable regression runners.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className="relative">
                <input
                  value={tableSearch}
                  onChange={e => {
                    setTableSearch(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="pl-8 pr-3 py-1.5 bg-white rounded-md font-mono text-xs text-slate-800 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 border border-slate-200 shadow-2xs"
                  placeholder="Filter by repo, PR, or CWE..."
                  type="text"
                />
                <span className="material-symbols-outlined text-xs text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2">
                  filter_list
                </span>
              </div>
              {tableSearch && (
                <button
                  onClick={() => {
                    setTableSearch('');
                    setCurrentPage(1);
                  }}
                  className="px-2.5 py-1.5 rounded-md bg-white hover:bg-slate-50 font-mono text-xs text-slate-700 flex items-center gap-1 transition-colors border border-slate-200 shadow-2xs"
                >
                  <span className="material-symbols-outlined text-xs">tune</span>
                  <span>Clear Filter</span>
                </button>
              )}
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
                {paginatedItems.map(item => {
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
                                className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono text-xs font-semibold transition-colors border border-slate-200"
                              >
                                Diff View
                              </button>
                              <button
                                onClick={onOpenExportModal}
                                className="p-1 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900 transition-colors border border-slate-200"
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
                                className="p-1 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900 border border-slate-200"
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
                                className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono text-xs transition-colors border border-slate-200"
                              >
                                Rerun Test
                              </button>
                              <button
                                onClick={() => onOpenCrashModal(item)}
                                className="p-1 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900 border border-slate-200"
                                title="View Logs"
                              >
                                <span className="material-symbols-outlined text-sm">subject</span>
                              </button>
                            </>
                          )}

                          {item.status === 'clean' && (
                            <button
                              onClick={onOpenExportModal}
                              className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-xs transition-colors border border-slate-200"
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
              <span>Showing {paginatedItems.length} of {filteredTableItems.length} active runs</span>
              <span className="text-slate-300">•</span>
              <span className="text-emerald-600 font-semibold">Continuous AST verification active</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                className="px-2.5 py-1 rounded bg-white border border-slate-200 text-slate-700 shadow-2xs disabled:opacity-40 hover:bg-slate-50"
              >
                ← Prev
              </button>
              <span className="px-2 py-1">Page {currentPage} of {totalPages}</span>
              <button
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                className="px-2.5 py-1 rounded bg-white border border-slate-200 text-slate-700 shadow-2xs disabled:opacity-40 hover:bg-slate-50"
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
