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
  mergedPrs
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
    <div className="flex flex-col w-full">
      {/* Top Command & Environment Meta Strip */}
      <div className="px-4 lg:px-gutter-desktop py-space-sm bg-surface-container-low flex flex-col md:flex-row md:items-center justify-between gap-space-sm border-b border-outline-variant/60">
        <div className="flex items-center flex-wrap gap-space-sm">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-surface-container-lowest text-primary font-mono-sm text-mono-sm font-semibold shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span>
            SANDBOX-US-EAST-1
          </span>
          <span className="font-body-sm text-body-sm text-on-surface-variant">Scope:</span>
          <button
            onClick={onNavigateToRepositories}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container font-mono-md text-mono-md text-on-surface font-medium hover:bg-surface-container-high transition-colors"
          >
            <span className="material-symbols-outlined text-xs text-primary">lan</span>
            <span>42 Production Repositories</span>
          </button>
          <span className="text-outline-variant">•</span>
          <div className="inline-flex items-center gap-1 font-mono-sm text-mono-sm text-on-surface-variant">
            <span className="material-symbols-outlined text-xs">merge_type</span>
            <span>main / production</span>
          </div>
          <span className="text-outline-variant">•</span>
          <span className="font-label-caps text-label-caps text-on-surface-variant px-1.5 py-0.5 rounded bg-surface-container uppercase">
            GITHUB ENTERPRISE &amp; GITLAB SYNCED
          </span>
        </div>

        {/* Right Controls: Period Selector & Zero State Toggle */}
        <div className="flex items-center gap-space-sm self-end md:self-auto">
          <div className="inline-flex p-0.5 rounded bg-surface-container-high" role="group">
            {(['24h', '7d', '30d', '90d'] as const).map(p => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-2.5 py-1 text-mono-sm font-mono-sm rounded transition-colors ${
                  period === p
                    ? 'bg-surface-container-lowest text-primary font-semibold shadow-xs'
                    : 'text-on-surface-variant hover:text-on-surface'
                }`}
                type="button"
              >
                {p}
              </button>
            ))}
          </div>

          <button
            onClick={() => setIsZeroState(!isZeroState)}
            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded transition-colors shadow-xs text-body-sm font-body-sm ${
              isZeroState
                ? 'bg-primary text-on-primary'
                : 'bg-surface-container-lowest hover:bg-surface-container text-on-surface-variant'
            }`}
            title="Preview zero-state experience for onboarding"
            type="button"
          >
            <span className="material-symbols-outlined text-sm">visibility</span>
            <span>Zero State</span>
          </button>
        </div>
      </div>

      {/* Primary Workspace Action Ribbon */}
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest flex flex-col lg:flex-row lg:items-center justify-between gap-space-md border-b border-outline-variant/60">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-label-caps text-primary uppercase font-bold tracking-wider">
              SEC-OPS WORKSPACE CONTROL CENTER
            </span>
            <span className="px-1.5 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-mono-sm font-bold">
              LIVE TELEMETRY
            </span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Automated AppSec &amp; Fix Verification Engine
          </h1>
        </div>

        <div className="flex items-center flex-wrap gap-space-sm">
          <button
            onClick={onOpenExportModal}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-surface-container-low hover:bg-surface-container text-on-surface font-body-sm text-body-sm transition-colors shadow-xs"
          >
            <span className="material-symbols-outlined text-base text-primary">download</span>
            <span>Export Compliance (PDF / SARIF / JSON)</span>
          </button>

          <button
            onClick={onNavigateToQueue}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-variant text-on-surface font-body-sm text-body-sm transition-colors shadow-xs"
          >
            <span className="material-symbols-outlined text-base text-tertiary">fact_check</span>
            <span>Verification Queue</span>
            <span className="px-1.5 py-0.5 rounded-full bg-primary text-on-primary font-mono-sm text-mono-sm font-bold">
              8
            </span>
          </button>

          <button
            onClick={onOpenScanModal}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-primary text-on-primary hover:bg-on-primary-fixed-variant font-body-sm text-body-sm font-medium transition-colors shadow-xs"
          >
            <span className="material-symbols-outlined text-base">bolt</span>
            <span>Trigger Full Scan</span>
          </button>
        </div>
      </div>

      {/* Main Operational Canvas */}
      <div className="px-4 lg:px-gutter-desktop py-space-lg space-y-space-lg">
        {/* Zero State View (Toggleable) */}
        {isZeroState ? (
          <div className="rounded bg-surface-container-lowest p-space-3xl shadow-xs text-center flex flex-col items-center justify-center border border-outline-variant">
            <div className="w-16 h-16 rounded-full bg-surface-container-high flex items-center justify-center text-primary mb-space-md">
              <span className="material-symbols-outlined text-3xl">account_tree</span>
            </div>
            <h3 className="font-headline-md text-headline-md text-on-surface font-bold">
              No Repositories Connected
            </h3>
            <p className="font-body-md text-body-md text-on-surface-variant max-w-lg mt-space-xs mb-space-lg">
              Connect your GitHub Enterprise or GitLab organization, or upload an authorized source archive to initialize continuous vulnerability scanning and automated AST fix verification.
            </p>
            <div className="flex items-center flex-wrap gap-space-md justify-center">
              <button
                onClick={() => setIsZeroState(false)}
                className="inline-flex items-center gap-2 px-4 py-2 rounded bg-primary text-on-primary font-body-sm text-body-sm font-medium shadow-xs hover:bg-on-primary-fixed-variant"
              >
                <span className="material-symbols-outlined text-base">cloud_sync</span>
                Connect GitHub Enterprise
              </button>
              <button
                onClick={() => setIsZeroState(false)}
                className="inline-flex items-center gap-2 px-4 py-2 rounded bg-surface-container-high text-on-surface font-body-sm text-body-sm font-medium hover:bg-surface-container"
              >
                <span className="material-symbols-outlined text-base">folder_zip</span>
                Upload Source Archive (.zip / .tar.gz)
              </button>
              <button
                onClick={() => setIsZeroState(false)}
                className="px-3 py-2 rounded bg-surface-container text-on-surface-variant font-mono-sm text-mono-sm hover:text-on-surface"
              >
                Return to Live Data
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* KPI Metric Matrix Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-space-md">
              {/* Card 1: Posture Score */}
              <div className="p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60">
                <div className="flex items-center justify-between">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase font-semibold">
                    Security Posture Score
                  </span>
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-mono-sm font-bold">
                    GRADE B+
                  </span>
                </div>
                <div className="my-space-sm flex items-baseline gap-2">
                  <span className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">
                    84.2
                  </span>
                  <span className="font-mono-md text-mono-md text-on-surface-variant">/ 100</span>
                  <span className="ml-auto inline-flex items-center text-tertiary font-mono-sm text-mono-sm font-bold">
                    <span className="material-symbols-outlined text-sm">trending_up</span>
                    +3.4 pts
                  </span>
                </div>
                <p className="font-body-sm text-body-sm text-on-surface-variant leading-tight">
                  Density, exploitability index, and MTTR across 42 active codebases.
                </p>
              </div>

              {/* Card 2: Open Vulnerabilities Split */}
              <div className="p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60">
                <div className="flex items-center justify-between">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase font-semibold">
                    Open Vulnerabilities
                  </span>
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="font-mono-sm text-mono-sm text-primary hover:underline font-semibold"
                  >
                    148 Total
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-1.5 my-space-sm">
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="px-2 py-1 rounded bg-error-container text-on-error-container flex items-center justify-between hover:opacity-90 transition-opacity"
                  >
                    <span className="font-mono-sm text-mono-sm uppercase font-semibold">Critical</span>
                    <span className="font-mono-lg text-mono-lg font-bold">14</span>
                  </button>
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="px-2 py-1 rounded bg-surface-container-high text-on-surface flex items-center justify-between hover:bg-surface-container-highest transition-colors"
                  >
                    <span className="font-mono-sm text-mono-sm uppercase font-semibold">High</span>
                    <span className="font-mono-lg text-mono-lg font-bold">32</span>
                  </button>
                  <div className="px-2 py-1 rounded bg-surface-container text-on-surface-variant flex items-center justify-between">
                    <span className="font-mono-sm text-mono-sm uppercase">Med</span>
                    <span className="font-mono-lg text-mono-lg font-medium">68</span>
                  </div>
                  <div className="px-2 py-1 rounded bg-surface-container-low text-on-surface-variant flex items-center justify-between">
                    <span className="font-mono-sm text-mono-sm uppercase">Low</span>
                    <span className="font-mono-lg text-mono-lg font-medium">34</span>
                  </div>
                </div>
                <div className="w-full bg-surface-container-high h-1.5 rounded overflow-hidden flex">
                  <div className="bg-error h-full" style={{ width: '9.4%' }}></div>
                  <div className="bg-primary h-full" style={{ width: '21.6%' }}></div>
                  <div className="bg-secondary h-full" style={{ width: '45.9%' }}></div>
                  <div className="bg-outline-variant h-full" style={{ width: '23.1%' }}></div>
                </div>
              </div>

              {/* Card 3: Fix Verification Matrix */}
              <div className="p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60 xl:col-span-1">
                <div className="flex items-center justify-between">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase font-semibold">
                    Fix Verification Suite
                  </span>
                  <button
                    onClick={onNavigateToQueue}
                    className="font-mono-sm text-mono-sm text-primary font-bold hover:underline"
                  >
                    58 Patches
                  </button>
                </div>
                <div className="my-space-xs space-y-1">
                  <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant">
                    <span className="font-mono-sm text-mono-sm flex items-center gap-1">
                      <span className="material-symbols-outlined text-xs">verified</span>
                      Verified Safe
                    </span>
                    <span className="font-mono-sm text-mono-sm font-bold">34 (58.6%)</span>
                  </div>
                  <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-error-container text-on-error-container">
                    <span className="font-mono-sm text-mono-sm flex items-center gap-1">
                      <span className="material-symbols-outlined text-xs">cancel</span>
                      Regression/Fail
                    </span>
                    <span className="font-mono-sm text-mono-sm font-bold">9 (15.5%)</span>
                  </div>
                  <div className="flex items-center justify-between px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant">
                    <span className="font-mono-sm text-mono-sm">Inconclusive / Timeout</span>
                    <span className="font-mono-sm text-mono-sm font-semibold">7 (12.1%)</span>
                  </div>
                </div>
                <span className="font-label-caps text-label-caps text-outline text-[9px] block leading-tight">
                  Validated via AST taint &amp; test runners. Zero raw LLM hallucinations.
                </span>
              </div>

              {/* Card 4: MTTR */}
              <div className="p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60">
                <div className="flex items-center justify-between">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase font-semibold">
                    MTTR (High/Critical)
                  </span>
                  <span className="inline-flex items-center gap-0.5 text-tertiary font-mono-sm text-mono-sm font-bold">
                    <span className="material-symbols-outlined text-xs">arrow_downward</span>
                    -1.2d
                  </span>
                </div>
                <div className="my-space-sm flex items-baseline gap-2">
                  <span className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">
                    3.8
                  </span>
                  <span className="font-mono-md text-mono-md text-on-surface-variant">days</span>
                </div>
                <div className="p-1.5 rounded bg-surface-container-low flex items-center justify-between">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase">
                    SLA Benchmark
                  </span>
                  <span className="font-mono-sm text-mono-sm text-primary font-semibold">
                    &lt; 5.0 days SLA
                  </span>
                </div>
              </div>

              {/* Card 5: Scan Coverage */}
              <div className="p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60">
                <div className="flex items-center justify-between">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase font-semibold">
                    Commit Coverage
                  </span>
                  <span className="material-symbols-outlined text-sm text-primary">security</span>
                </div>
                <div className="my-space-sm flex items-baseline gap-2">
                  <span className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">
                    98.4%
                  </span>
                  <span className="font-mono-sm text-mono-sm text-tertiary font-semibold">Enforced</span>
                </div>
                <p className="font-body-sm text-body-sm text-on-surface-variant leading-tight">
                  348 PR gates analyzed with active pre-commit taint analysis hooks.
                </p>
              </div>
            </div>

            {/* Middle Visualization & Architecture Section */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-space-lg">
              {/* Left Visual (7 of 12 cols): Trends */}
              <div className="lg:col-span-7 p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm pb-space-sm">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-primary text-base">insights</span>
                      <h2 className="font-headline-sm text-headline-sm text-on-surface">
                        Vulnerability Ingestion vs. Verified Remediation Trends
                      </h2>
                    </div>
                    <p className="font-body-sm text-body-sm text-on-surface-variant">
                      Velocity delta over past 30 days across all continuous deployment pipelines.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center gap-1 text-on-surface-variant font-mono-sm text-mono-sm">
                      <span className="w-2.5 h-2.5 rounded-full bg-error"></span> New Ingested
                    </span>
                    <span className="inline-flex items-center gap-1 text-on-surface-variant font-mono-sm text-mono-sm">
                      <span className="w-2.5 h-2.5 rounded-full bg-tertiary"></span> Verified Fixes
                    </span>
                  </div>
                </div>

                {/* SVG Dual Trend Chart */}
                <div className="relative w-full h-64 bg-surface-container-low rounded p-2 flex flex-col justify-between overflow-hidden">
                  {/* Background Axis Grid Lines */}
                  <div className="absolute inset-x-2 top-4 bottom-8 flex flex-col justify-between pointer-events-none opacity-40">
                    <div className="w-full h-px bg-outline-variant"></div>
                    <div className="w-full h-px bg-outline-variant"></div>
                    <div className="w-full h-px bg-outline-variant"></div>
                    <div className="w-full h-px bg-outline-variant"></div>
                  </div>

                  {/* Trend Lines SVG */}
                  <svg className="w-full h-full" fill="none" preserveAspectRatio="none" viewBox="0 0 600 200">
                    {/* Shaded Remediation Area (Velocity Delta) */}
                    <path
                      className="fill-tertiary opacity-10"
                      d="M 0,160 Q 50,140 100,120 T 200,90 T 300,110 T 400,60 T 500,45 T 600,30 L 600,24 T 500,35 T 400,50 T 300,95 T 200,110 T 100,150 Q 50,170 0,185 Z"
                    />

                    {/* Ingested Findings (Reddish curve) */}
                    <path
                      className="text-error"
                      d="M 0,160 Q 50,140 100,120 T 200,90 T 300,110 T 400,60 T 500,45 T 600,30"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.5"
                    />

                    {/* Verified Fixes (Teal curve closing the gap) */}
                    <path
                      className="text-tertiary"
                      d="M 0,185 Q 50,170 100,150 T 200,110 T 300,95 T 400,50 T 500,35 T 600,24"
                      fill="none"
                      stroke="currentColor"
                      strokeDasharray="0"
                      strokeWidth="2.5"
                    />

                    {/* Key Milestones Points */}
                    <circle className="fill-error" cx="300" cy="110" r="4" />
                    <circle className="fill-tertiary" cx="300" cy="95" r="4" />
                    <circle className="fill-error" cx="600" cy="30" r="4" />
                    <circle className="fill-tertiary" cx="600" cy="24" r="4" />
                  </svg>

                  {/* Chart Bottom Axis Metadata */}
                  <div className="flex items-center justify-between text-on-surface-variant font-mono-sm text-mono-sm px-1 pt-1 select-none">
                    <span>Day 1 (Sprint Start)</span>
                    <span>Day 8</span>
                    <span>Day 15 (Kernel Patch)</span>
                    <span>Day 22</span>
                    <span className="text-tertiary font-bold">Today (Triage Parity: 94%)</span>
                  </div>
                </div>

                <div className="mt-space-sm pt-space-xs flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-label-caps text-label-caps text-on-surface-variant uppercase">
                      Engine Filters:
                    </span>
                    <button
                      onClick={() => setEngineFilter('all')}
                      className={`px-2 py-0.5 rounded font-mono-sm text-mono-sm transition-colors ${
                        engineFilter === 'all'
                          ? 'bg-surface-container text-on-surface font-medium'
                          : 'hover:bg-surface-container text-on-surface-variant'
                      }`}
                    >
                      All Severities
                    </button>
                    <button
                      onClick={() => setEngineFilter('critical')}
                      className={`px-2 py-0.5 rounded font-mono-sm text-mono-sm transition-colors ${
                        engineFilter === 'critical'
                          ? 'bg-surface-container text-on-surface font-medium'
                          : 'hover:bg-surface-container text-on-surface-variant'
                      }`}
                    >
                      Critical Only
                    </button>
                    <button
                      onClick={() => setEngineFilter('sast-dast')}
                      className={`px-2 py-0.5 rounded font-mono-sm text-mono-sm transition-colors ${
                        engineFilter === 'sast-dast'
                          ? 'bg-surface-container text-on-surface font-medium'
                          : 'hover:bg-surface-container text-on-surface-variant'
                      }`}
                    >
                      SAST vs DAST
                    </button>
                  </div>
                  <span className="font-mono-sm text-mono-sm text-tertiary flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">speed</span>
                    Velocity: +18.4% remediation speed
                  </span>
                </div>
              </div>

              {/* Right Visual (5 of 12 cols): Attack Surface & Health */}
              <div className="lg:col-span-5 p-space-md rounded bg-surface-container-lowest shadow-xs flex flex-col justify-between border border-outline-variant/60">
                <div>
                  <div className="flex items-center justify-between mb-space-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-primary text-base">pie_chart</span>
                      <h2 className="font-headline-sm text-headline-sm text-on-surface">
                        Repository Health Distribution
                      </h2>
                    </div>
                    <button
                      onClick={onNavigateToRepositories}
                      className="font-mono-sm text-mono-sm text-primary hover:underline font-medium"
                    >
                      42 Active
                    </button>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant mb-space-sm">
                    Attack surface partition based on worst-case finding severity.
                  </p>

                  {/* Repository Health Distribution Stack */}
                  <div className="space-y-2 mb-space-md">
                    <div>
                      <div className="flex justify-between font-mono-sm text-mono-sm mb-0.5">
                        <span className="flex items-center gap-1 text-on-surface">
                          <span className="w-2 h-2 rounded-full bg-tertiary"></span>
                          Secure (0 Critical / High)
                        </span>
                        <span className="font-bold text-on-surface">26 repos (61.9%)</span>
                      </div>
                      <div className="w-full bg-surface-container h-2 rounded overflow-hidden">
                        <div className="bg-tertiary h-full" style={{ width: '61.9%' }}></div>
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between font-mono-sm text-mono-sm mb-0.5">
                        <span className="flex items-center gap-1 text-on-surface">
                          <span className="w-2 h-2 rounded-full bg-secondary"></span>
                          At Risk (1-3 High, 0 Critical)
                        </span>
                        <span className="font-bold text-on-surface">11 repos (26.2%)</span>
                      </div>
                      <div className="w-full bg-surface-container h-2 rounded overflow-hidden">
                        <div className="bg-secondary h-full" style={{ width: '26.2%' }}></div>
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between font-mono-sm text-mono-sm mb-0.5">
                        <span className="flex items-center gap-1 text-error">
                          <span className="w-2 h-2 rounded-full bg-error"></span>
                          Vulnerable (≥1 Critical)
                        </span>
                        <span className="font-bold text-error">5 repos (11.9%)</span>
                      </div>
                      <div className="w-full bg-surface-container h-2 rounded overflow-hidden">
                        <div className="bg-error h-full" style={{ width: '11.9%' }}></div>
                      </div>
                    </div>
                  </div>

                  {/* Top Attack Surface Categories (CWEs) */}
                  <div className="pt-space-xs">
                    <span className="font-label-caps text-label-caps text-on-surface-variant uppercase font-semibold block mb-1.5">
                      Top Incident Vectors (CVSS Weighted)
                    </span>
                    <div className="space-y-1.5">
                      <button
                        onClick={() => onNavigateToFindings('CWE-79')}
                        className="w-full p-1.5 rounded bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between text-mono-sm font-mono-sm text-left"
                      >
                        <span className="text-on-surface font-medium truncate">
                          CWE-79: Cross-Site Scripting (XSS)
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface font-bold shrink-0 ml-2">
                          14 findings
                        </span>
                      </button>

                      <button
                        onClick={() => onNavigateToFindings('CWE-798')}
                        className="w-full p-1.5 rounded bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between text-mono-sm font-mono-sm text-left"
                      >
                        <span className="text-on-surface font-medium truncate">
                          CWE-798: Hardcoded Secrets &amp; Tokens
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-error-container text-error font-bold shrink-0 ml-2">
                          11 findings
                        </span>
                      </button>

                      <button
                        onClick={() => onNavigateToFindings('CWE-89')}
                        className="w-full p-1.5 rounded bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between text-mono-sm font-mono-sm text-left"
                      >
                        <span className="text-on-surface font-medium truncate">
                          CWE-89: SQL Injection Flaws
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface font-bold shrink-0 ml-2">
                          6 findings
                        </span>
                      </button>

                      <button
                        onClick={() => onNavigateToFindings('CWE-22')}
                        className="w-full p-1.5 rounded bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between text-mono-sm font-mono-sm text-left"
                      >
                        <span className="text-on-surface font-medium truncate">
                          CWE-22: Path Traversal
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface font-bold shrink-0 ml-2">
                          4 findings
                        </span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="mt-space-sm pt-space-xs flex items-center justify-between text-body-sm font-body-sm text-on-surface-variant">
                  <span className="flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs text-primary">policy</span>
                    Policy: Zero Tolerated Secrets
                  </span>
                  <button
                    onClick={() => onNavigateToFindings()}
                    className="text-primary hover:underline font-medium text-mono-sm font-mono-sm"
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
            <div className="rounded bg-surface-container-lowest shadow-xs overflow-hidden flex flex-col border border-outline-variant/60">
              <div className="p-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm bg-surface-container-lowest border-b border-outline-variant/60">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary text-base">rule</span>
                    <h3 className="font-headline-sm text-headline-sm text-on-surface">
                      Recent Security Scan Activity &amp; Automated Fix Pipeline
                    </h3>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    Continuous verification of AI-recommended remediation diffs against AST and sandbox runners.
                  </p>
                </div>
                <div className="flex items-center gap-space-sm">
                  <div className="relative">
                    <input
                      value={tableSearch}
                      onChange={e => setTableSearch(e.target.value)}
                      className="pl-8 pr-3 py-1 bg-surface-container-low rounded font-mono-sm text-mono-sm text-on-surface placeholder:text-outline focus:outline-none focus:bg-surface-container-lowest border border-outline-variant/60"
                      placeholder="Filter by repo, PR, or CWE..."
                      type="text"
                    />
                    <span className="material-symbols-outlined text-xs text-outline absolute left-2.5 top-1/2 -translate-y-1/2">
                      filter_list
                    </span>
                  </div>
                  <button
                    onClick={() => setTableSearch('')}
                    className="px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-variant font-mono-sm text-mono-sm text-on-surface flex items-center gap-1 transition-colors"
                  >
                    <span className="material-symbols-outlined text-xs">tune</span>
                    <span>Clear Filter</span>
                  </button>
                </div>
              </div>

              {/* High Density Data Table */}
              <div className="overflow-x-auto w-full">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-surface-container-low text-on-surface-variant font-label-caps text-label-caps uppercase border-b border-outline-variant/60">
                      <th className="py-2.5 px-space-md">Repository / Branch</th>
                      <th className="py-2.5 px-space-md">Engine &amp; Target</th>
                      <th className="py-2.5 px-space-md">Findings</th>
                      <th className="py-2.5 px-space-md">Fix Recommendation &amp; Verification Status</th>
                      <th className="py-2.5 px-space-md text-right">Execution &amp; Timestamp</th>
                      <th className="py-2.5 px-space-md text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-outline-variant/60 font-body-sm text-body-sm">
                    {filteredTableItems.slice(0, 4).map(item => {
                      const isPrMerged = item.prNumber ? mergedPrs.has(item.prNumber) : false;

                      return (
                        <tr key={item.id} className="hover:bg-surface-container-low transition-colors">
                          {/* Repo / Branch */}
                          <td className="py-space-sm px-space-md">
                            <div className="flex flex-col">
                              <div className="flex items-center gap-1.5">
                                <span className="material-symbols-outlined text-sm text-primary">terminal</span>
                                <span className="font-mono-md text-mono-md font-semibold text-on-surface">
                                  {item.repo}
                                </span>
                              </div>
                              <span className="font-mono-sm text-mono-sm text-on-surface-variant ml-5">
                                branch: {item.branch} (git:{item.gitHash})
                              </span>
                            </div>
                          </td>

                          {/* Engine & Target */}
                          <td className="py-space-sm px-space-md">
                            <div className="flex flex-col">
                              <span className="font-mono-sm text-mono-sm text-on-surface font-medium">
                                {item.engine}
                              </span>
                              <span className="font-label-caps text-label-caps text-outline uppercase">
                                {item.target}
                              </span>
                            </div>
                          </td>

                          {/* Findings */}
                          <td className="py-space-sm px-space-md">
                            {item.status === 'clean' ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-mono-sm font-semibold">
                                0 Found (Clean)
                              </span>
                            ) : item.findingsCount.critical ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded bg-error-container text-on-error-container font-mono-sm text-mono-sm font-bold">
                                {item.findingsCount.critical} Critical, {item.findingsCount.high || 0} High
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded bg-surface-container-high text-on-surface font-mono-sm text-mono-sm font-bold">
                                {item.findingsCount.high || 0} High, {item.findingsCount.med || 0} Med
                              </span>
                            )}
                          </td>

                          {/* Fix Status */}
                          <td className="py-space-sm px-space-md">
                            <div className="flex flex-col gap-1 max-w-md">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {item.status === 'verified' && (
                                  <span className="px-1.5 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-mono-sm font-bold flex items-center gap-1">
                                    <span className="material-symbols-outlined text-xs">verified</span>
                                    {isPrMerged ? 'Merged into Target' : 'Verified Against Defined Checks'}
                                  </span>
                                )}
                                {item.status === 'failed' && (
                                  <span className="px-1.5 py-0.5 rounded bg-error-container text-error font-mono-sm text-mono-sm font-bold flex items-center gap-1">
                                    <span className="material-symbols-outlined text-xs">dangerous</span>
                                    Failed Verification
                                  </span>
                                )}
                                {item.status === 'inconclusive' && (
                                  <span className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant font-mono-sm text-mono-sm font-semibold flex items-center gap-1">
                                    <span className="material-symbols-outlined text-xs">help_outline</span>
                                    Inconclusive
                                  </span>
                                )}
                                {item.status === 'clean' && (
                                  <span className="font-body-sm text-body-sm text-tertiary font-medium flex items-center gap-1">
                                    <span className="material-symbols-outlined text-xs">shield</span>
                                    Passed all compliance rule gates. No patch required.
                                  </span>
                                )}
                                {item.prNumber && (
                                  <span className="font-mono-sm text-mono-sm text-on-surface">
                                    PR #{item.prNumber}
                                  </span>
                                )}
                              </div>
                              {item.status !== 'clean' && (
                                <span
                                  className={`font-body-sm text-body-sm ${
                                    item.status === 'failed' ? 'text-error' : 'text-on-surface-variant'
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
                          <td className="py-space-sm px-space-md text-right font-mono-sm text-mono-sm text-on-surface-variant">
                            <div>{item.executionTime}</div>
                            <div className="text-outline">{item.timestamp}</div>
                          </td>

                          {/* Actions */}
                          <td className="py-space-sm px-space-md text-right">
                            <div className="flex items-center justify-end gap-1">
                              {item.status === 'verified' && (
                                <>
                                  <button
                                    onClick={() => onOpenDiffModal(item)}
                                    className="px-2 py-1 rounded bg-surface-container-high hover:bg-surface-variant text-primary font-mono-sm text-mono-sm font-semibold transition-colors"
                                  >
                                    Diff View
                                  </button>
                                  <button
                                    onClick={onOpenExportModal}
                                    className="p-1 rounded hover:bg-surface-container text-on-surface-variant"
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
                                    className="px-2 py-1 rounded bg-surface-container-high hover:bg-surface-variant text-error font-mono-sm text-mono-sm font-semibold transition-colors"
                                  >
                                    Inspect Crash
                                  </button>
                                  <button
                                    onClick={() => onOpenCrashModal(item)}
                                    className="p-1 rounded hover:bg-surface-container text-on-surface-variant"
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
                                    className="px-2 py-1 rounded bg-surface-container-high hover:bg-surface-variant text-on-surface font-mono-sm text-mono-sm transition-colors"
                                  >
                                    Rerun Test
                                  </button>
                                  <button
                                    onClick={() => onOpenCrashModal(item)}
                                    className="p-1 rounded hover:bg-surface-container text-on-surface-variant"
                                    title="View Logs"
                                  >
                                    <span className="material-symbols-outlined text-sm">subject</span>
                                  </button>
                                </>
                              )}

                              {item.status === 'clean' && (
                                <button
                                  onClick={onOpenExportModal}
                                  className="px-2 py-1 rounded bg-surface-container-low hover:bg-surface-container text-on-surface-variant font-mono-sm text-mono-sm transition-colors"
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
              <div className="p-space-sm bg-surface-container-low flex flex-col sm:flex-row items-center justify-between text-mono-sm font-mono-sm text-on-surface-variant gap-space-sm border-t border-outline-variant/60">
                <div className="flex items-center gap-2">
                  <span>Showing 4 of 42 repository runs</span>
                  <span className="text-outline-variant">•</span>
                  <span className="text-tertiary font-semibold">All engines operational</span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    disabled={currentPage === 1}
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    className="px-2 py-1 rounded bg-surface-container-lowest text-on-surface shadow-xs disabled:opacity-50"
                  >
                    ← Prev
                  </button>
                  <span className="px-2 py-1">Page {currentPage} of 11</span>
                  <button
                    disabled={currentPage === 11}
                    onClick={() => setCurrentPage(p => Math.min(11, p + 1))}
                    className="px-2 py-1 rounded bg-surface-container-lowest text-on-surface shadow-xs hover:bg-surface-container"
                  >
                    Next →
                  </button>
                </div>
              </div>
            </div>

            {/* AST Verified Remediation Diff Preview */}
            <div className="rounded bg-surface-container-lowest shadow-xs p-space-md border border-outline-variant/60">
              <div className="flex items-center justify-between pb-space-sm mb-space-sm border-b border-outline-variant/60">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-tertiary text-base">verified_user</span>
                  <div>
                    <h4 className="font-headline-sm text-headline-sm text-on-surface">
                      AST Verified Remediation Diff Preview
                    </h4>
                    <p className="font-body-sm text-body-sm text-on-surface-variant">
                      PR #418 Fix Verification: SQL Injection (CWE-89) in{' '}
                      <code className="font-mono-sm text-mono-sm bg-surface-container px-1 py-0.5 rounded">
                        auth-gateway/src/dao/user_query.py
                      </code>
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center px-2 py-0.5 rounded bg-tertiary-fixed text-on-tertiary-fixed-variant font-mono-sm text-mono-sm font-bold">
                    AST TAINT CHECK: PASS
                  </span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded bg-surface-container text-on-surface-variant font-mono-sm text-mono-sm">
                    24 UNIT TESTS: PASS
                  </span>
                </div>
              </div>

              {/* Diff Container */}
              <div className="rounded overflow-hidden bg-surface-container-low font-mono-sm text-mono-sm border border-outline-variant/60">
                <div className="bg-surface-container px-3 py-1 text-on-surface-variant flex items-center justify-between border-b border-outline-variant/60">
                  <span>auth-gateway/src/dao/user_query.py</span>
                  <span className="text-outline">git:7f3a9b8 → patch:29ca90</span>
                </div>
                {/* Deletion lines */}
                <div className="flex bg-error-container text-on-error-container">
                  <div className="w-10 px-2 py-1 text-right text-outline select-none bg-surface-container-high opacity-70">
                    41
                  </div>
                  <div className="w-6 py-1 text-center font-bold select-none text-error">-</div>
                  <div className="py-1 pr-3 font-mono overflow-x-auto whitespace-pre">
                    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{'{tenant_id}'}' AND email = '{'{email}'}'")
                  </div>
                </div>
                {/* Addition lines */}
                <div className="flex bg-tertiary-fixed text-on-tertiary-fixed-variant">
                  <div className="w-10 px-2 py-1 text-right text-outline select-none bg-surface-container-high opacity-70">
                    41
                  </div>
                  <div className="w-6 py-1 text-center font-bold select-none text-tertiary">+</div>
                  <div className="py-1 pr-3 font-mono overflow-x-auto whitespace-pre">
                    query = "SELECT * FROM users WHERE tenant_id = %s AND email = %s"
                  </div>
                </div>
                <div className="flex bg-tertiary-fixed text-on-tertiary-fixed-variant">
                  <div className="w-10 px-2 py-1 text-right text-outline select-none bg-surface-container-high opacity-70">
                    42
                  </div>
                  <div className="w-6 py-1 text-center font-bold select-none text-tertiary">+</div>
                  <div className="py-1 pr-3 font-mono overflow-x-auto whitespace-pre">
                    cursor.execute(query, (tenant_id, email))  # AST-verified parameterized tuple
                  </div>
                </div>
              </div>

              <div className="mt-space-sm pt-space-xs flex items-center justify-between text-body-sm font-body-sm flex-wrap gap-2">
                <span className="text-on-surface-variant flex items-center gap-1 font-mono-sm text-mono-sm">
                  <span className="material-symbols-outlined text-xs text-primary">terminal</span>
                  Semgrep Rule: <code className="text-on-surface font-semibold">python.sqlalchemy.security.audit.raw-sql-format</code> resolved.
                </span>
                <button
                  disabled={isPr418Merged}
                  onClick={() => onApproveAndMerge('run-01', 418)}
                  className={`px-3 py-1 rounded font-body-sm text-body-sm transition-colors shadow-xs ${
                    isPr418Merged
                      ? 'bg-tertiary text-on-tertiary cursor-default font-medium'
                      : 'bg-primary text-on-primary hover:bg-on-primary-fixed-variant'
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
