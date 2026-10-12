import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export const LandingPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'diff' | 'evidence' | 'tests'>('diff');

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans selection:bg-slate-900 selection:text-white">
      {/* Top Header */}
      <header className="h-14 border-b border-slate-200/80 bg-white/90 backdrop-blur-md sticky top-0 z-50 px-4 lg:px-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-xs">
              <span className="material-symbols-outlined text-lg">shield</span>
            </div>
            <div className="flex flex-col">
              <span className="font-semibold text-slate-900 text-sm tracking-tight leading-none">
                RepoShield AI
              </span>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5 font-medium">
                Fix Verification Engine
              </span>
            </div>
          </Link>
          <span className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-600 border border-slate-200 ml-1">
            v0.1.0
          </span>
        </div>

        <nav className="hidden md:flex items-center gap-7 text-xs font-medium text-slate-600">
          <a href="#how-it-works" className="hover:text-slate-900 transition-colors">How It Works</a>
          <a href="#architecture" className="hover:text-slate-900 transition-colors">Verification Architecture</a>
          <a href="#scanners" className="hover:text-slate-900 transition-colors">Scanners</a>
          <a href="#compliance" className="hover:text-slate-900 transition-colors">Compliance</a>
        </nav>

        <div className="flex items-center gap-2.5">
          <Link
            to="/login"
            className="px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 hover:bg-slate-100 rounded-md transition-colors"
          >
            Sign In
          </Link>
          <Link
            to="/dashboard"
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-all shadow-xs hover:shadow-sm flex items-center gap-1.5 active:scale-[0.98]"
          >
            <span>Console</span>
            <span className="material-symbols-outlined text-sm">arrow_forward</span>
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <section className="pt-16 pb-12 px-4 lg:px-8 max-w-5xl mx-auto text-center flex flex-col items-center">
        {/* Release / Scope Pill */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white border border-slate-200 shadow-2xs text-slate-700 text-xs font-mono font-medium mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
          <span>AST TAINT VERIFICATION &amp; TEST GATE ORCHESTRATION</span>
        </div>

        {/* Main Headline */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-slate-900 tracking-tight leading-[1.1] max-w-4xl">
          Detect source vulnerabilities. <br />
          <span className="text-slate-500 font-semibold">Verify security fixes with proof.</span>
        </h1>

        {/* Supporting Copy */}
        <p className="mt-5 text-sm sm:text-base text-slate-600 max-w-2xl leading-relaxed">
          RepoShield AI correlates static scanner evidence with compiler AST taint traces and executes regression tests in ephemeral sandboxes to ensure every patch fixes the vulnerability without breaking production code.
        </p>

        {/* Primary CTA Buttons */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Link
            to="/dashboard"
            className="px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs sm:text-sm rounded-lg transition-all shadow-xs hover:shadow-sm flex items-center gap-2 active:scale-[0.98]"
          >
            <span className="material-symbols-outlined text-lg">dashboard</span>
            <span>Launch Security Console</span>
          </Link>

          <Link
            to="/register"
            className="px-5 py-2.5 bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs sm:text-sm rounded-lg border border-slate-200 shadow-2xs transition-all hover:border-slate-300"
          >
            Register Workspace
          </Link>
        </div>

        {/* Live Product Preview Widget (Interactive SaaS Mockup) */}
        <div className="mt-12 w-full max-w-4xl bg-white border border-slate-200/90 rounded-xl shadow-sm overflow-hidden text-left">
          {/* Mock Browser/Window Header */}
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-slate-300" />
              <div className="w-2.5 h-2.5 rounded-full bg-slate-300" />
              <div className="w-2.5 h-2.5 rounded-full bg-slate-300" />
              <span className="font-mono text-[11px] text-slate-500 ml-2">
                reposhield-cli verify --pr 418 --repo xerova/auth-gateway
              </span>
            </div>
            <div className="flex items-center gap-1.5 font-mono text-[11px]">
              <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
                VERIFIED SAFE
              </span>
            </div>
          </div>

          {/* Interactive Preview Tabs */}
          <div className="px-4 border-b border-slate-200 bg-white flex items-center gap-4 text-xs font-mono">
            <button
              onClick={() => setActiveTab('diff')}
              className={`py-2.5 border-b-2 font-medium transition-colors ${
                activeTab === 'diff'
                  ? 'border-slate-900 text-slate-900 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Unified Diff (FIND-418)
            </button>
            <button
              onClick={() => setActiveTab('evidence')}
              className={`py-2.5 border-b-2 font-medium transition-colors ${
                activeTab === 'evidence'
                  ? 'border-slate-900 text-slate-900 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Dual Evidence Ledger
            </button>
            <button
              onClick={() => setActiveTab('tests')}
              className={`py-2.5 border-b-2 font-medium transition-colors ${
                activeTab === 'tests'
                  ? 'border-slate-900 text-slate-900 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Regression Suite (142/142 Passed)
            </button>
          </div>

          {/* Preview Tab Content */}
          <div className="p-4 bg-slate-900 text-slate-200 font-mono text-xs overflow-x-auto min-h-[190px]">
            {activeTab === 'diff' && (
              <div className="space-y-1">
                <div className="text-slate-500">--- a/src/dao/user_query.py (Base: 4a2b1c8)</div>
                <div className="text-slate-500">+++ b/src/dao/user_query.py (Patch: 9f8e7d6)</div>
                <div className="text-slate-600">@@ -42,3 +42,3 @@ def get_user_record(cursor, user_id):</div>
                <div className="bg-rose-950/60 text-rose-300 px-1 -mx-1 rounded">
                  -    cursor.execute(f"SELECT * FROM users WHERE id = '{'{'}user_id{'}'}'") # CWE-89 SQL Injection
                </div>
                <div className="bg-emerald-950/60 text-emerald-300 px-1 -mx-1 rounded">
                  +    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)) # Parameterized tuple binding
                </div>
                <div className="text-slate-400">     return cursor.fetchone()</div>
              </div>
            )}

            {activeTab === 'evidence' && (
              <div className="space-y-2">
                <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
                  <span className="text-slate-400">STATIC SCANNER DIFFERENTIAL:</span>
                  <span className="text-emerald-400">PASSED (Semgrep OSS reported 0 findings on candidate AST)</span>
                </div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
                  <span className="text-slate-400">TARGETED EXPLOIT PROBE:</span>
                  <span className="text-emerald-400">PASSED (Malicious injection payload safely escaped)</span>
                </div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
                  <span className="text-slate-400">REGRESSION GATE STATUS:</span>
                  <span className="text-emerald-400">PASSED (0 new findings introduced across entire codebase)</span>
                </div>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-slate-400">CRYPTOGRAPHIC AUDIT HASH:</span>
                  <span className="text-slate-300">sha256:7c82a194e4d580f12... (Tamper-evident)</span>
                </div>
              </div>
            )}

            {activeTab === 'tests' && (
              <div className="space-y-1">
                <div className="text-emerald-400">✓ tests/security/test_sql_injection.py::test_parameterized_query PASSED [0.12s]</div>
                <div className="text-emerald-400">✓ tests/security/test_sql_injection.py::test_boundary_conditions PASSED [0.08s]</div>
                <div className="text-emerald-400">✓ tests/integration/test_auth_flow.py::test_token_issuance PASSED [0.45s]</div>
                <div className="text-emerald-400">✓ tests/unit/test_user_dao.py::test_record_parsing PASSED [0.03s]</div>
                <div className="text-slate-400 pt-2 border-t border-slate-800">
                  Result: 142 passed, 0 failed, 0 regressions in 1.48s in clean ephemeral sandbox.
                </div>
              </div>
            )}
          </div>

          {/* Mock Widget Footer */}
          <div className="px-4 py-2.5 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="material-symbols-outlined text-sm text-emerald-600">check_circle</span>
              <span>All 3 verification gates satisfied. PR #418 auto-merge ready.</span>
            </span>
            <Link to="/verification" className="text-slate-900 font-semibold hover:underline">
              Inspect Verification Queue &rarr;
            </Link>
          </div>
        </div>

        {/* Real-time stats card */}
        <div className="mt-8 w-full grid grid-cols-2 md:grid-cols-4 gap-3 p-3 rounded-xl bg-white border border-slate-200 shadow-2xs max-w-4xl">
          <div className="p-3 text-center border-r border-slate-100 last:border-0">
            <span className="text-2xl font-bold text-slate-900 block font-mono">42</span>
            <span className="text-xs text-slate-500 font-medium">Production Repos</span>
          </div>
          <div className="p-3 text-center border-r border-slate-100 last:border-0">
            <span className="text-2xl font-bold text-emerald-600 block font-mono">99.4%</span>
            <span className="text-xs text-slate-500 font-medium">Verified Fix Rate</span>
          </div>
          <div className="p-3 text-center border-r border-slate-100 last:border-0">
            <span className="text-2xl font-bold text-slate-900 block font-mono">&lt; 90s</span>
            <span className="text-xs text-slate-500 font-medium">Sandbox Gate Replay</span>
          </div>
          <div className="p-3 text-center">
            <span className="text-2xl font-bold text-slate-900 block font-mono">0</span>
            <span className="text-xs text-slate-500 font-medium">Post-Merge Regressions</span>
          </div>
        </div>
      </section>

      {/* Scanners & Integrations Ecosystem Strip */}
      <section id="scanners" className="py-8 bg-white border-y border-slate-200/80 px-4 lg:px-8">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <span className="font-mono text-xs uppercase font-semibold text-slate-400 tracking-wider shrink-0">
            Engineered Integrations
          </span>
          <div className="flex flex-wrap items-center justify-center gap-6 text-xs font-mono font-medium text-slate-600">
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200">
              <span className="material-symbols-outlined text-sm text-slate-700">code</span>
              Semgrep OSS
            </span>
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200">
              <span className="material-symbols-outlined text-sm text-slate-700">security</span>
              Bandit AST
            </span>
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200">
              <span className="material-symbols-outlined text-sm text-slate-700">inventory_2</span>
              pip-audit
            </span>
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200">
              <span className="material-symbols-outlined text-sm text-slate-700">key</span>
              Gitleaks
            </span>
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200">
              <span className="material-symbols-outlined text-sm text-slate-700">terminal</span>
              Docker Sandboxes
            </span>
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200">
              <span className="material-symbols-outlined text-sm text-slate-700">merge_type</span>
              GitHub &amp; GitLab PRs
            </span>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-16 bg-slate-50 px-4 lg:px-8">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-xl mx-auto mb-12">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold block mb-1">
              Core Architecture
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Engineered for Zero-Trust Code Verification
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 mt-2">
              Three verification layers ensure patches are effective, comprehensive, and non-regressive.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs hover:shadow-xs transition-shadow">
              <div className="w-9 h-9 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-4">
                <span className="material-symbols-outlined text-xl">account_tree</span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">
                AST Taint Grounding
              </h3>
              <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                Traces source-to-sink data flow across function boundaries. Does not classify issues based on heuristic keywords alone.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs hover:shadow-xs transition-shadow">
              <div className="w-9 h-9 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-4">
                <span className="material-symbols-outlined text-xl">biotech</span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">
                Ephemeral Test Sandboxes
              </h3>
              <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                Applies candidate patches into isolated clean runners and re-runs both unit tests and adversarial exploit probes.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs hover:shadow-xs transition-shadow">
              <div className="w-9 h-9 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-4">
                <span className="material-symbols-outlined text-xl">policy</span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">
                Automated Merge Gates
              </h3>
              <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                Pull requests are approved and merged only when verified. Quarantines patches that cause test regressions or fail AST verification.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-200 bg-white py-8 px-4 lg:px-8 text-xs text-slate-500 font-mono">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-800">RepoShield AI</span>
            <span>•</span>
            <span>Xerova Digital Solutions AppSec Division</span>
          </div>
          <div className="flex items-center gap-4 text-slate-600">
            <Link to="/login" className="hover:text-slate-900">Sign In</Link>
            <Link to="/dashboard" className="hover:text-slate-900">Console</Link>
            <Link to="/repositories" className="hover:text-slate-900">Repositories</Link>
            <Link to="/verification" className="hover:text-slate-900">Verification</Link>
            <Link to="/settings" className="hover:text-slate-900">Integrations</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};
