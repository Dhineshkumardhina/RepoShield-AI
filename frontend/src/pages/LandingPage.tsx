import React from 'react';
import { Link } from 'react-router-dom';

export const LandingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans">
      {/* Top Navigation */}
      <header className="h-16 border-b border-slate-200 bg-white/90 backdrop-blur-md sticky top-0 z-40 px-4 lg:px-12 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs">
            <span className="material-symbols-outlined text-2xl">shield</span>
          </div>
          <div>
            <span className="font-headline-sm text-base font-bold text-slate-900 tracking-tight block leading-tight">
              RepoShield AI
            </span>
            <span className="font-label-caps text-[9px] text-slate-500 uppercase font-semibold">
              Xerova Digital Solutions
            </span>
          </div>
        </div>

        <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-600">
          <a href="#features" className="hover:text-blue-600 transition-colors">Core Engine</a>
          <a href="#how-it-works" className="hover:text-blue-600 transition-colors">Verification Flow</a>
          <a href="#scanners" className="hover:text-blue-600 transition-colors">Scanner Ecosystem</a>
          <a href="#evidence" className="hover:text-blue-600 transition-colors">Audit Evidence</a>
        </nav>

        <div className="flex items-center gap-3">
          <Link
            to="/login"
            className="px-3.5 py-2 text-sm font-semibold text-slate-700 hover:text-blue-600 hover:bg-slate-100 rounded-lg transition-colors"
          >
            Sign In
          </Link>
          <Link
            to="/dashboard"
            className="px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-xs transition-colors flex items-center gap-1.5"
          >
            <span>Open Console</span>
            <span className="material-symbols-outlined text-base">arrow_forward</span>
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4 lg:px-12 max-w-7xl mx-auto text-center flex flex-col items-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-mono-sm font-semibold mb-6">
          <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse" />
          <span>AST TAINT VERIFICATION & TEST GATE ORCHESTRATION</span>
        </div>

        <h1 className="font-headline-xl text-3xl sm:text-5xl lg:text-6xl text-slate-900 max-w-4xl tracking-tight leading-tight">
          Detect source vulnerabilities. <br />
          <span className="text-blue-600">Verify security fixes with proof.</span>
        </h1>

        <p className="mt-6 text-base sm:text-lg text-slate-600 max-w-2xl leading-relaxed">
          RepoShield AI correlates static scanner evidence with compiler AST taint traces and executes regression tests in ephemeral sandboxes to ensure every patch fixes the vulnerability without breaking production code.
        </p>

        <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
          <Link
            to="/dashboard"
            className="px-6 py-3.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm rounded-xl shadow-sm transition-all flex items-center gap-2"
          >
            <span className="material-symbols-outlined text-lg">dashboard</span>
            <span>Launch Security Console</span>
          </Link>

          <Link
            to="/register"
            className="px-6 py-3.5 bg-white hover:bg-slate-50 text-slate-700 font-semibold text-sm rounded-xl border border-slate-300 shadow-2xs transition-all"
          >
            Register Workspace
          </Link>
        </div>

        {/* Real-time stats card */}
        <div className="mt-16 w-full grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-2xl bg-white border border-slate-200 shadow-xs max-w-4xl">
          <div className="p-4 text-center border-r border-slate-100 last:border-0">
            <span className="font-headline-lg text-2xl font-bold text-slate-900 block">42</span>
            <span className="text-xs text-slate-500 font-medium">Production Repos</span>
          </div>
          <div className="p-4 text-center border-r border-slate-100 last:border-0">
            <span className="font-headline-lg text-2xl font-bold text-emerald-600 block">99.4%</span>
            <span className="text-xs text-slate-500 font-medium">Verified Fix Rate</span>
          </div>
          <div className="p-4 text-center border-r border-slate-100 last:border-0">
            <span className="font-headline-lg text-2xl font-bold text-blue-600 block">&lt; 90s</span>
            <span className="text-xs text-slate-500 font-medium">Sandbox Gate Replay</span>
          </div>
          <div className="p-4 text-center">
            <span className="font-headline-lg text-2xl font-bold text-slate-900 block">0</span>
            <span className="text-xs text-slate-500 font-medium">Post-Merge Regressions</span>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-16 bg-white border-y border-slate-200 px-4 lg:px-12">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="font-label-caps text-xs text-blue-600 font-semibold tracking-wider uppercase">
              DEFENSIVE APPARATUS
            </span>
            <h2 className="font-headline-lg text-2xl sm:text-3xl text-slate-900 mt-1">
              Engineered for Zero-Trust Code Verification
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center mb-4">
                <span className="material-symbols-outlined text-xl">account_tree</span>
              </div>
              <h3 className="font-headline-sm text-base text-slate-900 font-semibold">
                AST Taint Grounding
              </h3>
              <p className="mt-2 text-sm text-slate-600 leading-relaxed">
                Traces source-to-sink data flow across function boundaries. Does not classify issues based on heuristic keywords alone.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-emerald-100 text-emerald-600 flex items-center justify-center mb-4">
                <span className="material-symbols-outlined text-xl">biotech</span>
              </div>
              <h3 className="font-headline-sm text-base text-slate-900 font-semibold">
                Ephemeral Test Sandboxes
              </h3>
              <p className="mt-2 text-sm text-slate-600 leading-relaxed">
                Applies candidate patches into isolated clean runners and re-runs both unit tests and adversarial exploit probes.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-purple-100 text-purple-600 flex items-center justify-center mb-4">
                <span className="material-symbols-outlined text-xl">policy</span>
              </div>
              <h3 className="font-headline-sm text-base text-slate-900 font-semibold">
                Automated Merge Gates
              </h3>
              <p className="mt-2 text-sm text-slate-600 leading-relaxed">
                Pull requests are approved and merged only when verified. Quarantines patches that cause test regressions or fail AST verification.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-200 bg-white py-8 px-4 lg:px-12 text-center text-xs text-slate-500 font-mono-sm">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-700">RepoShield AI</span>
            <span>•</span>
            <span>Xerova Digital Solutions AppSec Division</span>
          </div>
          <div className="flex items-center gap-4 text-slate-600">
            <Link to="/login" className="hover:text-blue-600">Sign In</Link>
            <Link to="/dashboard" className="hover:text-blue-600">Console</Link>
            <Link to="/settings" className="hover:text-blue-600">Integrations</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};
