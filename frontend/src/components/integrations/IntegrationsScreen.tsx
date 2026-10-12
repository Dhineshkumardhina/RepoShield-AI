import React, { useState } from 'react';
import { MOCK_INTEGRATIONS } from '../../data/mockData';
import { Integration } from '../../types';

export const IntegrationsScreen: React.FC = () => {
  const [integrations] = useState<Integration[]>(MOCK_INTEGRATIONS);
  const [testStatus, setTestStatus] = useState<string | null>(null);

  const activeCount = integrations.filter(i => i.status === 'active').length;

  const handleTestConnection = (integ: Integration) => {
    if (integ.status === 'disconnected') {
      setTestStatus(`Connector '${integ.name}' is NOT configured. Register credentials to establish live connection.`);
      setTimeout(() => setTestStatus(null), 4000);
      return;
    }
    setTestStatus(`Testing connection to ${integ.name}...`);
    setTimeout(() => {
      setTestStatus(`Successfully verified engine readiness for ${integ.name}. Execution mode: Local Runner.`);
      setTimeout(() => setTestStatus(null), 3000);
    }, 600);
  };

  return (
    <div className="flex flex-col w-full">
      {/* Header */}
      <div className="px-6 py-4 bg-white border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-blue-600 uppercase font-bold tracking-wider">
              DEVELOPER &amp; SEC-OPS CONNECTORS
            </span>
            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-800 font-mono text-[10px] font-bold border border-slate-200">
              {activeCount} READY / {integrations.length} CONFIGURED
            </span>
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight mt-0.5">
            Security Engines &amp; VCS Integrations
          </h1>
        </div>

        {testStatus && (
          <div className="px-3 py-1.5 rounded-lg bg-slate-100 text-slate-800 font-mono text-xs flex items-center gap-2 animate-in fade-in border border-slate-200 shadow-2xs">
            <span className="material-symbols-outlined text-sm text-blue-600">info</span>
            <span>{testStatus}</span>
          </div>
        )}
      </div>

      {/* Main Grid */}
      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {integrations.map(integ => {
            const isActive = integ.status === 'active';
            return (
              <div
                key={integ.id}
                className="p-5 rounded-xl bg-white border border-slate-200 shadow-2xs hover:shadow-xs transition-shadow flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-mono text-blue-600 uppercase font-bold text-[10px] tracking-wide">
                      {integ.category}
                    </span>
                    <span
                      className={`flex items-center gap-1.5 font-mono text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        isActive
                          ? 'text-emerald-700 bg-emerald-50 border-emerald-200'
                          : 'text-slate-500 bg-slate-100 border-slate-200'
                      }`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          isActive ? 'bg-emerald-500' : 'bg-slate-400'
                        }`}
                      ></span>
                      {isActive ? 'READY' : 'NOT CONFIGURED'}
                    </span>
                  </div>

                  <h3 className="font-bold text-slate-900 text-base mb-1">
                    {integ.name}
                  </h3>
                  <span className="font-mono text-slate-400 text-xs block mb-2">{integ.version}</span>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    {integ.description}
                  </p>
                </div>

                <div className="mt-5 pt-3.5 border-t border-slate-100">
                  <div className="flex items-center justify-between font-mono text-xs text-slate-500 mb-3">
                    <span>{integ.eventsProcessed}</span>
                    <span className="text-slate-400">{integ.lastSync}</span>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    <button
                      onClick={() => handleTestConnection(integ)}
                      className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono text-xs font-medium transition-colors border border-slate-200"
                    >
                      {isActive ? 'Test Ping' : 'Check Status'}
                    </button>
                    <button className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 text-blue-600 font-mono text-xs font-semibold transition-colors border border-slate-200">
                      Configure
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
