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
      <div className="px-4 lg:px-gutter-desktop py-space-md bg-surface-container-lowest border-b border-outline-variant/60 flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-label-caps text-label-caps text-primary uppercase font-bold tracking-wider">
              DEVELOPER &amp; SEC-OPS CONNECTORS
            </span>
            <span className="px-1.5 py-0.5 rounded bg-surface-container text-on-surface font-mono-sm text-mono-sm font-bold">
              {activeCount} READY / {integrations.length} CONFIGURED
            </span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Security Engines &amp; VCS Integrations
          </h1>
        </div>

        {testStatus && (
          <div className="p-2 rounded bg-surface-container text-on-surface font-mono-sm text-xs flex items-center gap-1.5 animate-in fade-in border border-outline-variant/60">
            <span className="material-symbols-outlined text-sm text-primary">info</span>
            <span>{testStatus}</span>
          </div>
        )}
      </div>

      {/* Main Grid */}
      <div className="px-4 lg:px-gutter-desktop py-space-lg">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {integrations.map(integ => {
            const isActive = integ.status === 'active';
            return (
              <div
                key={integ.id}
                className="p-5 rounded bg-surface-container-lowest border border-outline-variant/60 shadow-xs flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-label-caps text-primary uppercase font-bold text-[10px]">
                      {integ.category}
                    </span>
                    <span
                      className={`flex items-center gap-1 font-mono-sm text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        isActive
                          ? 'text-tertiary bg-tertiary-fixed'
                          : 'text-outline bg-surface-container text-on-surface-variant'
                      }`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          isActive ? 'bg-tertiary' : 'bg-outline'
                        }`}
                      ></span>
                      {isActive ? 'READY' : 'NOT CONFIGURED'}
                    </span>
                  </div>

                  <h3 className="font-headline-sm text-on-surface text-base font-semibold mb-1">
                    {integ.name}
                  </h3>
                  <span className="font-mono-sm text-outline text-xs block mb-2">{integ.version}</span>
                  <p className="font-body-sm text-xs text-on-surface-variant leading-relaxed">
                    {integ.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-outline-variant/60">
                  <div className="flex items-center justify-between text-mono-sm text-xs text-on-surface-variant mb-3">
                    <span>{integ.eventsProcessed}</span>
                    <span className="text-outline">{integ.lastSync}</span>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    <button
                      onClick={() => handleTestConnection(integ)}
                      className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-high text-on-surface font-mono-sm text-xs transition-colors"
                    >
                      {isActive ? 'Test Ping' : 'Check Status'}
                    </button>
                    <button className="px-2.5 py-1 rounded bg-surface-container-low hover:bg-surface-container text-primary font-mono-sm text-xs font-semibold transition-colors">
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
