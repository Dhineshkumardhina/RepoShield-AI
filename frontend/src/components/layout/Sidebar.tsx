import React from 'react';

export type ScreenId =
  | 'dashboard'
  | 'repositories'
  | 'findings'
  | 'fix-verification'
  | 'ai-analyzer'
  | 'evidence-center'
  | 'integrations'
  | 'settings';

interface SidebarProps {
  currentScreen: ScreenId;
  onSelectScreen: (screen: ScreenId) => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
  verificationQueueCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentScreen,
  onSelectScreen,
  isOpenMobile,
  onCloseMobile,
  verificationQueueCount
}) => {
  const navItems: {
    id: ScreenId;
    label: string;
    icon: string;
    badge?: React.ReactNode;
  }[] = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: 'dashboard',
      badge: <span className="w-1.5 h-1.5 rounded-full bg-blue-600"></span>
    },
    {
      id: 'repositories',
      label: 'Repositories',
      icon: 'folder_code',
      badge: (
        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold border border-slate-200">
          42
        </span>
      )
    },
    {
      id: 'findings',
      label: 'Findings',
      icon: 'security_update_warning',
      badge: (
        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 font-bold border border-rose-200">
          14
        </span>
      )
    },
    {
      id: 'fix-verification',
      label: 'Fix Verification',
      icon: 'task_alt',
      badge: (
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="font-mono text-[9px] text-emerald-700 font-bold uppercase">Synced</span>
        </div>
      )
    },
    {
      id: 'ai-analyzer',
      label: 'Patch Analyzer',
      icon: 'code_blocks',
      badge: (
        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold border border-slate-200">
          Beta
        </span>
      )
    },
    {
      id: 'evidence-center',
      label: 'Evidence Center',
      icon: 'fact_check'
    },
    {
      id: 'integrations',
      label: 'Integrations',
      icon: 'extension',
      badge: <span className="material-symbols-outlined text-xs text-on-surface-variant">link</span>
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: 'settings'
    }
  ];

  const handleNavClick = (id: ScreenId) => {
    onSelectScreen(id);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/50 backdrop-blur-xs lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed left-0 top-0 h-screen w-64 bg-white border-r border-slate-200 z-50 flex flex-col justify-between select-none transition-transform duration-200 ease-in-out ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="flex flex-col flex-1 min-h-0">
          {/* Brand Header */}
          <div className="h-14 px-4 border-b border-slate-200 flex items-center justify-between bg-white">
            <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => handleNavClick('dashboard')}>
              <img
                alt="RepoShield AI Brand Mark"
                className="h-8 w-auto object-contain"
                src="https://lh3.googleusercontent.com/aida/AEtjO1VcL0wlb_f5WBx-QIXHrLjESTw-qqtdxbz-WLCmCqPEOrxAsChrdoWAr8oY48rSZcB5tISGbyvnIW-pudiC5QA4i8Dhx5v4CymSU_5gAmCZ1izfX4V1unZp-MWq88xeuxkhp27Nl-fpQNFM6P0QBrrX0KX_WO6gQbTmmBiWBaZBjG25y5EBiyoiROTWcK4tKSkM04wD36Ugca-MtmT1OspOQoBjodP1W4PZEvR3xo9H0jBn4a-_54HoiS1m"
              />
              <div className="flex flex-col">
                <span className="font-bold text-sm text-slate-900 tracking-tight leading-none">
                  RepoShield AI
                </span>
                <span className="text-[10px] font-mono text-slate-500 uppercase mt-0.5">
                  by Xerova
                </span>
              </div>
            </div>
            <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              SEC-OPS
            </span>
          </div>

          {/* Workspace Switcher */}
          <div className="p-3 border-b border-slate-200 bg-white">
            <button
              className="w-full flex items-center justify-between px-3 py-2 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-left transition-colors"
              title="Current Active Workspace"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <span className="material-symbols-outlined text-slate-700 text-base">hub</span>
                <div className="flex flex-col min-w-0">
                  <span className="text-[10px] font-mono uppercase text-slate-500">
                    Workspace
                  </span>
                  <span className="text-xs font-semibold text-slate-900 truncate">
                    Xerova Production CI/CD
                  </span>
                </div>
              </div>
              <span className="material-symbols-outlined text-slate-400 text-base">unfold_more</span>
            </button>
          </div>

          {/* Navigation Engine Header */}
          <div className="px-4 pt-3 pb-1.5 flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-slate-500 tracking-wider font-semibold">
              Platform Navigation
            </span>
            {verificationQueueCount > 0 && (
              <span className="font-mono text-[10px] text-emerald-700 font-bold bg-emerald-50 border border-emerald-200 px-1.5 py-0.2 rounded">
                QUEUE: {verificationQueueCount}
              </span>
            )}
          </div>

          {/* Nav Items List */}
          <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
            {navItems.map(item => {
              const isActive = currentScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  aria-label={item.label}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-left transition-colors text-xs ${
                    isActive
                      ? 'bg-slate-900 text-white font-medium shadow-xs'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <span className="material-symbols-outlined text-base" aria-hidden="true">{item.icon}</span>
                    <span className="font-medium">{item.label}</span>
                  </div>
                  {item.badge}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Engine Status Bottom Bar */}
        <div className="p-3 border-t border-slate-200 bg-white space-y-2">
          <div className="px-3 py-2 rounded-md bg-slate-50 border border-slate-200">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold">
                Engine Status
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-[10px] font-mono text-emerald-700 font-bold">Online</span>
              </span>
            </div>
            <div className="font-mono text-xs text-slate-800 font-medium truncate">Scanner v4.2.8 (AST Verified)</div>
          </div>
          <div className="flex items-center justify-between pt-1 px-1 text-xs">
            <button
              onClick={() => handleNavClick('evidence-center')}
              className="flex items-center gap-1 text-slate-600 hover:text-slate-900 transition-colors"
            >
              <span className="material-symbols-outlined text-sm">menu_book</span>
              <span>Docs</span>
            </button>
            <span className="text-slate-300">•</span>
            <button
              onClick={() => handleNavClick('evidence-center')}
              className="flex items-center gap-1 text-slate-600 hover:text-slate-900 transition-colors"
            >
              <span className="material-symbols-outlined text-sm">history_edu</span>
              <span>Audit Logs</span>
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};
