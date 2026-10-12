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
      badge: <span className="w-1.5 h-1.5 rounded-full bg-primary-container"></span>
    },
    {
      id: 'repositories',
      label: 'Repositories',
      icon: 'folder_code',
      badge: (
        <span className="font-mono-sm text-mono-sm px-1.5 py-0.5 rounded bg-secondary-container text-on-secondary-fixed-variant">
          42
        </span>
      )
    },
    {
      id: 'findings',
      label: 'Findings',
      icon: 'security_update_warning',
      badge: (
        <span className="font-mono-sm text-mono-sm px-1.5 py-0.5 rounded bg-error-container text-error font-semibold">
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
          <span className="w-2 h-2 rounded-full bg-tertiary-container animate-pulse"></span>
          <span className="font-label-caps text-label-caps text-tertiary uppercase">Synced</span>
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
        className={`fixed left-0 top-0 h-screen w-64 bg-surface-container-lowest border-r border-outline-variant z-50 flex flex-col justify-between select-none transition-transform duration-200 ease-in-out ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="flex flex-col flex-1 min-h-0">
          {/* Brand Header */}
          <div className="h-14 px-space-md border-b border-outline-variant flex items-center justify-between bg-surface-container-lowest">
            <div className="flex items-center gap-space-sm cursor-pointer" onClick={() => handleNavClick('dashboard')}>
              <img
                alt="RepoShield AI Brand Mark"
                className="h-8 w-auto object-contain"
                src="https://lh3.googleusercontent.com/aida/AEtjO1VcL0wlb_f5WBx-QIXHrLjESTw-qqtdxbz-WLCmCqPEOrxAsChrdoWAr8oY48rSZcB5tISGbyvnIW-pudiC5QA4i8Dhx5v4CymSU_5gAmCZ1izfX4V1unZp-MWq88xeuxkhp27Nl-fpQNFM6P0QBrrX0KX_WO6gQbTmmBiWBaZBjG25y5EBiyoiROTWcK4tKSkM04wD36Ugca-MtmT1OspOQoBjodP1W4PZEvR3xo9H0jBn4a-_54HoiS1m"
              />
              <div className="flex flex-col">
                <span className="font-headline-sm text-headline-sm text-on-surface tracking-tight leading-none">
                  RepoShield AI
                </span>
                <span className="font-label-caps text-label-caps text-on-surface-variant uppercase mt-0.5">
                  by Xerova
                </span>
              </div>
            </div>
            <span className="font-label-caps text-label-caps px-1.5 py-0.5 rounded bg-surface-container-low text-primary border border-outline-variant">
              SEC-OPS
            </span>
          </div>

          {/* Workspace Switcher */}
          <div className="p-space-sm border-b border-outline-variant bg-surface-container-lowest">
            <button
              className="w-full flex items-center justify-between px-space-sm py-1.5 rounded-lg border border-outline-variant bg-surface-container-low hover:bg-surface-container text-left transition-colors"
              title="Current Active Workspace"
            >
              <div className="flex items-center gap-space-sm min-w-0">
                <span className="material-symbols-outlined text-primary text-base">hub</span>
                <div className="flex flex-col min-w-0">
                  <span className="font-label-caps text-label-caps text-on-surface-variant uppercase">
                    Workspace
                  </span>
                  <span className="font-mono-md text-mono-md text-on-surface truncate font-medium">
                    Xerova Production CI/CD
                  </span>
                </div>
              </div>
              <span className="material-symbols-outlined text-on-surface-variant text-base">unfold_more</span>
            </button>
          </div>

          {/* Navigation Engine Header */}
          <div className="px-space-md pt-space-sm pb-1 flex items-center justify-between">
            <span className="font-label-caps text-label-caps text-on-surface-variant uppercase tracking-wider">
              Navigation Engine
            </span>
            {verificationQueueCount > 0 && (
              <span className="font-mono-sm text-[10px] text-tertiary font-bold bg-tertiary-fixed px-1 rounded">
                QUEUE: {verificationQueueCount}
              </span>
            )}
          </div>

          {/* Nav Items List */}
          <nav className="flex-1 px-space-sm space-y-0.5 overflow-y-auto">
            {navItems.map(item => {
              const isActive = currentScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  aria-label={item.label}
                  className={`w-full flex items-center justify-between px-space-sm py-2 rounded text-left transition-colors ${
                    isActive
                      ? 'bg-primary text-on-primary font-medium shadow-xs'
                      : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                  }`}
                >
                  <div className="flex items-center gap-space-sm">
                    <span className="material-symbols-outlined text-lg" aria-hidden="true">{item.icon}</span>
                    <span className="font-body-sm text-body-sm">{item.label}</span>
                  </div>
                  {item.badge}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Engine Status Bottom Bar */}
        <div className="p-space-sm border-t border-outline-variant bg-surface-container-lowest space-y-space-xs">
          <div className="px-space-sm py-2 rounded bg-surface-container-low border border-outline-variant">
            <div className="flex items-center justify-between mb-1">
              <span className="font-label-caps text-label-caps text-on-surface-variant uppercase">
                Engine Status
              </span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-tertiary-container animate-pulse"></span>
                <span className="font-label-caps text-label-caps text-tertiary font-medium">Online</span>
              </span>
            </div>
            <div className="font-mono-sm text-mono-sm text-on-surface truncate">Scanner v4.2.8</div>
          </div>
          <div className="flex items-center justify-between pt-1 px-1">
            <button
              onClick={() => handleNavClick('evidence-center')}
              className="flex items-center gap-1 font-body-sm text-body-sm text-on-surface-variant hover:text-primary transition-colors"
            >
              <span className="material-symbols-outlined text-sm">menu_book</span>
              <span>Docs</span>
            </button>
            <span className="text-outline-variant">•</span>
            <button
              onClick={() => handleNavClick('evidence-center')}
              className="flex items-center gap-1 font-body-sm text-body-sm text-on-surface-variant hover:text-primary transition-colors"
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
