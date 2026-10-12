import React, { useState, useRef, useEffect } from 'react';

interface HeaderProps {
  onOpenMobileMenu: () => void;
  onTriggerScan: () => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenMobileMenu,
  onTriggerScan,
  searchQuery,
  onSearchChange
}) => {
  const [region, setRegion] = useState('us-east-prod-01');
  const [showRegionDropdown, setShowRegionDropdown] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [unreadCount, setUnreadCount] = useState(3);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Backend Health State
  const [backendStatus, setBackendStatus] = useState<'checking' | 'connected' | 'offline'>('checking');
  const [backendMeta, setBackendMeta] = useState<string>('');

  useEffect(() => {
    let mounted = true;
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/v1/health');
        if (res.ok) {
          const data = await res.json();
          if (mounted) {
            setBackendStatus('connected');
            setBackendMeta(`${data.service} v${data.version} (${data.database?.dialect || 'db'})`);
          }
        } else {
          if (mounted) setBackendStatus('offline');
        }
      } catch {
        if (mounted) setBackendStatus('offline');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  // Keyboard shortcut '/' to focus search input
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement !== searchInputRef.current) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const alerts = [
    {
      id: 1,
      title: 'Regression Detected in PR #402',
      repo: 'billing-service',
      time: '42m ago',
      type: 'error'
    },
    {
      id: 2,
      title: 'Fix Verified: Safe to Merge PR #418',
      repo: 'auth-gateway',
      time: '14m ago',
      type: 'success'
    },
    {
      id: 3,
      title: 'Secret Detected in Staging Branch',
      repo: 'notification-hub',
      time: '2h ago',
      type: 'warning'
    }
  ];

  return (
    <header className="fixed top-0 left-0 lg:left-64 right-0 h-14 bg-white border-b border-slate-200 z-40 flex items-center justify-between px-4 lg:px-8">
      {/* Left side: Hamburger for mobile + Search Input */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
        <button
          onClick={onOpenMobileMenu}
          className="lg:hidden p-1.5 rounded hover:bg-slate-100 text-slate-500"
          aria-label="Open Navigation"
        >
          <span className="material-symbols-outlined text-2xl">menu</span>
        </button>

        <div className="relative w-full">
          <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-base">
            search
          </span>
          <input
            ref={searchInputRef}
            value={searchQuery}
            onChange={e => onSearchChange(e.target.value)}
            className="w-full pl-9 pr-10 py-1.5 bg-slate-50 border border-slate-200 rounded-md font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 focus:bg-white transition-all"
            placeholder="Search CVE, repository, or finding... Press / to focus"
            type="text"
          />
          <kbd className="hidden sm:inline-block absolute right-2.5 top-1/2 -translate-y-1/2 font-mono text-[10px] px-1 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
            /
          </kbd>
        </div>
      </div>

      {/* Right side: Backend Health, Region Selector, Trigger Scan, Notifications, Profile */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* API Health Pill */}
        <div
          className={`hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-mono transition-colors ${
            backendStatus === 'connected'
              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : backendStatus === 'checking'
              ? 'bg-amber-50 text-amber-700 border-amber-200'
              : 'bg-rose-50 text-rose-700 border-rose-200'
          }`}
          title={backendMeta || 'FastAPI backend connection'}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              backendStatus === 'connected'
                ? 'bg-emerald-600'
                : backendStatus === 'checking'
                ? 'bg-amber-500'
                : 'bg-rose-500'
            }`}
          />
          <span className="font-medium text-[11px]">
            {backendStatus === 'connected' ? 'API Connected' : backendStatus === 'checking' ? 'Connecting...' : 'API Offline'}
          </span>
        </div>

        {/* Region selector */}
        <div className="relative hidden sm:block">
          <button
            onClick={() => setShowRegionDropdown(!showRegionDropdown)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs transition-colors"
          >
            <span className="material-symbols-outlined text-slate-500 text-sm">dns</span>
            <span className="font-mono text-xs">{region}</span>
            <span className="material-symbols-outlined text-slate-400 text-xs">arrow_drop_down</span>
          </button>

          {showRegionDropdown && (
            <div className="absolute right-0 mt-1 w-44 bg-white border border-slate-200 rounded-md shadow-lg z-50 py-1 font-mono text-xs">
              {['us-east-prod-01', 'eu-west-prod-01', 'ap-southeast-01'].map(r => (
                <button
                  key={r}
                  onClick={() => {
                    setRegion(r);
                    setShowRegionDropdown(false);
                  }}
                  className={`w-full text-left px-3 py-1.5 hover:bg-slate-50 transition-colors ${
                    region === r ? 'font-semibold text-slate-900 bg-slate-50' : 'text-slate-600'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Trigger Scan CTA */}
        <button
          onClick={onTriggerScan}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 transition-colors shadow-2xs"
        >
          <span className="material-symbols-outlined text-sm">radar</span>
          <span className="hidden sm:inline">Run Scan</span>
        </button>

        <div className="h-4 w-px bg-slate-200 hidden sm:block" />

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              if (unreadCount > 0) setUnreadCount(0);
            }}
            className="relative p-1.5 rounded-md hover:bg-slate-100 text-slate-500 hover:text-slate-800 transition-colors"
            title="Notifications"
          >
            <span className="material-symbols-outlined text-xl">notifications</span>
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 flex items-center justify-center min-w-[14px] h-[14px] px-0.5 text-[9px] font-mono font-bold bg-rose-600 text-white rounded-full">
                {unreadCount}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-1 w-80 bg-white border border-slate-200 rounded-md shadow-lg z-50 overflow-hidden">
              <div className="p-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-900 uppercase tracking-wide">
                  Security Alerts
                </span>
                <span className="font-mono text-slate-500 text-xs font-medium">3 New</span>
              </div>
              <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto">
                {alerts.map(a => (
                  <div key={a.id} className="p-3 hover:bg-slate-50 transition-colors text-left">
                    <div className="flex items-center justify-between font-mono text-[11px] mb-0.5">
                      <span className="font-semibold text-slate-800 truncate">{a.repo}</span>
                      <span className="text-slate-400 shrink-0">{a.time}</span>
                    </div>
                    <p className="text-xs text-slate-600">{a.title}</p>
                  </div>
                ))}
              </div>
              <div className="p-2 border-t border-slate-100 text-center bg-slate-50">
                <button
                  onClick={() => setShowNotifications(false)}
                  className="font-mono text-xs text-slate-700 font-medium hover:underline"
                >
                  Dismiss Alerts
                </button>
              </div>
            </div>
          )}
        </div>

        {/* User Badge */}
        <div className="flex items-center gap-2 pl-1">
          <div className="w-7 h-7 rounded bg-slate-200 text-slate-700 font-semibold flex items-center justify-center text-xs">
            S
          </div>
          <div className="hidden xl:flex flex-col text-left leading-tight">
            <span className="text-xs font-medium text-slate-900">
              SecOps Engineer
            </span>
            <span className="text-[10px] text-slate-500 font-mono">
              Production
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
