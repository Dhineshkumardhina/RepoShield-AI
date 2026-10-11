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
      repo: 'xerova/billing-service',
      time: '42m ago',
      type: 'error'
    },
    {
      id: 2,
      title: 'AST Taint Verified: Ready to Auto-Merge PR #418',
      repo: 'xerova/auth-gateway',
      time: '14m ago',
      type: 'success'
    },
    {
      id: 3,
      title: 'Trufflehog pre-commit secret block',
      repo: 'xerova/notification-hub',
      time: '2h ago',
      type: 'warning'
    }
  ];

  return (
    <header className="fixed top-0 left-0 lg:left-64 right-0 h-14 bg-surface-container-lowest border-b border-outline-variant z-40 flex items-center justify-between px-4 lg:px-gutter-desktop">
      {/* Left side: Hamburger for mobile + Search Input */}
      <div className="flex items-center gap-space-md flex-1 max-w-xl">
        <button
          onClick={onOpenMobileMenu}
          className="lg:hidden p-1.5 rounded hover:bg-surface-container text-on-surface-variant"
          aria-label="Open Navigation"
        >
          <span className="material-symbols-outlined text-2xl">menu</span>
        </button>

        <div className="relative w-full">
          <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant text-base">
            search
          </span>
          <input
            ref={searchInputRef}
            value={searchQuery}
            onChange={e => onSearchChange(e.target.value)}
            className="w-full pl-9 pr-10 py-1.5 bg-surface-container-low border border-outline-variant rounded font-mono-md text-mono-md text-on-surface placeholder:text-outline focus:outline-none focus:border-primary focus:bg-surface-container-lowest transition-all"
            placeholder="Search CVE, repo, commit, or finding ID... / for shortcut"
            type="text"
          />
          <kbd className="hidden sm:inline-block absolute right-2.5 top-1/2 -translate-y-1/2 font-label-caps text-label-caps px-1 py-0.5 rounded bg-surface-container-high text-on-surface-variant border border-outline-variant">
            /
          </kbd>
        </div>
      </div>

      {/* Right side: Backend Health, Region Selector, Trigger Scan, Notifications, Profile */}
      <div className="flex items-center gap-2 sm:gap-space-md">
        {/* API Health Pill */}
        <div
          className={`hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-mono-sm transition-colors ${
            backendStatus === 'connected'
              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : backendStatus === 'checking'
              ? 'bg-amber-50 text-amber-700 border-amber-200'
              : 'bg-rose-50 text-rose-700 border-rose-200'
          }`}
          title={backendMeta || 'FastAPI backend connection'}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              backendStatus === 'connected'
                ? 'bg-emerald-500 animate-pulse'
                : backendStatus === 'checking'
                ? 'bg-amber-500'
                : 'bg-rose-500'
            }`}
          />
          <span className="font-medium">
            {backendStatus === 'connected' ? 'API: Connected' : backendStatus === 'checking' ? 'API: Checking...' : 'API: Offline'}
          </span>
        </div>

        {/* Region selector */}
        <div className="relative hidden sm:block">
          <button
            onClick={() => setShowRegionDropdown(!showRegionDropdown)}
            className="flex items-center gap-space-xs px-2 py-1 rounded border border-outline-variant bg-surface-container-low hover:bg-surface-container text-on-surface transition-colors"
          >
            <span className="material-symbols-outlined text-on-surface-variant text-sm">dns</span>
            <span className="font-mono-md text-mono-md font-medium">{region}</span>
            <span className="material-symbols-outlined text-on-surface-variant text-xs">arrow_drop_down</span>
          </button>

          {showRegionDropdown && (
            <div className="absolute right-0 mt-1 w-44 bg-surface-container-lowest border border-outline-variant rounded shadow-lg z-50 py-1 font-mono-sm">
              {['us-east-prod-01', 'eu-west-prod-01', 'ap-southeast-01'].map(r => (
                <button
                  key={r}
                  onClick={() => {
                    setRegion(r);
                    setShowRegionDropdown(false);
                  }}
                  className={`w-full text-left px-3 py-1.5 hover:bg-surface-container transition-colors ${
                    region === r ? 'font-bold text-primary bg-surface-container-low' : 'text-on-surface'
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
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-on-primary font-body-sm text-body-sm font-medium hover:bg-on-primary-fixed-variant transition-colors shadow-xs"
        >
          <span className="material-symbols-outlined text-base">bolt</span>
          <span className="hidden sm:inline">Trigger Scan</span>
        </button>

        <div className="h-4 w-px bg-outline-variant hidden sm:block"></div>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              if (unreadCount > 0) setUnreadCount(0);
            }}
            className="relative p-1.5 rounded hover:bg-surface-container text-on-surface-variant hover:text-on-surface transition-colors"
            title="Active Security Notifications"
          >
            <span className="material-symbols-outlined text-xl">notifications</span>
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 flex items-center justify-center min-w-[14px] h-[14px] px-0.5 text-[9px] font-mono-sm font-bold bg-error text-on-error rounded-full">
                {unreadCount}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-1 w-80 bg-surface-container-lowest border border-outline-variant rounded shadow-lg z-50 overflow-hidden animate-in fade-in duration-100">
              <div className="p-3 border-b border-outline-variant bg-surface-container-low flex items-center justify-between">
                <span className="font-label-caps text-on-surface uppercase font-semibold">
                  Live Security Alerts
                </span>
                <span className="font-mono-sm text-primary text-xs font-semibold">3 New</span>
              </div>
              <div className="divide-y divide-outline-variant max-h-72 overflow-y-auto">
                {alerts.map(a => (
                  <div key={a.id} className="p-3 hover:bg-surface-container-low transition-colors text-left">
                    <div className="flex items-center justify-between font-mono-sm text-[11px] mb-0.5">
                      <span className="font-bold text-on-surface truncate">{a.repo}</span>
                      <span className="text-outline shrink-0">{a.time}</span>
                    </div>
                    <p className="font-body-sm text-xs text-on-surface-variant">{a.title}</p>
                  </div>
                ))}
              </div>
              <div className="p-2 border-t border-outline-variant text-center bg-surface-container-lowest">
                <button
                  onClick={() => setShowNotifications(false)}
                  className="font-mono-sm text-xs text-primary font-medium hover:underline"
                >
                  View All Telemetry Events
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Profile */}
        <div className="flex items-center gap-space-sm pl-space-xs">
          <img
            alt="Dr. Sarah Jenkins Profile"
            className="w-8 h-8 rounded-full object-cover border border-outline-variant"
            src="https://lh3.googleusercontent.com/aida-public/AB6AXuApgniuqkV6xUCmpqwEdn7CZ6mDxtnTkTx80rH4U4FE7achytd2w1jq8fZ8dsurIkegyI8Q5YuHt_Ojy4i3gRpw_FRfOzqOrURpBztYzzv4fEJ3nnvvGZ0gUDQg7Kj_6NDysBzjI_tJNLYY4qOkTtbeZYaA8PLPWLmipUe6h-TUP7j-WoeHO3pqjZHzAmaJTkr7jvS5Dr6uwPJ1C4Iwroisv9t7cAdDUWDbOKCB4tm8kc6nSYcHT0MYWg"
          />
          <div className="hidden xl:flex flex-col text-left leading-tight">
            <span className="font-body-sm text-body-sm font-semibold text-on-surface">
              Dr. Sarah Jenkins
            </span>
            <span className="font-label-caps text-label-caps text-on-surface-variant">
              Lead AppSec Eng
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
