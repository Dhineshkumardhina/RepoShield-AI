import React, { useState } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { Header } from './Header';
import { useAuth } from '../../context/AuthContext';

export interface AppLayoutProps {
  children: React.ReactNode;
  onTriggerScan?: () => void;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ children, onTriggerScan }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const navItems = [
    {
      path: '/dashboard',
      label: 'Dashboard',
      icon: 'dashboard',
    },
    {
      path: '/repositories',
      label: 'Repositories',
      icon: 'folder_code',
      badge: '42',
    },
    {
      path: '/findings',
      label: 'Findings',
      icon: 'security_update_warning',
      badge: '14',
      badgeColor: 'bg-red-100 text-red-700',
    },
    {
      path: '/verification',
      label: 'Fix Verification',
      icon: 'task_alt',
      badge: 'QUEUE: 8',
      badgeColor: 'bg-emerald-100 text-emerald-800',
    },
    {
      path: '/evidence',
      label: 'Evidence Center',
      icon: 'fact_check',
    },
    {
      path: '/analyzer',
      label: 'AI Analyst Lab',
      icon: 'psychology',
      badge: 'GEMINI',
      badgeColor: 'bg-blue-100 text-blue-800',
    },
    {
      path: '/settings',
      label: 'Settings',
      icon: 'settings',
    },
  ];

  const handleSignOut = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 antialiased flex flex-col">
      {/* Mobile Backdrop */}
      {isMobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/50 backdrop-blur-xs lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Persistent Enterprise Sidebar */}
      <aside
        className={`fixed left-0 top-0 h-screen w-64 bg-white border-r border-slate-200 z-50 flex flex-col justify-between select-none transition-transform duration-200 ease-in-out ${
          isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="flex flex-col flex-1 min-h-0">
          {/* Brand Header */}
          <div className="h-14 px-4 border-b border-slate-200 flex items-center justify-between bg-white">
            <Link to="/dashboard" className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs">
                <span className="material-symbols-outlined text-xl">shield</span>
              </div>
              <div className="flex flex-col">
                <span className="font-headline-sm text-sm font-bold text-slate-900 tracking-tight leading-none">
                  RepoShield AI
                </span>
                <span className="font-label-caps text-[10px] text-slate-500 uppercase mt-0.5 font-medium">
                  by Xerova
                </span>
              </div>
            </Link>
            <span className="font-mono-sm text-[10px] font-semibold px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
              APPSEC
            </span>
          </div>

          {/* Workspace Switcher */}
          <div className="p-2 border-b border-slate-200 bg-white">
            <div className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg border border-slate-200 bg-slate-50 text-left">
              <div className="flex items-center gap-2 min-w-0">
                <span className="material-symbols-outlined text-blue-600 text-base">hub</span>
                <div className="flex flex-col min-w-0">
                  <span className="font-label-caps text-[9px] text-slate-500 uppercase">
                    Workspace
                  </span>
                  <span className="font-mono-md text-xs text-slate-800 truncate font-semibold">
                    {user?.organization || 'Xerova Production CI/CD'}
                  </span>
                </div>
              </div>
              <span className="material-symbols-outlined text-slate-400 text-sm">unfold_more</span>
            </div>
          </div>

          {/* Navigation Items */}
          <div className="px-4 pt-3 pb-1 flex items-center justify-between">
            <span className="font-label-caps text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
              Platform Navigation
            </span>
          </div>

          <nav className="flex-1 px-2 space-y-0.5 overflow-y-auto">
            {navItems.map(item => {
              const isActive = location.pathname === item.path || (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
              return (
                <button
                  key={item.path}
                  type="button"
                  onClick={() => {
                    navigate(item.path);
                    setIsMobileMenuOpen(false);
                  }}
                  aria-label={item.label}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-left transition-colors text-sm ${
                    isActive
                      ? 'bg-blue-600 text-white font-semibold shadow-xs'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 font-medium'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`material-symbols-outlined text-lg ${isActive ? 'text-white' : 'text-slate-500'}`}
                      aria-hidden="true"
                    >
                      {item.icon}
                    </span>
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`font-mono-sm text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                        isActive ? 'bg-blue-700 text-white' : item.badgeColor || 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Session Footer & Sign Out */}
        <div className="p-3 border-t border-slate-200 bg-slate-50/60 space-y-2">
          <div className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-white border border-slate-200 shadow-2xs">
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-7 h-7 rounded-full bg-slate-200 text-slate-700 font-bold flex items-center justify-center text-xs shrink-0">
                {user?.fullName ? user.fullName.charAt(0) : 'U'}
              </div>
              <div className="flex flex-col min-w-0 leading-tight">
                <span className="font-semibold text-xs text-slate-900 truncate">
                  {user?.fullName || 'Security Analyst'}
                </span>
                <span className="font-mono-sm text-[10px] text-slate-500 truncate">
                  {user?.role || 'Operator'}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={handleSignOut}
              title="Sign Out Session"
              aria-label="Sign Out"
              className="p-1 rounded text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors"
            >
              <span className="material-symbols-outlined text-base">logout</span>
            </button>
          </div>

          <div className="px-2 py-1 text-center">
            <span className="font-mono-sm text-[10px] text-slate-400 block">
              RepoShield Engine v0.1.0 • Dev
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="lg:pl-64 flex flex-col flex-1 min-h-screen">
        {/* Top Navigation Bar */}
        <Header
          onOpenMobileMenu={() => setIsMobileMenuOpen(true)}
          onTriggerScan={onTriggerScan || (() => navigate('/repositories'))}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
        />

        {/* Dynamic Screen View */}
        <main className="relative pt-14 flex-1">
          {children}
        </main>
      </div>
    </div>
  );
};
