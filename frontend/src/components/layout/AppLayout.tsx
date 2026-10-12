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
      badgeColor: 'bg-rose-50 text-rose-700 border border-rose-200',
    },
    {
      path: '/verification',
      label: 'Fix Verification',
      icon: 'task_alt',
      badge: 'Queue: 8',
      badgeColor: 'bg-emerald-50 text-emerald-800 border border-emerald-200',
    },
    {
      path: '/evidence',
      label: 'Evidence Center',
      icon: 'fact_check',
    },
    {
      path: '/analyzer',
      label: 'Patch Analyzer',
      icon: 'code_blocks',
      badge: 'Beta',
      badgeColor: 'bg-slate-100 text-slate-700 border border-slate-200',
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
    <div className="min-h-screen bg-slate-50 text-slate-900 antialiased flex flex-col font-sans">
      {/* Mobile Backdrop */}
      {isMobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/40 backdrop-blur-xs lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Persistent Clean Enterprise Sidebar */}
      <aside
        className={`fixed left-0 top-0 h-screen w-64 bg-white border-r border-slate-200 z-50 flex flex-col justify-between select-none transition-transform duration-200 ease-in-out ${
          isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="flex flex-col flex-1 min-h-0">
          {/* Brand Header */}
          <div className="h-14 px-4 border-b border-slate-200 flex items-center justify-between bg-white">
            <Link to="/dashboard" className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-md bg-slate-900 flex items-center justify-center text-white">
                <span className="material-symbols-outlined text-xl">shield</span>
              </div>
              <div className="flex flex-col">
                <span className="font-semibold text-sm text-slate-900 tracking-tight leading-none">
                  RepoShield AI
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5 font-medium">
                  Fix Verification
                </span>
              </div>
            </Link>
            <span className="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              DevSecOps
            </span>
          </div>

          {/* Workspace Switcher */}
          <div className="p-2 border-b border-slate-200 bg-white">
            <div className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-md border border-slate-200 bg-slate-50 text-left">
              <div className="flex items-center gap-2 min-w-0">
                <span className="material-symbols-outlined text-slate-700 text-base">hub</span>
                <div className="flex flex-col min-w-0">
                  <span className="text-[9px] text-slate-500 uppercase font-medium">
                    Workspace
                  </span>
                  <span className="font-mono text-xs text-slate-800 truncate font-semibold">
                    {user?.organization || 'Production CI/CD'}
                  </span>
                </div>
              </div>
              <span className="material-symbols-outlined text-slate-400 text-sm">unfold_more</span>
            </div>
          </div>

          {/* Navigation Items */}
          <div className="px-3 pt-3 pb-1 flex items-center justify-between">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
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
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-left transition-colors text-sm ${
                    isActive
                      ? 'bg-slate-900 text-white font-medium shadow-2xs'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 font-normal'
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
                      className={`font-mono text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        isActive ? 'bg-slate-800 text-slate-200' : item.badgeColor || 'bg-slate-100 text-slate-600'
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
          <div className="flex items-center justify-between px-2 py-1.5 rounded-md bg-white border border-slate-200">
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-7 h-7 rounded bg-slate-200 text-slate-700 font-semibold flex items-center justify-center text-xs shrink-0">
                {user?.fullName ? user.fullName.charAt(0) : 'U'}
              </div>
              <div className="flex flex-col min-w-0 leading-tight">
                <span className="font-medium text-xs text-slate-900 truncate">
                  {user?.fullName || 'Security Analyst'}
                </span>
                <span className="font-mono text-[10px] text-slate-500 truncate">
                  {user?.role || 'Operator'}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={handleSignOut}
              title="Sign Out Session"
              aria-label="Sign Out"
              className="p-1 rounded text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
            >
              <span className="material-symbols-outlined text-base">logout</span>
            </button>
          </div>

          <div className="px-2 py-1 text-center">
            <span className="font-mono text-[10px] text-slate-400 block">
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
