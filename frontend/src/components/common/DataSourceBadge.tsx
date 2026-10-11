import React from 'react';

interface DataSourceBadgeProps {
  isLive: boolean;
  className?: string;
}

export const DataSourceBadge: React.FC<DataSourceBadgeProps> = ({ isLive, className = '' }) => {
  return isLive ? (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono-sm font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 ${className}`}
      title="This record is stored in and retrieved directly from the live database"
    >
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" aria-hidden="true" />
      LIVE BACKEND
    </span>
  ) : (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono-sm font-semibold bg-slate-100 text-slate-600 border border-slate-200 ${className}`}
      title="This is an isolated synthetic evaluation sample for preview & test harness"
    >
      <span className="material-symbols-outlined text-[11px]" aria-hidden="true">science</span>
      SANDBOX DEMO
    </span>
  );
};
