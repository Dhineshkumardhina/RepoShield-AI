import React from 'react';

interface DataSourceBadgeProps {
  isLive: boolean;
  className?: string;
}

export const DataSourceBadge: React.FC<DataSourceBadgeProps> = ({ isLive, className = '' }) => {
  return isLive ? (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 ${className}`}
      title="This record is stored in and retrieved directly from the live database"
    >
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" aria-hidden="true" />
      Live
    </span>
  ) : (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-100 text-slate-600 border border-slate-200 ${className}`}
      title="Synthetic evaluation fixture"
    >
      <span className="material-symbols-outlined text-[11px]" aria-hidden="true">science</span>
      Fixture
    </span>
  );
};
