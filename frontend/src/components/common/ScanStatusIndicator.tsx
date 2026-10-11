import React from 'react';

export type ScanStatusType = 'healthy' | 'at-risk' | 'vulnerable' | 'running' | 'synchronized';

interface ScanStatusIndicatorProps {
  status: ScanStatusType | string;
  label?: string;
  showIcon?: boolean;
}

export const ScanStatusIndicator: React.FC<ScanStatusIndicatorProps> = ({
  status,
  label,
  showIcon = true,
}) => {
  const norm = status.toLowerCase();

  let badgeColor = 'bg-slate-100 text-slate-700 border-slate-200';
  let dotColor = 'bg-slate-500';
  let defaultLabel = 'Unknown';
  let iconName = 'help_outline';

  if (norm === 'secure' || norm === 'healthy' || norm === 'synchronized' || norm === 'clean') {
    badgeColor = 'bg-emerald-50 text-emerald-700 border-emerald-200';
    dotColor = 'bg-emerald-500';
    defaultLabel = 'Healthy';
    iconName = 'verified_user';
  } else if (norm === 'at-risk' || norm === 'warning') {
    badgeColor = 'bg-amber-50 text-amber-700 border-amber-200';
    dotColor = 'bg-amber-500';
    defaultLabel = 'At Risk';
    iconName = 'warning_amber';
  } else if (norm === 'vulnerable' || norm === 'failed' || norm === 'error') {
    badgeColor = 'bg-red-50 text-red-700 border-red-200';
    dotColor = 'bg-red-500';
    defaultLabel = 'Vulnerable';
    iconName = 'error_outline';
  } else if (norm === 'running' || norm === 'scanning') {
    badgeColor = 'bg-blue-50 text-blue-700 border-blue-200';
    dotColor = 'bg-blue-500 animate-pulse';
    defaultLabel = 'Scanning';
    iconName = 'sync';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-mono-sm font-medium border ${badgeColor}`}
    >
      {showIcon ? (
        <span className="material-symbols-outlined text-[13px] leading-none" aria-hidden="true">
          {iconName}
        </span>
      ) : (
        <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} aria-hidden="true" />
      )}
      {label || defaultLabel}
    </span>
  );
};
