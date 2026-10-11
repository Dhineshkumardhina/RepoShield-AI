import React from 'react';

export type VerificationState = 'verified' | 'failed' | 'inconclusive' | 'clean' | 'running' | 'pending' | 'merged';

interface StatusBadgeProps {
  status: VerificationState | string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  const norm = status.toLowerCase();

  const configs: Record<string, { bg: string; text: string; border: string; icon: string; label: string }> = {
    verified: {
      bg: 'bg-emerald-50',
      text: 'text-emerald-700',
      border: 'border-emerald-200',
      icon: 'verified',
      label: 'Verified Patch',
    },
    merged: {
      bg: 'bg-purple-50',
      text: 'text-purple-700',
      border: 'border-purple-200',
      icon: 'call_merge',
      label: 'Merged into Main',
    },
    failed: {
      bg: 'bg-red-50',
      text: 'text-red-700',
      border: 'border-red-200',
      icon: 'dangerous',
      label: 'Regression Detected',
    },
    inconclusive: {
      bg: 'bg-amber-50',
      text: 'text-amber-700',
      border: 'border-amber-200',
      icon: 'help_outline',
      label: 'Inconclusive / Timeout',
    },
    clean: {
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
      icon: 'shield',
      label: 'No Patch Needed',
    },
    running: {
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
      icon: 'sync',
      label: 'Sandbox Replaying',
    },
    pending: {
      bg: 'bg-slate-100',
      text: 'text-slate-700',
      border: 'border-slate-200',
      icon: 'hourglass_empty',
      label: 'Pending Gate',
    },
  };

  const current = configs[norm] || configs.pending;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono-sm text-xs font-semibold border ${current.bg} ${current.text} ${current.border} ${className}`}
    >
      <span className="material-symbols-outlined text-[14px]" aria-hidden="true">
        {current.icon}
      </span>
      {current.label}
    </span>
  );
};
