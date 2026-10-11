import React from 'react';

export type SeverityLevel = 'CRITICAL' | 'critical' | 'HIGH' | 'high' | 'MEDIUM' | 'medium' | 'LOW' | 'low';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '', size = 'md' }) => {
  const norm = severity.toUpperCase();

  const configs: Record<string, { bg: string; text: string; border: string; dot: string; label: string }> = {
    CRITICAL: {
      bg: 'bg-red-50',
      text: 'text-red-700',
      border: 'border-red-200',
      dot: 'bg-red-600',
      label: 'Critical',
    },
    HIGH: {
      bg: 'bg-orange-50',
      text: 'text-orange-700',
      border: 'border-orange-200',
      dot: 'bg-orange-600',
      label: 'High',
    },
    MEDIUM: {
      bg: 'bg-amber-50',
      text: 'text-amber-700',
      border: 'border-amber-200',
      dot: 'bg-amber-600',
      label: 'Medium',
    },
    LOW: {
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
      dot: 'bg-blue-600',
      label: 'Low',
    },
  };

  const current = configs[norm] || configs.LOW;
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded font-mono-sm font-semibold border ${current.bg} ${current.text} ${current.border} ${sizeClasses} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot}`} aria-hidden="true" />
      {current.label}
    </span>
  );
};
