import React from 'react';

interface EmptyStateProps {
  icon?: string;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon = 'inbox',
  title,
  description,
  actionLabel,
  onAction,
  className = '',
}) => {
  return (
    <div className={`flex flex-col items-center justify-center p-8 text-center bg-white border border-dashed border-slate-200 rounded-xl ${className}`}>
      <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center text-slate-500 mb-3">
        <span className="material-symbols-outlined text-2xl">{icon}</span>
      </div>
      <h3 className="text-base font-semibold text-slate-800">{title}</h3>
      <p className="mt-1 text-sm text-slate-500 max-w-md">{description}</p>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-xs transition-colors flex items-center gap-1.5"
        >
          <span className="material-symbols-outlined text-sm">add</span>
          <span>{actionLabel}</span>
        </button>
      )}
    </div>
  );
};

export const LoadingState: React.FC<{ message?: string; className?: string }> = ({
  message = 'Loading security data...',
  className = '',
}) => {
  return (
    <div className={`flex flex-col items-center justify-center p-12 text-center ${className}`}>
      <div className="w-8 h-8 border-3 border-blue-600/20 border-t-blue-600 rounded-full animate-spin mb-3" />
      <p className="text-xs font-mono-sm text-slate-500 font-medium">{message}</p>
    </div>
  );
};

export const ErrorMessage: React.FC<{
  title?: string;
  message: string;
  requestId?: string;
  onRetry?: () => void;
  className?: string;
}> = ({
  title = 'API Operation Failed',
  message,
  requestId,
  onRetry,
  className = '',
}) => {
  return (
    <div className={`p-4 rounded-xl bg-red-50/70 border border-red-200 text-left ${className}`}>
      <div className="flex items-start gap-3">
        <span className="material-symbols-outlined text-red-600 text-xl shrink-0 mt-0.5">
          error
        </span>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold text-red-900">{title}</h4>
          <p className="mt-0.5 text-xs text-red-800 leading-relaxed break-words">{message}</p>
          {requestId && (
            <p className="mt-1 font-mono-sm text-[10px] text-red-600">
              Trace Request ID: <span className="font-semibold">{requestId}</span>
            </p>
          )}
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="px-2.5 py-1 text-xs font-medium bg-white border border-red-300 text-red-700 hover:bg-red-50 rounded transition-colors shrink-0"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
};
