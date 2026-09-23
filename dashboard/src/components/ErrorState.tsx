import React from 'react';
import { AlertOctagon } from 'lucide-react';

interface ErrorStateProps {
  message?: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({ 
  message = "Unable to reach API — check backend connection",
  onRetry 
}) => {
  return (
    <div 
      className="panel w-full h-64 flex flex-col items-center justify-center text-center p-8"
      style={{ borderColor: 'var(--color-critical-border)' }}
    >
      <div 
        className="w-14 h-14 rounded-full flex items-center justify-center mb-4"
        style={{ backgroundColor: 'var(--color-critical-bg)' }}
      >
        <AlertOctagon size={28} style={{ color: 'var(--color-critical)' }} />
      </div>
      <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>Connection Error</h3>
      <p className="text-sm max-w-md mb-6" style={{ color: 'var(--color-text-secondary)' }}>{message}</p>
      
      {onRetry && (
        <button 
          onClick={onRetry}
          className="btn btn-ghost"
        >
          Retry Connection
        </button>
      )}
    </div>
  );
};
