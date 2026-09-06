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
    <div className="w-full h-64 flex flex-col items-center justify-center text-center panel border-rose-500/30 p-8">
      <div className="w-16 h-16 rounded-full bg-rose-500/10 flex items-center justify-center mb-4">
        <AlertOctagon size={32} className="text-rose-500" />
      </div>
      <h3 className="text-xl font-bold text-zinc-100 mb-2">Connection Error</h3>
      <p className="text-zinc-400 max-w-md mb-6">{message}</p>
      
      {onRetry && (
        <button 
          onClick={onRetry}
          className="px-6 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 rounded-lg text-zinc-200 transition-colors"
        >
          Retry Connection
        </button>
      )}
    </div>
  );
};
