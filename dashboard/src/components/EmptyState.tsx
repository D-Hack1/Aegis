import React from 'react';
import { ShieldCheck } from 'lucide-react';

interface EmptyStateProps {
  message?: string;
  description?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ 
  message = "Network traffic is clean", 
  description = "No anomalies or threats detected in the current window." 
}) => {
  return (
    <div className="w-full h-64 flex flex-col items-center justify-center text-center panel p-8">
      <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center mb-4">
        <ShieldCheck size={32} className="text-emerald-500" />
      </div>
      <h3 className="text-xl font-bold text-zinc-100 mb-2">{message}</h3>
      <p className="text-zinc-400 max-w-md">{description}</p>
    </div>
  );
};
