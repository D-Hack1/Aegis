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
    <div className="panel w-full h-64 flex flex-col items-center justify-center text-center p-8">
      <div 
        className="w-14 h-14 rounded-full flex items-center justify-center mb-4"
        style={{ backgroundColor: 'var(--color-info-bg)' }}
      >
        <ShieldCheck size={28} style={{ color: 'var(--color-info)' }} />
      </div>
      <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>{message}</h3>
      <p className="text-sm max-w-md" style={{ color: 'var(--color-text-secondary)' }}>{description}</p>
    </div>
  );
};
