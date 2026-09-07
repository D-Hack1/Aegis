import React from 'react';
import { Severity, SEVERITY_COLOURS } from '../api/types';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  return (
    <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider ${SEVERITY_COLOURS[severity]} ${className}`}>
      {severity}
    </span>
  );
};
