import React from 'react';
import { Severity } from '../api/types';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  return (
    <span className={`badge badge-${severity} ${className}`}>
      {severity}
    </span>
  );
};
