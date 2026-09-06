import React from 'react';
import { ThreatClass, THREAT_CLASS_LABELS } from '../api/types';
import { ShieldAlert, Radio, Search, LockOpen, Network, FileDown, AlertTriangle, ShieldCheck } from 'lucide-react';

interface ThreatClassBadgeProps {
  threatClass: ThreatClass;
  className?: string;
}

const getIcon = (threat: ThreatClass, size = 14) => {
  switch (threat) {
    case 'ddos': return <Network size={size} />;
    case 'c2_beaconing': return <Radio size={size} />;
    case 'dns_anomaly': return <Search size={size} />;
    case 'malware_tls': return <LockOpen size={size} />;
    case 'port_scan': return <ShieldAlert size={size} />;
    case 'exfiltration': return <FileDown size={size} />;
    case 'unknown_anomaly': return <AlertTriangle size={size} />;
    case 'benign': return <ShieldCheck size={size} />;
  }
};

export const ThreatClassBadge: React.FC<ThreatClassBadgeProps> = ({ threatClass, className = '' }) => {
  return (
    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-zinc-800/80 border border-zinc-700 text-zinc-200 text-sm ${className}`}>
      <span className="text-sky-500">{getIcon(threatClass)}</span>
      <span>{THREAT_CLASS_LABELS[threatClass]}</span>
    </div>
  );
};
