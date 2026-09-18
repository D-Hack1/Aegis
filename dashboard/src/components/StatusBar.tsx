import React, { useEffect, useState } from 'react';
import { fetchHealth } from '../api/health';
import { HealthResponse } from '../api/types';
import { Server, Database } from 'lucide-react';

export const StatusBar: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const check = async () => {
      try {
        const data = await fetchHealth();
        setHealth(data);
      } catch (error) {
        console.error("Health check failed", error);
        setHealth(null);
      }
    };
    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status?: string) => {
    if (!status) return 'bg-rose-500'; // offline
    if (status === 'ok') return 'bg-emerald-500';
    return 'bg-yellow-500';
  };

  return (
    <div className="h-14 border-b border-zinc-700 bg-zinc-950/90 backdrop-blur flex items-center justify-between px-6 z-10 w-full">
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2">
          <div className={`w-2.5 h-2.5 rounded-full animate-pulse ${getStatusColor(health?.status)}`}></div>
          <span className="text-sm font-mono text-zinc-300">
            SYSTEM: {health?.status?.toUpperCase() || 'OFFLINE'}
          </span>
        </div>
        
        {health?.kafka && (
          <div className="flex items-center gap-2 border-l border-zinc-800 pl-6">
            <Server size={14} className="text-zinc-500" />
            <span className="text-xs font-mono text-zinc-400">KAFKA: {health.kafka.status.toUpperCase()}</span>
          </div>
        )}
        
        {health?.elasticsearch && (
          <div className="flex items-center gap-2 border-l border-zinc-800 pl-6">
            <Database size={14} className="text-zinc-500" />
            <span className="text-xs font-mono text-zinc-400">ES: {health.elasticsearch.status.toUpperCase()}</span>
          </div>
        )}
      </div>
      
      <div className="font-mono text-xs text-zinc-500">
        UPTIME: {health?.uptime_seconds ? Math.floor(health.uptime_seconds / 60) + 'm' : '--'}
      </div>
    </div>
  );
};
