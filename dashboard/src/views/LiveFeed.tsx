import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAlerts } from '../api/alerts';
import { Alert } from '../api/types';
import { SeverityBadge } from '../components/SeverityBadge';
import { ThreatClassBadge } from '../components/ThreatClassBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { AlertSidePanel } from '../components/AlertSidePanel';
import { Search, Filter, Shield } from 'lucide-react';

export const LiveFeed: React.FC = () => {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [evidenceSearch, setEvidenceSearch] = useState<string>('');

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['alerts', 'live', evidenceSearch],
    queryFn: () =>
      fetchAlerts({
        page: 1,
        page_size: 50,
        ...(evidenceSearch ? { evidence: evidenceSearch } : {}),
      }),
    refetchInterval: 5000, // Poll every 5s
  });
  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-zinc-100 flex items-center gap-3">
            <Shield className="text-sky-500" size={32} />
            Live Alert Feed
          </h1>
          <p className="text-zinc-400 mt-2 font-mono text-sm">
            Real-time threat detection from Zeek & Kafka pipeline
          </p>
        </div>

        <div className="flex gap-4 items-center">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
            <input
              type="text"
              placeholder="Search IPs..."
              className="bg-zinc-900 border border-zinc-700 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-sky-500 transition-colors text-zinc-200"
            />
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
            <input
              type="text"
              placeholder="Search evidence..."
              value={evidenceSearch}
              onChange={(e) => setEvidenceSearch(e.target.value)}
              className="bg-zinc-900 border border-zinc-700 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-sky-500 transition-colors text-zinc-200"
            />
          </div>
          <button className="flex items-center gap-2 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2 text-sm hover:bg-zinc-800 transition-colors">
            <Filter size={16} />
            Filters
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {isLoading && !data ? (
          <div className="flex flex-col gap-4 animate-pulse">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-24 bg-zinc-900 rounded-xl border border-zinc-800"></div>
            ))}
          </div>
        ) : isError ? (
          <ErrorState onRetry={() => refetch()} />
        ) : !data || data.results.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="flex flex-col gap-4">
            {data.results.map((alert: Alert, index) => (
              <div
                key={alert.id}
                onClick={() => setSelectedAlert(alert)}
                className={`panel p-5 cursor-pointer flex items-center justify-between group animate-fade-in-up hover:glow-${alert.severity}`}
                style={{ animationDelay: `${index * 50}ms` }}
              >
                <div className="flex items-center gap-6">
                  <div className="flex flex-col gap-1 w-32">
                    <span className="text-xs text-zinc-500 font-mono">DETECTED</span>
                    <span className="text-sm font-mono text-zinc-300">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 min-w-[280px]">
                    <div className="text-right">
                      <div className="font-mono text-amber-500 font-bold">{alert.src_ip}</div>
                      <div className="text-xs text-zinc-500 font-mono">:{alert.src_port}</div>
                    </div>
                    <div className="w-8 h-px bg-zinc-700 relative">
                      <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1.5 h-1.5 border-t border-r border-zinc-600 transform rotate-45"></div>
                    </div>
                    <div>
                      <div className="font-mono text-sky-500 font-bold">{alert.dst_ip}</div>
                      <div className="text-xs text-zinc-500 font-mono">:{alert.dst_port}</div>
                    </div>
                  </div>

                  <ThreatClassBadge threatClass={alert.threat_class} />
                </div>

                <div className="flex items-center gap-8">
                  <div className="flex flex-col items-end">
                    <span className="text-xs text-zinc-500 font-mono mb-1">CONFIDENCE</span>
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-zinc-950 rounded-full h-1.5">
                        <div
                          className="bg-sky-500 h-1.5 rounded-full"
                          style={{ width: `${alert.confidence * 100}%` }}
                        ></div>
                      </div>
                      <span className="font-mono text-xs text-zinc-300">{(alert.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                  <SeverityBadge severity={alert.severity} className="w-24 text-center" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <AlertSidePanel
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  );
};
