import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { fetchKillChains } from '../api/killChains';
import { KillChain } from '../api/types';
import { Link2, ArrowRight } from 'lucide-react';
import { SeverityBadge } from '../components/SeverityBadge';
import { ThreatClassBadge } from '../components/ThreatClassBadge';
import { AlertSidePanel } from '../components/AlertSidePanel';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { fetchAlertById } from '../api/alerts';

export const KillChains: React.FC = () => {
  const [searchParams] = useSearchParams();
  const highlightedId = searchParams.get('id');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['killChains'],
    queryFn: () => fetchKillChains(24),
  });

  const { data: selectedAlert } = useQuery({
    queryKey: ['alert', selectedAlertId],
    queryFn: () => fetchAlertById(selectedAlertId!),
    enabled: !!selectedAlertId,
  });

  if (isLoading && !data) {
    return <div className="h-full flex items-center justify-center text-sky-500 animate-pulse">Analyzing multi-stage threats...</div>;
  }

  if (isError) {
    return <div className="p-6 h-full"><ErrorState onRetry={() => refetch()} /></div>;
  }

  if (!data || data.chains.length === 0) {
    return <div className="p-6 h-full"><EmptyState message="No Multi-Stage Attacks" description="No correlated attack chains found in the current timeframe." /></div>;
  }

  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full overflow-y-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-zinc-100 flex items-center gap-3">
          <Link2 className="text-sky-500" size={32} />
          Kill Chain Timeline
        </h1>
        <p className="text-zinc-400 mt-2 font-mono text-sm">
          Correlated multi-stage attack progressions grouped by adversary IP
        </p>
      </div>

      <div className="flex flex-col gap-8">
        {data.chains.map((chain: KillChain) => (
          <div 
            key={chain.chain_id} 
            className={`panel p-6 flex flex-col gap-6 border-l-4 transition-all ${
              highlightedId === chain.chain_id ? 'bg-zinc-800' : ''
            }`}
            style={{ 
              borderLeftColor: chain.max_severity === 'critical' ? '#FF2A55' : 
                               chain.max_severity === 'high' ? '#FF6B00' : 
                               chain.max_severity === 'medium' ? '#FFC700' : '#00F0FF' 
            }}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="flex flex-col">
                  <span className="text-xs font-mono text-zinc-500 mb-1">ATTACKER IP</span>
                  <span className="font-mono text-amber-500 font-bold text-xl">{chain.src_ip}</span>
                </div>
                <div className="h-8 w-px bg-zinc-700 mx-2"></div>
                <div className="flex flex-col">
                  <span className="text-xs font-mono text-zinc-500 mb-1">TIME WINDOW</span>
                  <span className="font-mono text-zinc-300 text-sm">
                    {new Date(chain.first_seen).toLocaleTimeString()} → {new Date(chain.last_seen).toLocaleTimeString()}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-zinc-400 text-sm font-bold bg-zinc-950 px-3 py-1 rounded border border-zinc-800">
                  {chain.stage_count} STAGES
                </span>
                <SeverityBadge severity={chain.max_severity} />
              </div>
            </div>

            <div className="relative pt-8 pb-4 px-4 overflow-x-auto">
              <div className="absolute top-1/2 left-8 right-8 h-1 bg-zinc-800 -translate-y-1/2 z-0 rounded-full"></div>
              
              <div className="relative z-10 flex items-center justify-between min-w-max gap-12">
                {chain.stages.map((stage, idx) => (
                  <React.Fragment key={stage.alert_id}>
                    {idx > 0 && (
                      <div className="flex-1 flex justify-center text-zinc-600">
                        <ArrowRight size={20} />
                      </div>
                    )}
                    <div 
                      onClick={() => setSelectedAlertId(stage.alert_id)}
                      className={`flex flex-col items-center gap-3 cursor-pointer group bg-zinc-900 p-4 rounded-xl border-2 transition-all hover:-translate-y-1 ${
                        stage.severity === 'critical' ? 'border-rose-500 ' :
                        stage.severity === 'high' ? 'border-amber-500 ' :
                        stage.severity === 'medium' ? 'border-yellow-500 ' :
                        'border-sky-500 '
                      }`}
                    >
                      <div className="text-xs font-mono text-zinc-400">{new Date(stage.timestamp).toLocaleTimeString()}</div>
                      <ThreatClassBadge threatClass={stage.threat_class} className="shadow-none border-none bg-zinc-950" />
                      <div className="text-xs font-mono text-zinc-500 mt-1">
                        TARGET: <span className="text-sky-500">{stage.dst_ip}</span>{stage.dst_port > 0 ? `:${stage.dst_port}` : ''}
                      </div>
                    </div>
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      <AlertSidePanel 
        alert={selectedAlert || null} 
        onClose={() => setSelectedAlertId(null)} 
      />
    </div>
  );
};
