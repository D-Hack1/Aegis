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
    return (
      <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full gap-8">
        <div className="flex flex-col gap-2">
          <div className="skeleton h-10 w-64 rounded" />
          <div className="skeleton h-6 w-96 rounded" />
        </div>
        {[1,2,3].map(i => <div key={i} className="skeleton h-64 rounded-xl" />)}
      </div>
    );
  }

  if (isError) {
    return <div className="p-6 h-full"><ErrorState onRetry={() => refetch()} /></div>;
  }

  if (!data || data.chains.length === 0) {
    return <div className="p-6 h-full"><EmptyState message="No Multi-Stage Attacks" description="No correlated attack chains found in the current timeframe." /></div>;
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'var(--color-critical)';
      case 'high': return 'var(--color-high)';
      case 'medium': return 'var(--color-medium)';
      default: return 'var(--color-info)';
    }
  };

  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full overflow-y-auto animate-fade-in">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold flex items-center gap-2 mb-1" style={{ color: 'var(--color-text-primary)' }}>
          <Link2 size={24} style={{ color: 'var(--color-accent)' }} />
          Kill Chain Timeline
        </h1>
        <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Correlated multi-stage attack progressions grouped by adversary IP
        </p>
      </div>

      <div className="flex flex-col gap-8">
        {data.chains.map((chain: KillChain) => (
          <div 
            key={chain.chain_id} 
            className="panel p-6 flex flex-col gap-6 transition-all"
            style={{ 
              borderLeft: `4px solid ${getSeverityColor(chain.max_severity)}`,
              backgroundColor: highlightedId === chain.chain_id ? 'var(--color-surface-active)' : 'var(--color-surface)'
            }}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div className="flex flex-col">
                  <span className="text-xs font-medium mb-1" style={{ color: 'var(--color-text-secondary)' }}>Attacker IP</span>
                  <span className="font-mono font-semibold text-lg" style={{ color: 'var(--color-warning)' }}>{chain.src_ip}</span>
                </div>
                <div className="h-8 w-px" style={{ backgroundColor: 'var(--color-border)' }}></div>
                <div className="flex flex-col">
                  <span className="text-xs font-medium mb-1" style={{ color: 'var(--color-text-secondary)' }}>Time Window</span>
                  <span className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>
                    {new Date(chain.first_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} 
                    <span style={{ color: 'var(--color-text-muted)', margin: '0 4px' }}>→</span> 
                    {new Date(chain.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className="badge" style={{ backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}>
                  {chain.stage_count} STAGES
                </span>
                <SeverityBadge severity={chain.max_severity} />
              </div>
            </div>

            <div className="relative pt-10 pb-4 px-4 overflow-x-auto">
              <div 
                className="absolute top-1/2 left-8 right-8 h-0.5 -translate-y-1/2 z-0 rounded-full opacity-50"
                style={{ 
                  background: `linear-gradient(90deg, var(--color-border-strong) 0%, ${getSeverityColor(chain.max_severity)} 100%)` 
                }}
              ></div>
              
              <div className="relative z-10 flex items-center justify-between min-w-max gap-12">
                {chain.stages.map((stage, idx) => (
                  <React.Fragment key={stage.alert_id}>
                    {idx > 0 && (
                      <div className="flex-1 flex justify-center" style={{ color: 'var(--color-text-muted)' }}>
                        <ArrowRight size={18} />
                      </div>
                    )}
                    <div 
                      onClick={() => setSelectedAlertId(stage.alert_id)}
                      className="flex flex-col items-center gap-3 cursor-pointer p-4 rounded-xl transition-all hover:-translate-y-1"
                      style={{
                        backgroundColor: 'var(--color-bg)',
                        border: `2px solid ${getSeverityColor(stage.severity)}`,
                        boxShadow: `0 4px 12px rgba(0,0,0,0.1)`
                      }}
                    >
                      <div className="text-xs font-mono" style={{ color: 'var(--color-text-secondary)' }}>
                        {new Date(stage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </div>
                      <ThreatClassBadge threatClass={stage.threat_class} />
                      <div className="text-xs flex items-center gap-1 mt-1" style={{ color: 'var(--color-text-secondary)' }}>
                        Target: 
                        <span className="font-mono font-medium" style={{ color: 'var(--color-info)' }}>
                          {stage.dst_ip}{stage.dst_port > 0 ? `:${stage.dst_port}` : ''}
                        </span>
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
