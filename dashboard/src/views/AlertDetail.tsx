import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { fetchAlertById } from '../api/alerts';
import { ArrowLeft, ShieldAlert, Zap, Lock, Search } from 'lucide-react';
import { SeverityBadge } from '../components/SeverityBadge';
import { ThreatClassBadge } from '../components/ThreatClassBadge';
import { ErrorState } from '../components/ErrorState';

export const AlertDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const { data: alert, isLoading, isError, refetch } = useQuery({
    queryKey: ['alert', id],
    queryFn: () => fetchAlertById(id!),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="h-full flex flex-col p-6 max-w-5xl mx-auto w-full gap-6">
        <div className="skeleton h-8 w-64 rounded mb-6" />
        <div className="grid grid-cols-2 gap-6">
          <div className="skeleton h-96 rounded-xl" />
          <div className="skeleton h-96 rounded-xl" />
        </div>
      </div>
    );
  }

  if (isError || !alert) {
    return <div className="p-6 h-full"><ErrorState onRetry={() => refetch()} /></div>;
  }

  return (
    <div className="h-full flex flex-col p-6 max-w-5xl mx-auto w-full overflow-y-auto animate-fade-in">
      <div className="mb-8">
        <Link 
          to="/" 
          className="flex items-center gap-2 mb-6 text-sm font-medium hover:underline w-max transition-colors"
          style={{ color: 'var(--color-accent)' }}
        >
          <ArrowLeft size={16} />
          Back to Live Feed
        </Link>
        <div className="flex items-center gap-4 mb-2">
          <h1 className="text-2xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>
            Alert Inspection
          </h1>
          <SeverityBadge severity={alert.severity} className="text-sm px-3 py-1" />
          <ThreatClassBadge threatClass={alert.threat_class} className="text-sm px-3 py-1 shadow-none border-none bg-transparent p-0" />
        </div>
        <p className="font-mono text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          ID: {alert.id} • {new Date(alert.timestamp).toLocaleString()}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Network Tuple */}
        <div className="panel p-6 flex flex-col gap-6">
          <h3 className="section-header flex items-center gap-2 border-b pb-3 mb-0" style={{ borderColor: 'var(--color-border)' }}>
            <Zap size={16} style={{ color: 'var(--color-accent)' }} />
            Network Tuple
          </h3>
          <div className="grid grid-cols-2 gap-y-6">
            <div>
              <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Source IP</div>
              <div className="font-mono text-lg font-semibold" style={{ color: 'var(--color-warning)' }}>{alert.src_ip}</div>
            </div>
            <div>
              <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Destination IP</div>
              <div className="font-mono text-lg font-semibold" style={{ color: 'var(--color-info)' }}>{alert.dst_ip}</div>
            </div>
            <div>
              <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Source Port</div>
              <div className="font-mono text-lg" style={{ color: 'var(--color-text-primary)' }}>{alert.src_port}</div>
            </div>
            <div>
              <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Dest Port</div>
              <div className="font-mono text-lg" style={{ color: 'var(--color-text-primary)' }}>{alert.dst_port}</div>
            </div>
            <div>
              <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Protocol</div>
              <div className="font-mono uppercase text-lg" style={{ color: 'var(--color-text-primary)' }}>{alert.protocol}</div>
            </div>
            {alert.duration && (
              <div>
                <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Duration</div>
                <div className="font-mono text-lg" style={{ color: 'var(--color-text-primary)' }}>{alert.duration}s</div>
              </div>
            )}
          </div>
        </div>

        {/* ML Inference */}
        <div className="panel p-6 flex flex-col gap-6">
          <h3 className="section-header flex items-center gap-2 border-b pb-3 mb-0" style={{ borderColor: 'var(--color-border)' }}>
            <ShieldAlert size={16} style={{ color: 'var(--color-accent)' }} />
            ML Inference Analysis
          </h3>
          
          <div className="flex flex-col gap-2">
            <div className="flex justify-between text-sm">
              <span style={{ color: 'var(--color-text-secondary)' }}>Model Confidence</span>
              <span className="font-mono font-semibold" style={{ color: 'var(--color-text-primary)' }}>{(alert.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="progress-bar">
              <div 
                className="progress-fill" 
                style={{ width: `${alert.confidence * 100}%`, backgroundColor: 'var(--color-info)' }}
              ></div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex justify-between text-sm">
              <span style={{ color: 'var(--color-text-secondary)' }}>Isolation Forest Anomaly</span>
              <span className="font-mono font-semibold" style={{ color: 'var(--color-text-primary)' }}>{alert.anomaly_score.toFixed(3)}</span>
            </div>
            <div className="progress-bar">
              <div 
                className="progress-fill" 
                style={{ width: `${alert.anomaly_score * 100}%`, backgroundColor: 'var(--color-warning)' }}
              ></div>
            </div>
          </div>

          <div className="mt-2 flex flex-col gap-3">
            <div className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>SHAP Evidence</div>
            {alert.evidence.map((ev, i) => (
              <div 
                key={i} 
                className="px-4 py-3 rounded-lg text-sm flex items-start gap-3"
                style={{ backgroundColor: 'var(--color-bg-subtle)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}
              >
                <Search size={16} className="mt-0.5 flex-shrink-0" style={{ color: 'var(--color-accent)' }} />
                {ev}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* TLS & Fingerprints */}
        {(alert.ja3_hash || alert.ja4_hash) && (
          <div className="panel p-6 flex flex-col gap-6">
            <h3 className="section-header flex items-center gap-2 border-b pb-3 mb-0" style={{ borderColor: 'var(--color-border)' }}>
              <Lock size={16} style={{ color: 'var(--color-accent)' }} />
              Encryption & Fingerprints
            </h3>
            <div className="flex flex-col gap-4">
              {alert.ja3_hash && (
                <div>
                  <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>JA3 Hash (Client)</div>
                  <div 
                    className="rounded px-3 py-2 font-mono text-sm break-all"
                    style={{ backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', color: 'var(--color-warning)' }}
                  >
                    {alert.ja3_hash}
                  </div>
                </div>
              )}
              {alert.ja4_hash && (
                <div>
                  <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>JA4 Hash</div>
                  <div 
                    className="rounded px-3 py-2 font-mono text-sm break-all"
                    style={{ backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)', color: 'var(--color-warning)' }}
                  >
                    {alert.ja4_hash}
                  </div>
                </div>
              )}
              {alert.is_quic !== undefined && (
                <div 
                  className="flex items-center justify-between rounded px-3 py-2"
                  style={{ backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)' }}
                >
                  <span className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>QUIC Protocol</span>
                  <span className="font-semibold text-sm" style={{ color: alert.is_quic ? 'var(--color-success)' : 'var(--color-text-muted)' }}>
                    {alert.is_quic ? 'Detected' : 'No'}
                  </span>
                </div>
              )}
              {alert.quic_0rtt !== undefined && (
                <div 
                  className="flex items-center justify-between rounded px-3 py-2"
                  style={{ backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)' }}
                >
                  <span className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>0-RTT Resumption</span>
                  <span className="font-semibold text-sm" style={{ color: alert.quic_0rtt ? 'var(--color-critical)' : 'var(--color-text-muted)' }}>
                    {alert.quic_0rtt ? 'Detected' : 'No'}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Action Panel */}
        <div 
          className="panel p-6 flex flex-col justify-center items-center text-center"
          style={{ 
            backgroundColor: alert.kill_chain_id ? 'var(--color-critical-bg)' : 'var(--color-surface)',
            borderColor: alert.kill_chain_id ? 'var(--color-critical-border)' : 'var(--color-border)'
          }}
        >
          {alert.kill_chain_id ? (
            <>
              <div 
                className="w-16 h-16 rounded-full flex items-center justify-center mb-4"
                style={{ backgroundColor: 'var(--color-critical-bg)' }}
              >
                <ShieldAlert size={32} style={{ color: 'var(--color-critical)' }} className="animate-pulse" />
              </div>
              <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>Part of Kill Chain</h3>
              <p className="text-sm mb-6 max-w-sm" style={{ color: 'var(--color-text-secondary)' }}>
                This alert is correlated with a multi-stage attack from source IP <span className="font-mono font-medium" style={{ color: 'var(--color-warning)' }}>{alert.src_ip}</span>.
              </p>
              <Link 
                to={`/kill-chains?id=${alert.kill_chain_id}`}
                className="btn"
                style={{ backgroundColor: 'var(--color-critical)', color: '#fff' }}
              >
                Investigate Kill Chain
              </Link>
            </>
          ) : (
            <>
              <div 
                className="w-16 h-16 rounded-full flex items-center justify-center mb-4"
                style={{ backgroundColor: 'var(--color-bg-subtle)' }}
              >
                <Search size={32} style={{ color: 'var(--color-text-muted)' }} />
              </div>
              <h3 className="text-xl font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>Isolated Threat</h3>
              <p className="text-sm mb-6 max-w-sm" style={{ color: 'var(--color-text-secondary)' }}>
                This alert has not been correlated with any larger attack pattern.
              </p>
              <button className="btn btn-ghost border">
                Mark as Reviewed
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
