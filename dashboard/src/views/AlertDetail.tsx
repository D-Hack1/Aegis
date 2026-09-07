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
    return <div className="h-full flex items-center justify-center text-sky-500 animate-pulse">Loading inspection data...</div>;
  }

  if (isError || !alert) {
    return <div className="p-6 h-full"><ErrorState onRetry={() => refetch()} /></div>;
  }

  return (
    <div className="h-full flex flex-col p-6 max-w-5xl mx-auto w-full overflow-y-auto">
      <div className="mb-8">
        <Link to="/" className="text-sky-500 flex items-center gap-2 hover:underline mb-6 font-mono text-sm">
          <ArrowLeft size={16} />
          Back to Live Feed
        </Link>
        <div className="flex items-center gap-4">
          <h1 className="text-3xl font-bold text-zinc-100 flex items-center gap-3">
            Alert Inspection
          </h1>
          <SeverityBadge severity={alert.severity} className="text-sm px-3 py-1.5" />
          <ThreatClassBadge threatClass={alert.threat_class} className="text-sm px-3 py-1.5" />
        </div>
        <p className="text-zinc-400 mt-2 font-mono text-sm">
          ID: {alert.id} • {new Date(alert.timestamp).toLocaleString()}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Network Tuple */}
        <div className="panel p-6 flex flex-col gap-6">
          <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2 border-b border-zinc-700 pb-3">
            <Zap size={16} className="text-sky-500" />
            Network Tuple
          </h3>
          <div className="grid grid-cols-2 gap-y-6">
            <div>
              <div className="text-xs text-zinc-500 mb-1 font-mono">SOURCE IP</div>
              <div className="font-mono text-amber-500 text-lg font-bold">{alert.src_ip}</div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1 font-mono">DESTINATION IP</div>
              <div className="font-mono text-sky-500 text-lg font-bold">{alert.dst_ip}</div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1 font-mono">SOURCE PORT</div>
              <div className="font-mono text-zinc-200 text-lg">{alert.src_port}</div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1 font-mono">DEST PORT</div>
              <div className="font-mono text-zinc-200 text-lg">{alert.dst_port}</div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1 font-mono">PROTOCOL</div>
              <div className="font-mono text-zinc-200 uppercase text-lg">{alert.protocol}</div>
            </div>
            {alert.duration && (
              <div>
                <div className="text-xs text-zinc-500 mb-1 font-mono">DURATION</div>
                <div className="font-mono text-zinc-200 text-lg">{alert.duration}s</div>
              </div>
            )}
          </div>
        </div>

        {/* ML Inference */}
        <div className="panel p-6 flex flex-col gap-6">
          <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2 border-b border-zinc-700 pb-3">
            <ShieldAlert size={16} className="text-sky-500" />
            ML Inference Analysis
          </h3>
          
          <div className="flex flex-col gap-2">
            <div className="flex justify-between text-sm">
              <span className="text-zinc-400">Model Confidence</span>
              <span className="font-mono text-zinc-200 font-bold">{(alert.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="w-full bg-zinc-950 rounded-full h-3">
              <div 
                className="bg-sky-500 h-3 rounded-full" 
                style={{ width: `${alert.confidence * 100}%` }}
              ></div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex justify-between text-sm">
              <span className="text-zinc-400">Isolation Forest Anomaly</span>
              <span className="font-mono text-zinc-200 font-bold">{alert.anomaly_score.toFixed(3)}</span>
            </div>
            <div className="w-full bg-zinc-950 rounded-full h-3">
              <div 
                className="bg-yellow-500 h-3 rounded-full" 
                style={{ width: `${alert.anomaly_score * 100}%` }}
              ></div>
            </div>
          </div>

          <div className="mt-2 flex flex-col gap-3">
            <div className="text-xs text-zinc-500 font-mono">SHAP EVIDENCE</div>
            {alert.evidence.map((ev, i) => (
              <div key={i} className="px-4 py-3 bg-zinc-950 border border-zinc-800 rounded-lg text-sm text-zinc-300 flex items-start gap-3">
                <Search size={16} className="text-sky-500 mt-0.5 flex-shrink-0" />
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
            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2 border-b border-zinc-700 pb-3">
              <Lock size={16} className="text-indigo-500" />
              Encryption & Fingerprints
            </h3>
            <div className="flex flex-col gap-4">
              {alert.ja3_hash && (
                <div>
                  <div className="text-xs text-zinc-500 mb-1 font-mono">JA3 HASH (CLIENT)</div>
                  <div className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 font-mono text-sm text-yellow-500 break-all">
                    {alert.ja3_hash}
                  </div>
                </div>
              )}
              {alert.ja4_hash && (
                <div>
                  <div className="text-xs text-zinc-500 mb-1 font-mono">JA4 HASH</div>
                  <div className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 font-mono text-sm text-yellow-500 break-all">
                    {alert.ja4_hash}
                  </div>
                </div>
              )}
              {alert.is_quic !== undefined && (
                <div className="flex items-center justify-between bg-zinc-950 border border-zinc-800 rounded px-3 py-2">
                  <span className="text-sm text-zinc-400">QUIC Protocol</span>
                  <span className={`font-bold text-sm ${alert.is_quic ? 'text-emerald-500' : 'text-zinc-500'}`}>
                    {alert.is_quic ? 'DETECTED' : 'NO'}
                  </span>
                </div>
              )}
              {alert.quic_0rtt !== undefined && (
                <div className="flex items-center justify-between bg-zinc-950 border border-zinc-800 rounded px-3 py-2">
                  <span className="text-sm text-zinc-400">0-RTT Resumption</span>
                  <span className={`font-bold text-sm ${alert.quic_0rtt ? 'text-rose-500' : 'text-zinc-500'}`}>
                    {alert.quic_0rtt ? 'DETECTED' : 'NO'}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Action Panel */}
        <div className="panel p-6 flex flex-col justify-center items-center text-center border-sky-500/20 bg-gradient-to-br from-zinc-900 to-zinc-950">
          {alert.kill_chain_id ? (
            <>
              <div className="w-16 h-16 rounded-full bg-rose-500/10 flex items-center justify-center mb-4">
                <ShieldAlert size={32} className="text-rose-500 animate-pulse" />
              </div>
              <h3 className="text-xl font-bold text-zinc-100 mb-2">Part of Kill Chain</h3>
              <p className="text-zinc-400 text-sm mb-6 max-w-sm">
                This alert is correlated with a multi-stage attack from source IP <span className="font-mono text-amber-500">{alert.src_ip}</span>.
              </p>
              <Link 
                to={`/kill-chains?id=${alert.kill_chain_id}`}
                className="bg-rose-500 text-white px-6 py-3 rounded-lg font-bold hover:bg-red-600 transition-colors "
              >
                Investigate Kill Chain
              </Link>
            </>
          ) : (
            <>
              <div className="w-16 h-16 rounded-full bg-sky-500/10 flex items-center justify-center mb-4">
                <Search size={32} className="text-sky-500" />
              </div>
              <h3 className="text-xl font-bold text-zinc-100 mb-2">Isolated Threat</h3>
              <p className="text-zinc-400 text-sm mb-6 max-w-sm">
                This alert has not been correlated with any larger attack pattern.
              </p>
              <button className="bg-zinc-800 border border-zinc-600 text-zinc-200 px-6 py-3 rounded-lg font-bold hover:bg-zinc-700 transition-colors">
                Mark as Reviewed
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
