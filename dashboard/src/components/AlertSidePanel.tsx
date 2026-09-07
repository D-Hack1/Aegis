import React from 'react';
import { X, ExternalLink, ShieldAlert, Zap } from 'lucide-react';
import { Alert } from '../api/types';
import { SeverityBadge } from './SeverityBadge';
import { ThreatClassBadge } from './ThreatClassBadge';
import { Link, useLocation } from 'react-router-dom';

interface AlertSidePanelProps {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertSidePanel: React.FC<AlertSidePanelProps> = ({ alert, onClose }) => {
  const location = useLocation();
  const isKillChainsPage = location.pathname.includes('/kill-chains');

  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6">
      {/* Backdrop overlay */}
      <div 
        className="absolute inset-0 bg-zinc-950/80 backdrop-blur-sm transition-opacity" 
        onClick={onClose}
      />
      
      {/* Modal Panel */}
      <div className="relative w-full max-w-2xl bg-zinc-900 border border-zinc-700 shadow-2xl flex flex-col rounded-xl max-h-[90vh] overflow-hidden">
        <div className="p-6 border-b border-zinc-800 flex items-center justify-between sticky top-0 bg-zinc-900/95 backdrop-blur z-10">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold">Alert Inspector</h2>
            <SeverityBadge severity={alert.severity} />
          </div>
          <button 
            onClick={onClose}
            className="p-2 hover:bg-zinc-800 rounded-full transition-colors text-zinc-400 hover:text-white"
          >
            <X size={20} />
          </button>
        </div>

        <div className="p-6 flex-1 flex flex-col gap-8 overflow-y-auto">
          {/* Header Summary */}
          <div className="flex flex-col gap-4">
            <ThreatClassBadge threatClass={alert.threat_class} className="self-start text-base px-3 py-1.5" />
            <div className="font-mono text-sm text-zinc-400">
              ID: <span className="text-zinc-200">{alert.id}</span>
            </div>
            <div className="font-mono text-sm text-zinc-400">
              Detected: <span className="text-zinc-200">{new Date(alert.timestamp).toLocaleString()}</span>
            </div>
          </div>

          {/* Network Tuple */}
          <div className="panel p-5 flex flex-col gap-4">
            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2">
              <Zap size={16} className="text-sky-500" />
              Network Flow
            </h3>
            <div className="grid grid-cols-2 gap-y-4">
              <div>
                <div className="text-xs text-zinc-500 mb-1 font-mono">SOURCE IP</div>
                <div className="font-mono text-amber-500">{alert.src_ip}</div>
              </div>
              <div>
                <div className="text-xs text-zinc-500 mb-1 font-mono">DESTINATION IP</div>
                <div className="font-mono text-sky-500">{alert.dst_ip}</div>
              </div>
              <div>
                <div className="text-xs text-zinc-500 mb-1 font-mono">SOURCE PORT</div>
                <div className="font-mono text-zinc-200">{alert.src_port}</div>
              </div>
              <div>
                <div className="text-xs text-zinc-500 mb-1 font-mono">DEST PORT</div>
                <div className="font-mono text-zinc-200">{alert.dst_port}</div>
              </div>
              <div>
                <div className="text-xs text-zinc-500 mb-1 font-mono">PROTOCOL</div>
                <div className="font-mono text-zinc-200 uppercase">{alert.protocol}</div>
              </div>
            </div>
          </div>

          {/* ML Analysis */}
          <div className="panel p-5 flex flex-col gap-4">
            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert size={16} className="text-sky-500" />
              ML Inference
            </h3>
            
            <div className="flex flex-col gap-2">
              <div className="flex justify-between text-sm">
                <span className="text-zinc-400">Confidence</span>
                <span className="font-mono text-zinc-200">{(alert.confidence * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full bg-zinc-950 rounded-full h-2">
                <div 
                  className="bg-sky-500 h-2 rounded-full" 
                  style={{ width: `${alert.confidence * 100}%` }}
                ></div>
              </div>
            </div>

            <div className="flex flex-col gap-2 mt-2">
              <div className="flex justify-between text-sm">
                <span className="text-zinc-400">Anomaly Score</span>
                <span className="font-mono text-zinc-200">{alert.anomaly_score.toFixed(3)}</span>
              </div>
              <div className="w-full bg-zinc-950 rounded-full h-2">
                <div 
                  className="bg-yellow-500 h-2 rounded-full" 
                  style={{ width: `${alert.anomaly_score * 100}%` }}
                ></div>
              </div>
            </div>

            <div className="mt-4">
              <div className="text-xs text-zinc-500 mb-3 font-mono">KEY EVIDENCE (SHAP)</div>
              <div className="flex flex-col gap-2">
                {alert.evidence.map((ev, i) => (
                  <div key={i} className="px-3 py-2 bg-zinc-950 border border-zinc-800 rounded text-sm text-zinc-300">
                    {ev}
                  </div>
                ))}
              </div>
            </div>
          </div>
          
          {/* Actions */}
          <div className="mt-auto pt-4 flex gap-3 pb-2">
            <Link 
              to={`/alerts/${alert.id}`}
              className="flex-1 flex items-center justify-center gap-2 bg-sky-500 text-zinc-950 font-bold py-3 rounded-lg hover:bg-cyan-400 transition-colors"
            >
              <ExternalLink size={18} />
              Full Inspection
            </Link>
            
            {alert.kill_chain_id && !isKillChainsPage && (
              <Link 
                to={`/kill-chains?id=${alert.kill_chain_id}`}
                className="flex-1 flex items-center justify-center gap-2 bg-zinc-800 text-zinc-200 font-bold py-3 rounded-lg hover:bg-zinc-700 border border-zinc-600 transition-colors"
              >
                View Kill Chain
              </Link>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
