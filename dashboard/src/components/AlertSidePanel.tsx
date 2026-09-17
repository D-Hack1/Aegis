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
    <div className="fixed inset-0 z-50 flex items-center justify-end">
      {/* Backdrop overlay */}
      <div 
        className="absolute inset-0 bg-black/40 backdrop-blur-sm transition-opacity animate-fade-in" 
        onClick={onClose}
      />
      
      {/* Slide-in Panel */}
      <div 
        className="relative w-full max-w-lg h-full shadow-2xl flex flex-col animate-slide-in-right"
        style={{
          backgroundColor: 'var(--color-bg)',
          borderLeft: '1px solid var(--color-border)',
        }}
      >
        <div 
          className="p-5 flex items-center justify-between sticky top-0 z-10"
          style={{ borderBottom: '1px solid var(--color-border)' }}
        >
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold" style={{ color: 'var(--color-text-primary)' }}>Alert Inspector</h2>
            <SeverityBadge severity={alert.severity} />
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 rounded-full transition-colors"
            style={{ color: 'var(--color-text-muted)' }}
            onMouseOver={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-surface-hover)';
              e.currentTarget.style.color = 'var(--color-text-primary)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-muted)';
            }}
          >
            <X size={20} />
          </button>
        </div>

        <div className="p-5 flex-1 flex flex-col gap-6 overflow-y-auto">
          {/* Header Summary */}
          <div className="flex flex-col gap-3">
            <ThreatClassBadge threatClass={alert.threat_class} className="self-start text-sm px-3 py-1" />
            <div className="font-mono text-xs" style={{ color: 'var(--color-text-muted)' }}>
              ID: <span style={{ color: 'var(--color-text-primary)' }}>{alert.id}</span>
            </div>
            <div className="text-sm font-medium" style={{ color: 'var(--color-text-secondary)' }}>
              Detected: <span style={{ color: 'var(--color-text-primary)' }}>{new Date(alert.timestamp).toLocaleString()}</span>
            </div>
          </div>

          {/* Network Tuple */}
          <div className="panel p-4 flex flex-col gap-4">
            <h3 className="section-header flex items-center gap-2 mb-0">
              <Zap size={14} style={{ color: 'var(--color-accent)' }} />
              Network Flow
            </h3>
            <div className="grid grid-cols-2 gap-y-4">
              <div>
                <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Source IP</div>
                <div className="font-mono font-medium" style={{ color: 'var(--color-warning)' }}>{alert.src_ip}</div>
              </div>
              <div>
                <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Destination IP</div>
                <div className="font-mono font-medium" style={{ color: 'var(--color-info)' }}>{alert.dst_ip}</div>
              </div>
              <div>
                <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Source Port</div>
                <div className="font-mono" style={{ color: 'var(--color-text-primary)' }}>{alert.src_port}</div>
              </div>
              <div>
                <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Dest Port</div>
                <div className="font-mono" style={{ color: 'var(--color-text-primary)' }}>{alert.dst_port}</div>
              </div>
              <div>
                <div className="text-xs mb-1" style={{ color: 'var(--color-text-secondary)' }}>Protocol</div>
                <div className="font-medium" style={{ color: 'var(--color-text-primary)' }}>{alert.protocol.toUpperCase()}</div>
              </div>
            </div>
          </div>

          {/* ML Analysis */}
          <div className="panel p-4 flex flex-col gap-4">
            <h3 className="section-header flex items-center gap-2 mb-0">
              <ShieldAlert size={14} style={{ color: 'var(--color-accent)' }} />
              ML Inference
            </h3>
            
            <div className="flex flex-col gap-2">
              <div className="flex justify-between text-sm">
                <span style={{ color: 'var(--color-text-secondary)' }}>Confidence</span>
                <span className="font-mono font-medium" style={{ color: 'var(--color-text-primary)' }}>{(alert.confidence * 100).toFixed(1)}%</span>
              </div>
              <div className="progress-bar">
                <div 
                  className="progress-fill" 
                  style={{ width: `${alert.confidence * 100}%`, backgroundColor: 'var(--color-info)' }}
                />
              </div>
            </div>

            <div className="flex flex-col gap-2 mt-2">
              <div className="flex justify-between text-sm">
                <span style={{ color: 'var(--color-text-secondary)' }}>Anomaly Score</span>
                <span className="font-mono font-medium" style={{ color: 'var(--color-text-primary)' }}>{alert.anomaly_score.toFixed(3)}</span>
              </div>
              <div className="progress-bar">
                <div 
                  className="progress-fill" 
                  style={{ width: `${alert.anomaly_score * 100}%`, backgroundColor: 'var(--color-warning)' }}
                />
              </div>
            </div>

            <div className="mt-2">
              <div className="text-xs mb-2" style={{ color: 'var(--color-text-secondary)' }}>Key Evidence (SHAP)</div>
              <div className="flex flex-col gap-2">
                {alert.evidence.map((ev, i) => (
                  <div 
                    key={i} 
                    className="px-3 py-2 rounded text-sm"
                    style={{ 
                      backgroundColor: 'var(--color-bg-subtle)', 
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-text-secondary)'
                    }}
                  >
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
              className="btn btn-primary flex-1"
            >
              <ExternalLink size={16} />
              Full Inspection
            </Link>
            
            {alert.kill_chain_id && !isKillChainsPage && (
              <Link 
                to={`/kill-chains?id=${alert.kill_chain_id}`}
                className="btn btn-ghost flex-1"
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
