import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAlerts } from '../api/alerts';
import { Alert } from '../api/types';
import { SeverityBadge } from '../components/SeverityBadge';
import { ThreatClassBadge } from '../components/ThreatClassBadge';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { AlertSidePanel } from '../components/AlertSidePanel';
import { DemoControl } from '../components/DemoControl';
import { Search, Filter, Shield, Clock } from 'lucide-react';

// Helper to format relative time
const getRelativeTime = (date: Date) => {
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  const daysDifference = Math.round((date.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  if (daysDifference === 0) {
    const hoursDifference = Math.round((date.getTime() - Date.now()) / (1000 * 60 * 60));
    if (hoursDifference === 0) {
      const minutesDifference = Math.round((date.getTime() - Date.now()) / (1000 * 60));
      return rtf.format(minutesDifference, 'minute');
    }
    return rtf.format(hoursDifference, 'hour');
  }
  return rtf.format(daysDifference, 'day');
};

export const LiveFeed: React.FC = () => {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [evidenceSearch, setEvidenceSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [threatClassFilter, setThreatClassFilter] = useState<string>('');

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['alerts', 'live', evidenceSearch, severityFilter, threatClassFilter],
    queryFn: () =>
      fetchAlerts({
        page: 1,
        page_size: 50,
        ...(evidenceSearch ? { evidence: evidenceSearch } : {}),
        ...(severityFilter ? { severity: severityFilter } : {}),
        ...(threatClassFilter ? { threat_class: threatClassFilter } : {}),
      }),
    refetchInterval: 5000,
  });

  return (
    <div className="flex flex-col p-6 max-w-7xl mx-auto w-full h-full overflow-hidden animate-fade-in">
      <div className="flex items-end justify-between mb-6 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2 mb-1" style={{ color: 'var(--color-text-primary)' }}>
            <Shield size={24} style={{ color: 'var(--color-accent)' }} />
            Live Alert Feed
          </h1>
          <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
            Real-time threat detection from Zeek & Kafka pipeline
          </p>
        </div>

        <div className="flex gap-3 items-center">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2" size={15} style={{ color: 'var(--color-text-muted)' }} />
            <input
              type="text"
              placeholder="Search evidence or IPs..."
              value={evidenceSearch}
              onChange={(e) => setEvidenceSearch(e.target.value)}
              className="input pl-9 w-64"
            />
          </div>
          <select 
            className="input w-36 text-sm" 
            value={severityFilter} 
            onChange={e => setSeverityFilter(e.target.value)}
            style={{ backgroundColor: 'var(--color-surface)', height: '36px' }}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select 
            className="input w-44 text-sm" 
            value={threatClassFilter} 
            onChange={e => setThreatClassFilter(e.target.value)}
            style={{ backgroundColor: 'var(--color-surface)', height: '36px' }}
          >
            <option value="">All Threats</option>
            <option value="denial_of_service">Denial of Service</option>
            <option value="reconnaissance">Reconnaissance</option>
            <option value="exfiltration">Exfiltration</option>
            <option value="lateral_movement">Lateral Movement</option>
            <option value="malware">Malware</option>
          </select>
        </div>
      </div>

      <div className="mb-6 flex-shrink-0">
        <DemoControl onReset={() => refetch()} />
      </div>

      <div className="overflow-auto rounded-lg panel flex flex-col flex-1 min-h-0">
        {isLoading && !data ? (
          <div className="flex flex-col">
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} className="px-5 py-4 border-b" style={{ borderColor: 'var(--color-border-subtle)' }}>
                <div className="skeleton h-12 w-full rounded" />
              </div>
            ))}
          </div>
        ) : isError ? (
          <div className="p-10"><ErrorState onRetry={() => refetch()} /></div>
        ) : !data || data.results.length === 0 ? (
          <div className="p-10"><EmptyState /></div>
        ) : (
          <div className="flex flex-col">
            {/* Table Header */}
            <div 
              className="flex items-center justify-between px-5 py-3 border-b text-xs font-semibold uppercase tracking-wider sticky top-0 z-10"
              style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}
            >
              <div className="flex gap-6 w-full">
                <div className="w-24">Time</div>
                <div className="w-[300px]">Network Flow</div>
                <div className="w-48">Classification</div>
                <div className="flex-1 text-right">Confidence & Severity</div>
              </div>
            </div>

            {/* Table Body */}
            {data.results.map((alert: Alert) => (
              <div
                key={alert.id}
                onClick={() => setSelectedAlert(alert)}
                className="alert-row px-5 py-4 flex items-center justify-between"
              >
                <div className="flex items-center gap-6 w-full">
                  
                  {/* Time */}
                  <div className="w-24 flex flex-col gap-1">
                    <span className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>
                      {getRelativeTime(new Date(alert.timestamp))}
                    </span>
                    <span className="text-xs flex items-center gap-1" style={{ color: 'var(--color-text-muted)' }}>
                      <Clock size={10} />
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>

                  {/* Flow */}
                  <div className="w-[300px] flex items-center gap-3">
                    <div className="text-right">
                      <div className="font-mono text-sm font-medium" style={{ color: 'var(--color-warning)' }}>{alert.src_ip}</div>
                      <div className="font-mono text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>:{alert.src_port}</div>
                    </div>
                    <div className="text-xs" style={{ color: 'var(--color-text-muted)' }}>→</div>
                    <div>
                      <div className="font-mono text-sm font-medium" style={{ color: 'var(--color-info)' }}>{alert.dst_ip}</div>
                      <div className="font-mono text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>:{alert.dst_port}</div>
                    </div>
                  </div>

                  {/* Threat */}
                  <div className="w-48">
                    <ThreatClassBadge threatClass={alert.threat_class} />
                  </div>

                  {/* Confidence / Severity */}
                  <div className="flex-1 flex items-center justify-end gap-6">
                    <div className="flex flex-col items-end w-24">
                      <div className="flex items-center justify-between w-full mb-1">
                        <span className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>Conf</span>
                        <span className="font-mono text-xs font-medium" style={{ color: 'var(--color-text-primary)' }}>
                          {(alert.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="progress-bar w-full">
                        <div
                          className="progress-fill"
                          style={{ width: `${alert.confidence * 100}%` }}
                        ></div>
                      </div>
                    </div>
                    <div className="w-24 text-right">
                      <SeverityBadge severity={alert.severity} />
                    </div>
                  </div>

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
