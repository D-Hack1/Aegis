import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchStats } from '../api/stats';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, Cell } from 'recharts';
import { THREAT_CLASS_LABELS } from '../api/types';
import { BarChart2, Activity, ShieldAlert, Target } from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

export const Stats: React.FC = () => {
  const [hours, setHours] = useState<number>(1);
  
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['stats', hours],
    queryFn: () => fetchStats(hours),
    refetchInterval: 30000,
  });

  if (isLoading && !data) {
    return (
      <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full gap-6">
        <div className="flex items-end justify-between mb-2">
          <div className="skeleton h-10 w-64 rounded" />
          <div className="skeleton h-8 w-48 rounded" />
        </div>
        <div className="grid grid-cols-4 gap-6">
          {[1,2,3,4].map(i => <div key={i} className="skeleton h-28 rounded-lg" />)}
        </div>
        <div className="grid grid-cols-3 gap-6 h-[400px]">
          <div className="col-span-1 skeleton rounded-lg" />
          <div className="col-span-2 skeleton rounded-lg" />
        </div>
      </div>
    );
  }

  if (isError) {
    return <div className="p-6 h-full"><ErrorState onRetry={() => refetch()} /></div>;
  }

  if (!data) return <div className="p-6 h-full"><EmptyState /></div>;

  const threatData = Object.entries(data.by_threat_class).map(([key, value]) => ({
    name: THREAT_CLASS_LABELS[key as keyof typeof THREAT_CLASS_LABELS],
    value,
    class: key
  })).sort((a, b) => b.value - a.value);

  const getBarColor = (threatClass: string) => {
    switch (threatClass) {
      case 'c2_beaconing': return 'var(--color-critical)';
      case 'ddos': return 'var(--color-high)';
      case 'exfiltration': return 'var(--color-accent)';
      case 'malware_tls': return 'var(--color-medium)';
      default: return 'var(--color-info)';
    }
  };

  const timelineData = data.timeline.map(t => ({
    time: new Date(t.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    count: t.count
  }));

  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full overflow-y-auto animate-fade-in">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2 mb-1" style={{ color: 'var(--color-text-primary)' }}>
            <BarChart2 size={24} style={{ color: 'var(--color-accent)' }} />
            Analytics & Stats
          </h1>
          <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
            Threat distribution and historical event volume
          </p>
        </div>
        
        <div className="segmented">
          {[1, 6, 12, 24].map(h => (
            <button 
              key={h}
              onClick={() => setHours(h)}
              className={`segmented-option ${hours === h ? 'active' : ''}`}
            >
              {h}H
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-4 gap-6 mb-6">
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-2">
            <Activity size={15} style={{ color: 'var(--color-info)' }} />
            <span className="section-header mb-0">Total Alerts</span>
          </div>
          <div className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>{data.total_alerts}</div>
        </div>
        <div className="stat-card" style={{ borderLeft: '3px solid var(--color-critical)' }}>
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert size={15} style={{ color: 'var(--color-critical)' }} />
            <span className="section-header mb-0">Critical</span>
          </div>
          <div className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>{data.by_severity.critical || 0}</div>
        </div>
        <div className="stat-card" style={{ borderLeft: '3px solid var(--color-high)' }}>
          <div className="flex items-center gap-2 mb-2">
            <Target size={15} style={{ color: 'var(--color-high)' }} />
            <span className="section-header mb-0">High</span>
          </div>
          <div className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>{data.by_severity.high || 0}</div>
        </div>
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-2">
            <Activity size={15} style={{ color: 'var(--color-accent)' }} />
            <span className="section-header mb-0">Sources</span>
          </div>
          <div className="text-3xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>{data.top_src_ips.length}</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6 mb-6 h-[400px]">
        {/* Threat Class Distribution */}
        <div className="col-span-1 panel p-6 flex flex-col">
          <h3 className="section-header mb-6">Threat Distribution</h3>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatData} layout="vertical" margin={{ top: 0, right: 0, left: 30, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: 'var(--chart-axis-text)', fontSize: 12 }} width={100} />
                <Tooltip 
                  cursor={{ fill: 'var(--chart-grid)' }} 
                  contentStyle={{ backgroundColor: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)', color: 'var(--chart-tooltip-text)' }}
                  itemStyle={{ color: 'var(--chart-tooltip-text)' }}
                  labelStyle={{ color: 'var(--chart-tooltip-text)' }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {threatData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getBarColor(entry.class)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Timeline */}
        <div className="col-span-2 panel p-6 flex flex-col">
          <h3 className="section-header mb-6">Alert Volume (5-min buckets)</h3>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: 'var(--chart-axis-text)', fontSize: 12 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'var(--chart-axis-text)', fontSize: 12 }} />
                <Tooltip 
                  cursor={{ stroke: 'var(--chart-grid)', strokeWidth: 1 }} 
                  contentStyle={{ backgroundColor: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)', color: 'var(--chart-tooltip-text)' }}
                  itemStyle={{ color: 'var(--chart-tooltip-text)' }}
                  labelStyle={{ color: 'var(--chart-tooltip-text)' }}
                />
                <Line 
                  type="monotone" 
                  dataKey="count" 
                  stroke="var(--color-accent)" 
                  strokeWidth={2} 
                  dot={{ r: 3, fill: 'var(--color-surface)', strokeWidth: 2, stroke: 'var(--color-accent)' }} 
                  activeDot={{ r: 5, fill: 'var(--color-accent)' }} 
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      
      {/* Top IPs */}
      <div className="panel p-6">
        <h3 className="section-header mb-4">Top Source IPs</h3>
        <div className="grid grid-cols-5 gap-4">
          {data.top_src_ips.slice(0, 5).map((ip, i) => (
            <div 
              key={i} 
              className="p-4 rounded-lg flex items-center justify-between"
              style={{ backgroundColor: 'var(--color-bg)', border: '1px solid var(--color-border)' }}
            >
              <span className="font-mono font-semibold text-sm" style={{ color: 'var(--color-warning)' }}>{ip.ip}</span>
              <span className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>{ip.count} events</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
