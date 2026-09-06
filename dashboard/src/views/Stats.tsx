import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchStats } from '../api/stats';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, Cell } from 'recharts';
import { THREAT_CLASS_LABELS, SEVERITY_COLOURS } from '../api/types';
import { BarChart2, Activity, ShieldAlert, Target } from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

export const Stats: React.FC = () => {
  const [hours, setHours] = useState<number>(1);
  
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['stats', hours],
    queryFn: () => fetchStats(hours),
    refetchInterval: 30000, // Refresh every 30s
  });

  if (isLoading && !data) {
    return <div className="h-full flex items-center justify-center text-sky-500 animate-pulse">Loading analytics...</div>;
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
      case 'c2_beaconing': return '#FF2A55';
      case 'ddos': return '#FF6B00';
      case 'exfiltration': return '#7000FF';
      case 'malware_tls': return '#FFC700';
      default: return '#00F0FF';
    }
  };

  const timelineData = data.timeline.map(t => ({
    time: new Date(t.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    count: t.count
  }));

  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full overflow-y-auto">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-zinc-100 flex items-center gap-3">
            <BarChart2 className="text-sky-500" size={32} />
            Analytics & Stats
          </h1>
          <p className="text-zinc-400 mt-2 font-mono text-sm">
            Threat distribution and historical event volume
          </p>
        </div>
        
        <div className="flex gap-2">
          {[1, 6, 12, 24].map(h => (
            <button 
              key={h}
              onClick={() => setHours(h)}
              className={`px-4 py-2 rounded-lg text-sm font-mono transition-colors ${
                hours === h 
                  ? 'bg-sky-500 text-zinc-950 font-bold' 
                  : 'bg-zinc-900 text-zinc-400 hover:bg-zinc-800 border border-zinc-700'
              }`}
            >
              {h}H
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-4 gap-6 mb-6">
        <div className="panel p-5">
          <div className="flex items-center gap-2 text-zinc-400 mb-2">
            <Activity size={16} />
            <span className="text-xs font-bold tracking-wider">TOTAL ALERTS</span>
          </div>
          <div className="text-3xl font-bold text-zinc-100">{data.total_alerts}</div>
        </div>
        <div className="panel p-5">
          <div className="flex items-center gap-2 text-rose-500 mb-2">
            <ShieldAlert size={16} />
            <span className="text-xs font-bold tracking-wider">CRITICAL</span>
          </div>
          <div className="text-3xl font-bold text-zinc-100">{data.by_severity.critical || 0}</div>
        </div>
        <div className="panel p-5">
          <div className="flex items-center gap-2 text-amber-500 mb-2">
            <Target size={16} />
            <span className="text-xs font-bold tracking-wider">HIGH</span>
          </div>
          <div className="text-3xl font-bold text-zinc-100">{data.by_severity.high || 0}</div>
        </div>
        <div className="panel p-5">
          <div className="flex items-center gap-2 text-sky-500 mb-2">
            <Activity size={16} />
            <span className="text-xs font-bold tracking-wider">SOURCES</span>
          </div>
          <div className="text-3xl font-bold text-zinc-100">{data.top_src_ips.length}</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6 mb-6 h-[400px]">
        {/* Threat Class Distribution */}
        <div className="col-span-1 panel p-6 flex flex-col">
          <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-6">Threat Distribution</h3>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatData} layout="vertical" margin={{ top: 0, right: 0, left: 30, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#94A3B8', fontSize: 12 }} width={100} />
                <Tooltip 
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', color: '#f4f4f5' }}
                  itemStyle={{ color: '#f4f4f5' }}
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
          <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-6">Alert Volume (5-min buckets)</h3>
          <div className="flex-1 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#64748B', fontSize: 12 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#64748B', fontSize: 12 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', borderColor: '#27272a', color: '#f4f4f5' }}
                  itemStyle={{ color: '#f4f4f5' }}
                />
                <Line type="monotone" dataKey="count" stroke="#00F0FF" strokeWidth={3} dot={{ r: 4, fill: '#0F1523', strokeWidth: 2 }} activeDot={{ r: 6, fill: '#00F0FF' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      
      {/* Top IPs */}
      <div className="panel p-6">
        <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-4">Top Source IPs</h3>
        <div className="grid grid-cols-5 gap-4">
          {data.top_src_ips.slice(0, 5).map((ip, i) => (
            <div key={i} className="bg-zinc-950 border border-zinc-800 p-4 rounded-lg flex items-center justify-between">
              <span className="font-mono text-amber-500 font-bold text-sm">{ip.ip}</span>
              <span className="text-zinc-400 text-sm">{ip.count} events</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
