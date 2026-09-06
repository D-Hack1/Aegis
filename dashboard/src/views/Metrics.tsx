import React, { useEffect, useState } from 'react';
import { subscribePipelineMetrics } from '../api/metrics';
import { PipelineMetrics } from '../api/types';
import { Activity, Zap, HardDrive, Clock, LineChart as LineChartIcon } from 'lucide-react';
import { LineChart, Line, ResponsiveContainer, YAxis } from 'recharts';

export const Metrics: React.FC = () => {
  const [metrics, setMetrics] = useState<PipelineMetrics | null>(null);
  const [history, setHistory] = useState<PipelineMetrics[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const unsubscribe = subscribePipelineMetrics(
      (data) => {
        setMetrics(data);
        setIsConnected(true);
        setHistory(prev => {
          const newHistory = [...prev, data];
          if (newHistory.length > 30) return newHistory.slice(newHistory.length - 30);
          return newHistory;
        });
      },
      (error) => {
        setIsConnected(false);
      }
    );

    return () => unsubscribe();
  }, []);

  const getLatencyColor = (latency: number) => {
    if (latency < 100) return 'bg-emerald-500 text-emerald-500';
    if (latency < 500) return 'bg-yellow-500 text-yellow-500';
    return 'bg-rose-500 text-rose-500';
  };

  const getLatencyGlow = (latency: number) => {
    if (latency < 100) return 'glow-emerald border-emerald-500/50';
    if (latency < 500) return 'glow-medium border-yellow-500/50';
    return 'glow-critical border-rose-500/50';
  };

  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-zinc-100 flex items-center gap-3">
            <Activity className="text-sky-500" size={32} />
            Pipeline Metrics
          </h1>
          <p className="text-zinc-400 mt-2 font-mono text-sm">
            Live SSE telemetry from Aegis backend engine
          </p>
        </div>
        
        <div className="flex items-center gap-2 bg-zinc-900 px-4 py-2 rounded-lg border border-zinc-700">
          <div className={`w-2 h-2 rounded-full animate-pulse ${isConnected ? 'bg-emerald-500' : 'bg-rose-500'}`}></div>
          <span className="text-sm font-mono text-zinc-300">SSE {isConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Flows Per Sec */}
        <div className="panel p-6 flex flex-col">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2 text-zinc-400">
              <Zap size={18} className="text-sky-500" />
              <span className="font-bold tracking-wider text-sm">FLOWS / SEC</span>
            </div>
            <span className="text-xs font-mono text-zinc-600">2s window</span>
          </div>
          <div className="text-4xl font-bold text-zinc-100 mb-4">
            {metrics?.flows_per_sec.toFixed(1) || '0.0'}
          </div>
          <div className="h-16 mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['auto', 'auto']} hide />
                <Line type="monotone" dataKey="flows_per_sec" stroke="#00F0FF" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bytes Per Sec */}
        <div className="panel p-6 flex flex-col">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2 text-zinc-400">
              <LineChartIcon size={18} className="text-indigo-500" />
              <span className="font-bold tracking-wider text-sm">THROUGHPUT (MB/s)</span>
            </div>
            <span className="text-xs font-mono text-zinc-600">2s window</span>
          </div>
          <div className="text-4xl font-bold text-zinc-100 mb-4">
            {metrics ? (metrics.bytes_per_sec / 1024 / 1024).toFixed(2) : '0.00'} <span className="text-xl text-zinc-500">MB/s</span>
          </div>
          <div className="h-16 mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['auto', 'auto']} hide />
                <Line type="monotone" dataKey="bytes_per_sec" stroke="#7000FF" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Kafka Queue */}
        <div className="panel p-6 flex flex-col">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2 text-zinc-400">
              <HardDrive size={18} className="text-amber-500" />
              <span className="font-bold tracking-wider text-sm">KAFKA QUEUE DEPTH</span>
            </div>
          </div>
          <div className="text-4xl font-bold text-zinc-100 mb-4">
            {metrics?.kafka_queue_depth || '0'} <span className="text-xl text-zinc-500">msgs</span>
          </div>
          <div className="h-16 mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['auto', 'auto']} hide />
                <Line type="stepAfter" dataKey="kafka_queue_depth" stroke="#FF6B00" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Latency */}
        <div className={`panel p-6 flex flex-col transition-all duration-300 ${metrics ? getLatencyGlow(metrics.pipeline_latency_ms) : ''}`}>
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2 text-zinc-400">
              <Clock size={18} className={metrics ? getLatencyColor(metrics.pipeline_latency_ms).split(' ')[1] : ''} />
              <span className="font-bold tracking-wider text-sm">PIPELINE LATENCY</span>
            </div>
            {metrics && (
              <div className={`w-3 h-3 rounded-full animate-pulse ${getLatencyColor(metrics.pipeline_latency_ms).split(' ')[0]}`}></div>
            )}
          </div>
          <div className="text-4xl font-bold text-zinc-100 mb-4">
            {metrics?.pipeline_latency_ms.toFixed(1) || '0.0'} <span className="text-xl text-zinc-500">ms</span>
          </div>
          <div className="flex justify-between items-end mt-auto h-16">
            <div className="flex flex-col gap-1">
              <span className="text-xs text-zinc-500 font-mono">MEAN (2s)</span>
              <span className="text-sm text-zinc-300 font-mono">{metrics?.latency_ms_mean.toFixed(1) || '0.0'} ms</span>
            </div>
            <div className="w-1/2 h-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={history}>
                  <YAxis domain={[0, 600]} hide />
                  <Line 
                    type="monotone" 
                    dataKey="pipeline_latency_ms" 
                    stroke={metrics && metrics.pipeline_latency_ms >= 500 ? '#FF2A55' : (metrics && metrics.pipeline_latency_ms >= 100 ? '#FFC700' : '#00E676')} 
                    strokeWidth={2} 
                    dot={false} 
                    isAnimationActive={false} 
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
