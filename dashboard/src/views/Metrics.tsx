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
    if (latency < 100) return 'var(--color-success)';
    if (latency < 500) return 'var(--color-warning)';
    return 'var(--color-critical)';
  };

  return (
    <div className="h-full flex flex-col p-6 max-w-7xl mx-auto w-full animate-fade-in">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2 mb-1" style={{ color: 'var(--color-text-primary)' }}>
            <Activity size={24} style={{ color: 'var(--color-accent)' }} />
            Pipeline Metrics
          </h1>
          <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
            Live SSE telemetry from Aegis backend engine
          </p>
        </div>
        
        <div className="badge" style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', padding: '6px 12px' }}>
          <div 
            className="w-2 h-2 rounded-full animate-pulse" 
            style={{ backgroundColor: isConnected ? 'var(--color-success)' : 'var(--color-critical)' }} 
          />
          <span className="font-mono">SSE {isConnected ? 'Connected' : 'Disconnected'}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Flows Per Sec */}
        <div className="panel p-6 flex flex-col">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2" style={{ color: 'var(--color-text-secondary)' }}>
              <Zap size={16} style={{ color: 'var(--color-info)' }} />
              <span className="section-header mb-0">Flows / Sec</span>
            </div>
            <span className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>2s window</span>
          </div>
          <div className="text-4xl font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
            {metrics?.flows_per_sec.toFixed(1) || '0.0'}
          </div>
          <div className="h-16 mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['auto', 'auto']} hide />
                <Line type="monotone" dataKey="flows_per_sec" stroke="var(--color-info)" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bytes Per Sec */}
        <div className="panel p-6 flex flex-col">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2" style={{ color: 'var(--color-text-secondary)' }}>
              <LineChartIcon size={16} style={{ color: 'var(--color-accent)' }} />
              <span className="section-header mb-0">Throughput</span>
            </div>
            <span className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>2s window</span>
          </div>
          <div className="text-4xl font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
            {metrics ? (metrics.bytes_per_sec / 1024 / 1024).toFixed(2) : '0.00'} <span className="text-lg" style={{ color: 'var(--color-text-muted)' }}>MB/s</span>
          </div>
          <div className="h-16 mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['auto', 'auto']} hide />
                <Line type="monotone" dataKey="bytes_per_sec" stroke="var(--color-accent)" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Kafka Queue */}
        <div className="panel p-6 flex flex-col">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2" style={{ color: 'var(--color-text-secondary)' }}>
              <HardDrive size={16} style={{ color: 'var(--color-warning)' }} />
              <span className="section-header mb-0">Kafka Queue Depth</span>
            </div>
          </div>
          <div className="text-4xl font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
            {metrics?.kafka_queue_depth || '0'} <span className="text-lg" style={{ color: 'var(--color-text-muted)' }}>msgs</span>
          </div>
          <div className="h-16 mt-auto">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['auto', 'auto']} hide />
                <Line type="stepAfter" dataKey="kafka_queue_depth" stroke="var(--color-warning)" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Latency */}
        <div 
          className="panel p-6 flex flex-col transition-colors duration-300"
          style={{
            borderColor: metrics ? (
              metrics.pipeline_latency_ms >= 500 ? 'var(--color-critical-border)' :
              metrics.pipeline_latency_ms >= 100 ? 'var(--color-medium-border)' :
              'var(--color-info-border)'
            ) : 'var(--color-border)'
          }}
        >
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-2" style={{ color: 'var(--color-text-secondary)' }}>
              <Clock size={16} style={{ color: metrics ? getLatencyColor(metrics.pipeline_latency_ms) : 'var(--color-text-muted)' }} />
              <span className="section-header mb-0">Pipeline Latency</span>
            </div>
            {metrics && (
              <div 
                className="w-2.5 h-2.5 rounded-full animate-pulse"
                style={{ backgroundColor: getLatencyColor(metrics.pipeline_latency_ms) }}
              />
            )}
          </div>
          <div className="text-4xl font-semibold mb-4" style={{ color: 'var(--color-text-primary)' }}>
            {metrics?.pipeline_latency_ms.toFixed(1) || '0.0'} <span className="text-lg" style={{ color: 'var(--color-text-muted)' }}>ms</span>
          </div>
          <div className="flex justify-between items-end mt-auto h-16">
            <div className="flex flex-col gap-1">
              <span className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>MEAN (2s)</span>
              <span className="text-sm font-mono" style={{ color: 'var(--color-text-secondary)' }}>{metrics?.latency_ms_mean.toFixed(1) || '0.0'} ms</span>
            </div>
            <div className="w-1/2 h-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={history}>
                  <YAxis domain={[0, 600]} hide />
                  <Line 
                    type="monotone" 
                    dataKey="pipeline_latency_ms" 
                    stroke={metrics ? getLatencyColor(metrics.pipeline_latency_ms) : 'var(--color-border)'} 
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
