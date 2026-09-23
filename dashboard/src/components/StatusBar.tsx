import React, { useEffect, useState } from 'react';
import { fetchHealth } from '../api/health';
import { HealthResponse } from '../api/types';

const StatusDot: React.FC<{ status?: string }> = ({ status }) => {
  const color =
    !status ? 'var(--color-error)' :
    status === 'ok' ? 'var(--color-success)' :
    'var(--color-warning)';

  return (
    <span
      style={{
        display: 'inline-block',
        width: '7px',
        height: '7px',
        borderRadius: '50%',
        backgroundColor: color,
        flexShrink: 0,
      }}
    />
  );
};

const Chip: React.FC<{ label: string; value: string; healthy?: boolean }> = ({ label, value, healthy }) => (
  <div
    className="flex items-center gap-1.5"
    style={{
      padding: '3px 10px',
      borderRadius: '6px',
      fontSize: '12px',
      border: '1px solid var(--color-border)',
      backgroundColor: 'var(--color-surface)',
      color: 'var(--color-text-secondary)',
      gap: '6px',
    }}
  >
    <StatusDot status={healthy === undefined ? undefined : healthy ? 'ok' : 'error'} />
    <span style={{ fontFamily: 'inherit', fontWeight: 500 }}>
      {label}
    </span>
    <span style={{ color: healthy ? 'var(--color-success)' : healthy === false ? 'var(--color-error)' : 'var(--color-text-muted)', fontWeight: 600, fontSize: '11px' }}>
      {value}
    </span>
  </div>
);

export const StatusBar: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const check = async () => {
      try {
        const data = await fetchHealth();
        setHealth(data);
      } catch (error) {
        console.error("Health check failed", error);
        setHealth(null);
      }
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      className="flex items-center justify-between px-5"
      style={{
        height: '48px',
        borderBottom: '1px solid var(--color-border)',
        backgroundColor: 'var(--color-surface)',
        flexShrink: 0,
      }}
    >
      {/* Left: service status chips */}
      <div className="flex items-center gap-2">
        <Chip
          label="System"
          value={health?.status === 'ok' ? 'Healthy' : health?.status === 'degraded' ? 'Degraded' : 'Offline'}
          healthy={health?.status === 'ok'}
        />

        {health?.kafka && (
          <Chip
            label="Kafka"
            value={health.kafka.status === 'ok' ? 'Connected' : 'Error'}
            healthy={health.kafka.status === 'ok'}
          />
        )}

        {health?.elasticsearch && (
          <Chip
            label="Elasticsearch"
            value={health.elasticsearch.status === 'ok' ? 'Connected' : 'Error'}
            healthy={health.elasticsearch.status === 'ok'}
          />
        )}
      </div>

      {/* Right: uptime */}
      <div className="flex items-center gap-4">
        <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', fontFamily: '"JetBrains Mono", monospace' }}>
          {health?.uptime_seconds != null
            ? `Up ${Math.floor(health.uptime_seconds / 3600)}h ${Math.floor((health.uptime_seconds % 3600) / 60)}m`
            : 'Connecting...'}
        </div>
      </div>
    </div>
  );
};
