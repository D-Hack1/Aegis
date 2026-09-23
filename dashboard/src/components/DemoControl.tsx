import React, { useState } from 'react';
import { Play, RotateCcw, Crosshair } from 'lucide-react';
import { launchAttack, resetDashboard } from '../api/demo';

interface DemoControlProps {
  onReset: () => void;
}

export const DemoControl: React.FC<DemoControlProps> = ({ onReset }) => {
  const [attackType, setAttackType] = useState<string>('port_scan');
  const [isLaunching, setIsLaunching] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const attackOptions = [
    { value: 'port_scan', label: 'Port Scan' },
    { value: 'syn_flood', label: 'SYN Flood' },
    { value: 'udp_flood', label: 'UDP Flood' },
    { value: 'exfiltration', label: 'Data Exfiltration' },
    { value: 'benign', label: 'Benign Traffic' },
  ];

  const handleLaunch = async () => {
    setIsLaunching(true);
    try {
      await launchAttack(attackType);
    } catch (error) {
      console.error('Failed to launch attack:', error);
    }
    // Re-enable after 10 seconds
    setTimeout(() => {
      setIsLaunching(false);
    }, 10000);
  };

  const handleReset = async () => {
    setIsResetting(true);
    try {
      await resetDashboard();
      onReset();
    } catch (error) {
      console.error('Failed to reset dashboard:', error);
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <div 
      className="panel p-4 flex items-center gap-4 animate-fade-in"
      style={{
        borderColor: 'var(--color-critical-border)',
        backgroundColor: 'var(--color-critical-bg)',
        boxShadow: '0 0 15px rgba(239, 68, 68, 0.1)',
      }}
    >
      <div className="flex items-center gap-2 mr-2">
        <Crosshair size={20} style={{ color: 'var(--color-critical)' }} />
        <span className="font-semibold text-sm uppercase tracking-wider" style={{ color: 'var(--color-critical)' }}>
          Demo Control
        </span>
      </div>

      <div className="flex items-center gap-2 border-l pl-4" style={{ borderColor: 'var(--color-border-strong)' }}>
        <select
          className="input w-48 text-sm"
          value={attackType}
          onChange={(e) => setAttackType(e.target.value)}
          disabled={isLaunching || isResetting}
          style={{ backgroundColor: 'var(--color-surface)', border: '1px solid var(--color-border)' }}
        >
          {attackOptions.map(option => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>

        <button
          className="btn"
          onClick={handleLaunch}
          disabled={isLaunching || isResetting}
          style={{
            backgroundColor: isLaunching ? 'var(--color-surface-active)' : 'var(--color-critical)',
            color: isLaunching ? 'var(--color-text-muted)' : '#ffffff',
            opacity: isLaunching ? 0.7 : 1,
          }}
        >
          <Play size={15} />
          {isLaunching ? 'Launching...' : 'Launch Attack'}
        </button>
      </div>

      <div className="ml-auto">
        <button
          className="btn btn-ghost"
          onClick={handleReset}
          disabled={isLaunching || isResetting}
          style={{ color: 'var(--color-text-primary)' }}
        >
          <RotateCcw size={15} className={isResetting ? 'animate-spin' : ''} />
          {isResetting ? 'Resetting...' : 'Reset Dashboard'}
        </button>
      </div>
    </div>
  );
};
