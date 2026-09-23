import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Activity, BarChart2, Link2, Sun, Moon, ChevronLeft, ChevronRight } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

const navItems = [
  { name: 'Live Feed', path: '/', icon: Shield },
  { name: 'Metrics', path: '/metrics', icon: Activity },
  { name: 'Stats', path: '/stats', icon: BarChart2 },
  { name: 'Kill Chains', path: '/kill-chains', icon: Link2 },
];

export const Sidebar: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div
      className="relative flex flex-col h-full border-r transition-all duration-300 ease-in-out"
      style={{
        width: collapsed ? '64px' : '220px',
        backgroundColor: 'var(--color-surface)',
        borderColor: 'var(--color-border)',
        flexShrink: 0,
        transition: 'width 0.3s ease, background-color 0.3s',
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center border-b"
        style={{
          padding: collapsed ? '18px 0' : '18px 16px',
          borderColor: 'var(--color-border)',
          justifyContent: collapsed ? 'center' : 'flex-start',
          minHeight: '60px',
        }}
      >
        {collapsed ? (
          <img
            src="/icon.png"
            alt="Aegis icon"
            style={{ height: '28px', width: 'auto', objectFit: 'contain' }}
          />
        ) : (
          <img
            src={theme === 'dark' ? '/title.png' : '/light%20mode%20title.png'}
            alt="Aegis"
            style={{ height: '28px', width: 'auto', objectFit: 'contain' }}
          />
        )}
      </div>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(prev => !prev)}
        className="absolute -right-3 top-[52px] z-20 flex items-center justify-center rounded-full border transition-all duration-150"
        style={{
          width: '28px',
          height: '28px',
          backgroundColor: 'var(--color-surface)',
          borderColor: 'var(--color-border)',
          color: 'var(--color-accent)',
          transition: 'background-color 0.3s ease, border-color 0.3s ease',
        }}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={20} style={{ color: 'var(--color-accent)' }} /> : <ChevronLeft size={20} style={{ color: 'var(--color-accent)' }} />}
      </button>

      {/* Nav */}
      <nav className="flex-1 py-3 flex flex-col gap-1" style={{ padding: '12px 8px' }}>
        {navItems.map(({ name, path, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            end={path === '/'}
            title={collapsed ? name : undefined}
            className={({ isActive }) =>
              `nav-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center' : ''}`
            }
          >
            <Icon size={17} style={{ flexShrink: 0 }} />
            {!collapsed && <span>{name}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div
        className="flex flex-col gap-2 border-t"
        style={{
          padding: '12px 8px',
          borderColor: 'var(--color-border)',
        }}
      >
        {/* Theme toggle moved to top‑right */}
        {/* Placeholder retained for future customizations */}

        {/* Version */}
        {!collapsed && (
          <div style={{ padding: '0 10px', fontSize: '11px', color: 'var(--color-text-muted)' }}>
            Aegis v1.0 · SOC
          </div>
        )}
      </div>
    </div>
  );
};
