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
          <Shield size={22} style={{ color: 'var(--color-accent)', flexShrink: 0 }} />
        ) : (
          <img
            src="/title.png"
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
          width: '22px',
          height: '22px',
          backgroundColor: 'var(--color-surface)',
          borderColor: 'var(--color-border)',
          color: 'var(--color-text-muted)',
        }}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
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
        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          className="nav-link"
          style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
        >
          {theme === 'dark' ? <Sun size={17} style={{ flexShrink: 0 }} /> : <Moon size={17} style={{ flexShrink: 0 }} />}
          {!collapsed && (
            <span style={{ color: 'var(--color-text-muted)', fontSize: '12.5px' }}>
              {theme === 'dark' ? 'Light mode' : 'Dark mode'}
            </span>
          )}
        </button>

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
