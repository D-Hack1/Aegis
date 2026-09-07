import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Activity, BarChart2, Link2 } from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { name: 'Live Feed', path: '/', icon: <Shield size={20} /> },
    { name: 'Metrics', path: '/metrics', icon: <Activity size={20} /> },
    { name: 'Stats', path: '/stats', icon: <BarChart2 size={20} /> },
    { name: 'Kill Chains', path: '/kill-chains', icon: <Link2 size={20} /> },
  ];

  return (
    <div className="w-64 border-r border-zinc-800 bg-zinc-900/50 backdrop-blur flex flex-col h-full">
      <div className="p-6 flex items-center justify-center border-b border-zinc-800">
        <img 
          src="/title.png" 
          alt="Aegis Logo" 
          className="h-10 w-auto object-contain"
        />
      </div>
      
      <div className="flex-1 py-6 flex flex-col gap-2 px-4">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 font-medium ${
                isActive
                  ? 'bg-zinc-800 text-sky-500 shadow-[inset_2px_0_0_#38bdf8]'
                  : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200'
              }`
            }
          >
            {item.icon}
            <span>{item.name}</span>
          </NavLink>
        ))}
      </div>
      
      <div className="p-6 text-xs text-zinc-700 font-mono text-center">
        v1.0.0 — SOC COMMAND
      </div>
    </div>
  );
};
