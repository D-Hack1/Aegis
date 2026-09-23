import React from 'react';
import { useTheme } from '../context/ThemeContext';

export const ThemeSwitch: React.FC = () => {
  const { theme, toggleTheme } = useTheme();

  const handleChange = () => {
    toggleTheme();
  };

  return (
    <label className="switch">
      <input
        type="checkbox"
        className="toggle"
        checked={theme === 'dark'}
        onChange={handleChange}
      />
      <span className="slider"></span>
      <span className="card-side"></span>
    </label>
  );
};
