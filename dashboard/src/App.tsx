import React, { useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider, useTheme } from './context/ThemeContext';
import { Sidebar } from './components/Sidebar';
import { StatusBar } from './components/StatusBar';
import { LiveFeed } from './views/LiveFeed';
import { AlertDetail } from './views/AlertDetail';
import { Stats } from './views/Stats';
import { Metrics } from './views/Metrics';
import { KillChains } from './views/KillChains';
import './App.css';

declare global {
  interface Window {
    VANTA: any;
  }
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

/** Inner app — has access to theme context */
const AppInner: React.FC = () => {
  const { theme } = useTheme();
  const vantaRef = useRef<HTMLDivElement>(null);
  const vantaEffect = useRef<any>(null);

  useEffect(() => {
    const initVanta = () => {
      if (vantaRef.current && window.VANTA) {
        // Destroy existing instance before recreating with new theme colors
        if (vantaEffect.current) vantaEffect.current.destroy();

        vantaEffect.current = window.VANTA.DOTS({
          el: vantaRef.current,
          mouseControls: true,
          touchControls: true,
          gyroControls: false,
          minHeight: 200,
          minWidth: 200,
          scale: 1,
          scaleMobile: 1,
          // Adapt colors to theme
          color: theme === 'dark' ? 0x3730a3 : 0xc8ccdc,
          color2: theme === 'dark' ? 0x1e1b4b : 0xe2e5ef,
          backgroundColor: theme === 'dark' ? 0x0f1117 : 0xf8f9fc,
          size: theme === 'dark' ? 2.5 : 2,
          spacing: theme === 'dark' ? 28 : 32,
        });
      }
    };

    // Wait for Vanta to be available (loaded via CDN)
    if (window.VANTA) {
      initVanta();
    } else {
      const interval = setInterval(() => {
        if (window.VANTA) {
          clearInterval(interval);
          initVanta();
        }
      }, 100);
    }

    return () => {
      if (vantaEffect.current) {
        vantaEffect.current.destroy();
        vantaEffect.current = null;
      }
    };
  }, [theme]); // Re-init when theme changes

  return (
    <BrowserRouter>
      {/* Vanta Background */}
      <div
        ref={vantaRef}
        className="fixed inset-0 z-0 pointer-events-none"
        style={{ opacity: theme === 'dark' ? 0.45 : 0.6 }}
      />

      {/* App Shell */}
      <div
        className="flex h-screen w-screen overflow-hidden relative z-10"
        style={{ backgroundColor: 'transparent' }}
      >
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <StatusBar />
          <main
            className="flex-1 relative overflow-hidden"
            style={{ backgroundColor: 'transparent' }}
          >
            <Routes>
              <Route path="/" element={<LiveFeed />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/stats" element={<Stats />} />
              <Route path="/metrics" element={<Metrics />} />
              <Route path="/kill-chains" element={<KillChains />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AppInner />
      </ThemeProvider>
    </QueryClientProvider>
  );
};
