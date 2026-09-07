import React, { useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Sidebar } from './components/Sidebar';
import { StatusBar } from './components/StatusBar';
import { LiveFeed } from './views/LiveFeed';
import { AlertDetail } from './views/AlertDetail';
import { Stats } from './views/Stats';
import { Metrics } from './views/Metrics';
import { KillChains } from './views/KillChains';

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

export const App: React.FC = () => {
  const vantaRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let vantaEffect: any = null;
    if (vantaRef.current && window.VANTA) {
      vantaEffect = window.VANTA.DOTS({
        el: vantaRef.current,
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00,
        color: 0xdedddd,
        color2: 0xd7d7d7,
        backgroundColor: 0x09090b // Match zinc-950
      });
    }
    return () => {
      if (vantaEffect) vantaEffect.destroy();
    };
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {/* Vanta Background Container */}
        <div 
          ref={vantaRef} 
          className="fixed inset-0 z-0 opacity-50 pointer-events-none"
        />
        
        <div className="flex h-screen w-screen bg-zinc-950/50 text-zinc-100 overflow-hidden relative z-10">
          <Sidebar />
          <div className="flex-1 flex flex-col min-w-0">
            <StatusBar />
            <main className="flex-1 relative overflow-hidden bg-transparent">
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
    </QueryClientProvider>
  );
};
