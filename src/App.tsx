import { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { Terminal, Power, LogOut } from 'lucide-react';
import { CodeList } from './components/CodeList';
import { Auth } from './components/Auth';
import { tauriApi } from './lib/tauri';
import { CodeEntry } from './types/tauri';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    checkAuth();
    loadCodes();

    const unlisten = listen<CodeEntry[]>('codes-updated', (event) => {
      setCodes(event.payload);
    });

    // Disable right click for app-like feel
    document.addEventListener('contextmenu', event => event.preventDefault());

    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const checkAuth = async () => {
    try {
      const status = await tauriApi.getAuthStatus();
      setIsAuthenticated(status);
    } catch (error) {
      console.error('Failed to check auth status:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadCodes = async () => {
    try {
      const recentCodes = await tauriApi.getCodes();
      setCodes(recentCodes);
    } catch (error) {
      console.error('Failed to load codes:', error);
    }
  };

  const handleLogout = async () => {
    await tauriApi.logout();
    setIsAuthenticated(false);
    setCodes([]);
  };

  const handleQuit = async () => {
    await tauriApi.quitApp();
  };

  if (loading) {
    return <div className="h-screen w-full bg-terminal-bg flex items-center justify-center text-terminal-accent font-mono animate-pulse">INITIALIZING...</div>;
  }

  return (
    <div className="flex flex-col h-screen w-full bg-terminal-bg text-terminal-fg font-mono overflow-hidden border border-terminal-border/50">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-3 bg-terminal-bg border-b border-terminal-border shrink-0 select-none drag-region">
        <div className="flex items-center gap-2 group">
          <Terminal size={16} className="text-terminal-accent" />
          <h1 className="font-bold tracking-[0.2em] text-sm text-terminal-fg group-hover:text-terminal-accent transition-colors">OTPBAR</h1>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2 py-0.5 border border-terminal-border bg-terminal-selection/50">
            <div className={`w-1.5 h-1.5 rounded-full ${isAuthenticated ? 'bg-terminal-accent shadow-[0_0_4px_#4af626]' : 'bg-red-500 shadow-[0_0_4px_red]'} transition-colors duration-500`} />
            <span className="text-[10px] uppercase tracking-widest text-terminal-dim">
              {isAuthenticated ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden relative bg-terminal-bg">
        {/* CRT Scanline effect overlay */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] z-10 pointer-events-none bg-[length:100%_2px,3px_100%] opacity-20"></div>

        {isAuthenticated ? (
          <CodeList codes={codes} />
        ) : (
          <Auth />
        )}
      </main>

      {/* Footer */}
      <footer className="flex items-center justify-between px-3 py-2 bg-terminal-bg border-t border-terminal-border shrink-0 text-[10px] text-terminal-dim">
        <div className="flex gap-4">
          {isAuthenticated && (
            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 hover:text-red-400 transition-colors uppercase tracking-wider group"
            >
              <LogOut size={12} />
              <span className="group-hover:underline decoration-red-400/50 underline-offset-2">Logout</span>
            </button>
          )}
        </div>

        <button
          onClick={handleQuit}
          className="flex items-center gap-1.5 hover:text-terminal-fg transition-colors uppercase tracking-wider group ml-auto"
        >
          <Power size={12} />
          <span className="group-hover:underline decoration-terminal-fg/50 underline-offset-2">Quit</span>
        </button>
      </footer>
    </div>
  );
}

export default App;
