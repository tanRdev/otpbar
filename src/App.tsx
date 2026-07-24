import { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { Loader2 } from 'lucide-react';
import { CodeList } from './components/CodeList';
import { Auth } from './components/Auth';
import { PrivacyDashboard } from './components/PrivacyDashboard';
import { Settings as SettingsComponent } from './components/Settings';
import { ErrorBoundary } from './components/ErrorBoundary';
import { tauriApi } from './lib/tauri';
import { CodeEntry } from './types/tauri';

type View = 'main' | 'privacy' | 'settings';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [currentView, setCurrentView] = useState<View>('main');

  useEffect(() => {
    const init = async () => {
      try {
        const status = await tauriApi.getAuthStatus();
        setIsAuthenticated(status);
      } catch {
        setError('Unable to verify authentication.');
      }

      try {
        const recentCodes = await tauriApi.getCodes();
        setCodes(recentCodes);
      } catch {
        setError('Failed to load OTP codes.');
      }

      setLoading(false);
    };

    init();

    const unlisten = listen<CodeEntry[]>('codes-updated', (event) => {
      setCodes(event.payload);
    });

    document.addEventListener('contextmenu', event => event.preventDefault());

    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const handleLogout = async () => {
    await tauriApi.logout();
    setIsAuthenticated(false);
    setCodes([]);
  };

  const handleQuit = async () => {
    await tauriApi.quitApp();
  };

  const handleShowPrivacy = () => {
    setCurrentView('privacy');
  };

  const handleBackToMain = () => {
    setCurrentView('main');
  };

  const handleShowSettings = () => {
    setCurrentView('settings');
  };

  if (loading) {
    return (
      <div className="h-screen w-full glass rounded-[14px] flex items-center justify-center">
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-screen w-full glass rounded-[14px] flex flex-col items-center justify-center gap-3 px-6">
        <p className="text-[11px] text-muted-foreground text-center">{error}</p>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="text-[11px] text-foreground/50 underline underline-offset-2 hover:text-foreground transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="flex flex-col h-screen w-full glass rounded-[14px] text-foreground overflow-hidden font-sans">
        <header className="flex items-center justify-between px-4 py-2.5 shrink-0 select-none drag-region">
          <h1 className="text-[12px] font-medium text-foreground/70">OTPBar</h1>
          <div className="flex items-center gap-0 -mr-1">
            {isAuthenticated && currentView === 'main' && (
              <>
                <button
                  type="button"
                  onClick={handleShowSettings}
                  className="px-2.5 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/15 transition-all rounded-md"
                >
                  Settings
                </button>
                <button
                  type="button"
                  onClick={handleShowPrivacy}
                  className="px-2.5 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/15 transition-all rounded-md"
                >
                  Privacy
                </button>
              </>
            )}
            {isAuthenticated && (
              <button
                type="button"
                onClick={handleLogout}
                className="px-2.5 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/15 transition-all rounded-md"
              >
                Logout
              </button>
            )}
            <button
              type="button"
              onClick={handleQuit}
              className="px-2.5 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/15 transition-all rounded-md"
            >
              Quit
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-hidden px-2 pb-2">
          {currentView === 'privacy' ? (
            <PrivacyDashboard onBack={handleBackToMain} />
          ) : currentView === 'settings' ? (
            <SettingsComponent onBack={handleBackToMain} />
          ) : isAuthenticated ? (
            <CodeList codes={codes} />
          ) : (
            <Auth onAuthSuccess={() => setIsAuthenticated(true)} />
          )}
        </main>
      </div>
    </ErrorBoundary>
  );
}

export default App;
