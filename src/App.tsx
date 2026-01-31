import { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { ShieldCheck, Power, LogOut, Loader2, Shield, Settings, AlertCircle, RefreshCw } from 'lucide-react';
import { CodeList } from './components/CodeList';
import { Auth } from './components/Auth';
import { PrivacyDashboard } from './components/PrivacyDashboard';
import { Settings as SettingsComponent } from './components/Settings';
import { ErrorBoundary } from './components/ErrorBoundary';
import { tauriApi } from './lib/tauri';
import { CodeEntry } from './types/tauri';
import { cn } from './lib/utils';

type View = 'main' | 'privacy' | 'settings';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [currentView, setCurrentView] = useState<View>('main');

  useEffect(() => {
    checkAuth();
    loadCodes();

    const unlisten = listen<CodeEntry[]>('codes-updated', (event) => {
      setCodes(event.payload);
    });

    // Disable right click for app-like feel
    document.addEventListener('contextmenu', event => event.preventDefault());

    return () => {
      unlisten.then(f => f()).catch(console.error);
    };
  }, []);

  const checkAuth = async () => {
    try {
      const status = await tauriApi.getAuthStatus();
      setIsAuthenticated(status);
      setError(null);
    } catch (error) {
      console.error('Failed to check auth status:', error);
      setError('Unable to verify authentication. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const loadCodes = async () => {
    try {
      const recentCodes = await tauriApi.getCodes();
      setCodes(recentCodes);
      setError(null);
    } catch (error) {
      console.error('Failed to load codes:', error);
      setError('Failed to load OTP codes. Please try again.');
    }
  };

  const handleRetry = async () => {
    setError(null);
    setLoading(true);
    await checkAuth();
    await loadCodes();
  };

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
      <div className="h-screen w-full bg-background flex items-center justify-center text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-screen w-full bg-background flex items-center justify-center px-6">
        <div className="max-w-md w-full text-center space-y-4">
          <div className="flex justify-center">
            <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
              <AlertCircle className="h-6 w-6 text-destructive" />
            </div>
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-semibold text-foreground">Something went wrong</h2>
            <p className="text-sm text-muted-foreground">{error}</p>
          </div>
          <button
            onClick={handleRetry}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
          >
            <RefreshCw size={16} />
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen w-full bg-background text-foreground overflow-hidden font-sans antialiased selection:bg-accent selection:text-accent-foreground">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-3 glass-panel border-b border-border/40 shrink-0 select-none drag-region sticky top-0 z-10">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary border border-border/50 shadow-inner-glow">
            <ShieldCheck size={16} className="text-foreground/80" strokeWidth={2} />
          </div>
          <div className="flex flex-col gap-0.5">
            <h1 className="font-semibold text-sm leading-none tracking-tight text-foreground/90">OTPBar</h1>
            <div className="flex items-center gap-1.5">
              <span className={cn(
                "w-1.5 h-1.5 rounded-full transition-all duration-300",
                isAuthenticated
                  ? "bg-status-active glow-active"
                  : "bg-muted-foreground/50"
              )} />
              <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                {isAuthenticated ? 'Active' : 'Offline'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content with ErrorBoundary scoped to content only */}
      <main className="flex-1 overflow-hidden relative">
        <ErrorBoundary>
          {currentView === 'privacy' ? (
            <PrivacyDashboard onBack={handleBackToMain} />
          ) : currentView === 'settings' ? (
            <SettingsComponent onBack={handleBackToMain} />
          ) : isAuthenticated ? (
            <CodeList codes={codes} />
          ) : (
            <Auth onAuthSuccess={() => setIsAuthenticated(true)} />
          )}
        </ErrorBoundary>
        </main>

        {/* Footer */}
        <footer className="flex items-center justify-between px-4 py-2.5 glass-panel border-t border-border/40 shrink-0">
          <div className="flex gap-4">
            {isAuthenticated && currentView === 'main' && (
              <>
                <button
                  onClick={handleShowSettings}
                  className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors group"
                >
                  <Settings size={12} className="opacity-60 group-hover:opacity-100 transition-opacity" />
                  <span>Settings</span>
                </button>
                <button
                  onClick={handleShowPrivacy}
                  className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors group"
                >
                  <Shield size={12} className="opacity-60 group-hover:opacity-100 transition-opacity" />
                  <span>Privacy</span>
                </button>
              </>
            )}
            {isAuthenticated && (
              <button
                onClick={handleLogout}
                className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors group"
              >
                <LogOut size={12} className="opacity-60 group-hover:opacity-100 transition-opacity" />
                <span>Logout</span>
              </button>
            )}
          </div>

          <button
            onClick={handleQuit}
            className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors group ml-auto"
          >
            <Power size={12} className="opacity-60 group-hover:opacity-100 transition-opacity" />
            <span>Quit</span>
          </button>
        </footer>
      </div>
  );
}

export default App;
