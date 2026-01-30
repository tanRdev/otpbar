import React, { useState, useEffect } from 'react';
import { ArrowLeft, ToggleLeft, ToggleRight, AlertCircle, RefreshCw } from 'lucide-react';
import { tauriApi } from '../lib/tauri';
import { cn } from '../lib/utils';

interface PrivacyPreferences {
  auto_copy_enabled: boolean;
  provider_auto_copy: Record<string, boolean>;
}

export const Settings: React.FC<{
  onBack: () => void;
}> = ({ onBack }) => {
  const [preferences, setPreferences] = useState<PrivacyPreferences | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    loadPreferences();
  }, []);

  const loadPreferences = async () => {
    try {
      const prefs = await tauriApi.getPreferences();
      setPreferences(prefs);
      setError(null);
    } catch (error) {
      console.error('Failed to load preferences:', error);
      setError('Unable to load settings. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleAutoCopy = async () => {
    if (!preferences) return;

    const newEnabled = !preferences.auto_copy_enabled;
    try {
      await tauriApi.setAutoCopyEnabled(newEnabled);
      setPreferences({ ...preferences, auto_copy_enabled: newEnabled });
      setActionError(null);
    } catch (error) {
      console.error('Failed to update auto-copy preference:', error);
      setActionError('Failed to update setting. Please try again.');
    }
  };

  const handleRetry = () => {
    setError(null);
    setLoading(true);
    loadPreferences();
  };

  if (loading) {
    return (
      <div className="flex flex-col h-full w-full bg-background">
        <div className="flex items-center justify-center h-full">
          <div className="text-sm text-muted-foreground">Loading...</div>
        </div>
      </div>
    );
  }

  if (!preferences) {
    return (
      <div className="flex flex-col h-full w-full bg-background">
        <header className="flex items-center gap-3 px-4 py-3 glass-panel border-b border-border/40 shrink-0">
          <button
            onClick={onBack}
            aria-label="Back to main view"
            className="flex items-center justify-center w-8 h-8 rounded-lg hover:bg-secondary/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <ArrowLeft size={16} className="text-foreground/80" />
          </button>
          <h1 className="font-semibold text-sm text-foreground/90">Settings</h1>
        </header>
        <div className="flex-1 flex items-center justify-center px-6">
          <div className="max-w-md w-full text-center space-y-4">
            <div className="flex justify-center">
              <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
                <AlertCircle className="h-6 w-6 text-destructive" />
              </div>
            </div>
            <div className="space-y-2">
              <h2 className="text-lg font-semibold text-foreground">No Settings Available</h2>
              <p className="text-sm text-muted-foreground">Unable to load preferences.</p>
            </div>
            <button
              onClick={handleRetry}
              className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              <RefreshCw size={16} />
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col h-full w-full bg-background">
        <header className="flex items-center gap-3 px-4 py-3 glass-panel border-b border-border/40 shrink-0">
          <button
            onClick={onBack}
            aria-label="Back to main view"
            className="flex items-center justify-center w-8 h-8 rounded-lg hover:bg-secondary/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <ArrowLeft size={16} className="text-foreground/80" />
          </button>
          <h1 className="font-semibold text-sm text-foreground/90">Settings</h1>
        </header>
        <div className="flex-1 flex items-center justify-center px-6">
          <div className="max-w-md w-full text-center space-y-4">
            <div className="flex justify-center">
              <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
                <AlertCircle className="h-6 w-6 text-destructive" />
              </div>
            </div>
            <div className="space-y-2">
              <h2 className="text-lg font-semibold text-foreground">Error Loading Settings</h2>
              <p className="text-sm text-muted-foreground">{error}</p>
            </div>
            <button
              onClick={handleRetry}
              className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              <RefreshCw size={16} />
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full w-full bg-background">
      <header className="flex items-center gap-3 px-4 py-3 glass-panel border-b border-border/40 shrink-0">
        <button
          onClick={onBack}
            aria-label="Back to main view"
          className="flex items-center justify-center w-8 h-8 rounded-lg hover:bg-secondary/80 transition-colors"
        >
          <ArrowLeft size={16} className="text-foreground/80" />
        </button>
        <h1 className="font-semibold text-sm text-foreground/90">Settings</h1>
      </header>

      <main className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
        {actionError && (
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 flex items-start gap-3">
            <AlertCircle size={16} className="text-destructive mt-0.5 shrink-0" />
            <div className="flex-1">
              <p className="text-sm text-destructive font-medium">Action Failed</p>
              <p className="text-xs text-destructive/80 mt-1">{actionError}</p>
            </div>
            <button
              onClick={() => setActionError(null)}
              className="text-destructive/70 hover:text-destructive transition-colors text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background rounded px-1"
            >
              Dismiss
            </button>
          </div>
        )}

        <section className="space-y-3">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Privacy
          </h2>

          <div className="bg-card/60 border border-border/30 rounded-lg p-4 shadow-inner-glow">
            <div className="flex items-center justify-between">
              <div className="flex flex-col gap-1">
                <h3 className="text-sm font-medium text-foreground/90">Auto-Copy OTP Codes</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Automatically copy OTP codes to clipboard when received
                </p>
              </div>

              <button
                onClick={handleToggleAutoCopy}
                aria-label={preferences.auto_copy_enabled ? "Disable auto-copy" : "Enable auto-copy"}
                className={cn(
                  "flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
                  preferences.auto_copy_enabled
                    ? "bg-status-active/20 text-status-active border border-status-active/30"
                    : "bg-secondary/80 text-muted-foreground border border-border/30"
                )}
              >
                {preferences.auto_copy_enabled ? (
                  <>
                    <ToggleRight size={16} />
                    <span>On</span>
                  </>
                ) : (
                  <>
                    <ToggleLeft size={16} />
                    <span>Off</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
};
