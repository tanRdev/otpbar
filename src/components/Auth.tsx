import React, { useState } from 'react';
import { Mail, Loader2, AlertCircle, ArrowRight } from 'lucide-react';
import { tauriApi } from '../lib/tauri';
import { cn } from '../lib/utils';

interface AuthProps {
  onAuthSuccess?: () => void;
}

export const Auth: React.FC<AuthProps> = ({ onAuthSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await tauriApi.startAuth();
      if (result.success) {
        onAuthSuccess?.();
      } else if (result.error) {
        setError(result.error);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center h-full p-6 text-center">
      <div className="w-full max-w-[260px] flex flex-col items-center gap-5">
        <div className="flex flex-col items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-secondary/80 flex items-center justify-center border border-border/30 shadow-inner-glow">
            <Mail className="text-foreground/70 w-5 h-5" strokeWidth={1.5} />
          </div>
          <div className="flex flex-col gap-1">
            <h2 className="text-foreground/90 font-semibold tracking-tight text-base">
              Connect Account
            </h2>
            <p className="text-muted-foreground text-xs leading-relaxed">
              Sign in with Google to sync OTP codes
            </p>
          </div>
        </div>

        <button
          onClick={handleLogin}
          disabled={loading}
          className={cn(
            "group relative w-full flex items-center justify-center gap-2 px-4 py-2.5",
            "bg-foreground/90 text-background text-sm font-medium rounded-lg",
            "hover:bg-foreground transition-all duration-200",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
            "disabled:opacity-50 disabled:pointer-events-none"
          )}
        >
          {loading ? (
            <>
              <Loader2 className="animate-spin w-3.5 h-3.5" />
              <span>Connecting...</span>
            </>
          ) : (
            <>
              <span>Sign in with Google</span>
              <ArrowRight className="w-3.5 h-3.5 opacity-60 group-hover:translate-x-0.5 transition-transform" />
            </>
          )}
        </button>

        {error && (
          <div className="flex items-start gap-2 p-3 rounded-lg border border-destructive/20 bg-destructive/5 text-destructive text-xs w-full text-left">
            <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span className="break-words leading-relaxed">{error}</span>
          </div>
        )}
      </div>
    </div>
  );
};
