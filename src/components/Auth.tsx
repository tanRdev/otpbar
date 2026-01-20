import React, { useState } from 'react';
import { Mail, Loader2, AlertCircle } from 'lucide-react';
import { tauriApi } from '../lib/tauri';

export const Auth: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await tauriApi.startAuth();
      if (!result.success && result.error) {
        setError(result.error);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center h-full p-6 gap-6 border-t border-terminal-border min-h-[300px]">
      <div className="flex flex-col items-center gap-2 text-center">
        <div className="w-12 h-12 border border-terminal-accent/30 rounded-none flex items-center justify-center bg-terminal-accent/5 mb-2">
           <Mail className="text-terminal-accent w-6 h-6" />
        </div>
        <h2 className="text-terminal-fg font-bold uppercase tracking-widest text-sm">Authentication Required</h2>
        <p className="text-terminal-dim text-xs max-w-[200px] leading-relaxed">
          Connect your Gmail account to start monitoring for OTP codes.
        </p>
      </div>

      <button
        onClick={handleLogin}
        disabled={loading}
        className="group relative px-6 py-3 bg-terminal-accent/10 hover:bg-terminal-accent/20 border border-terminal-accent text-terminal-accent text-sm font-bold tracking-widest uppercase transition-all active:translate-y-[1px]"
      >
        {loading ? (
          <span className="flex items-center gap-2">
            <Loader2 className="animate-spin w-4 h-4" />
            Connecting...
          </span>
        ) : (
          <span className="flex items-center gap-2">
            Sign In With Gmail
            <span className="block w-1.5 h-1.5 bg-terminal-accent ml-1 opacity-0 group-hover:opacity-100 transition-opacity animate-pulse" />
          </span>
        )}
      </button>

      {error && (
        <div className="flex items-start gap-2 p-3 border border-red-900/50 bg-red-900/10 text-red-400 text-xs font-mono w-full max-w-[260px]">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span className="break-words">{error}</span>
        </div>
      )}
    </div>
  );
};
