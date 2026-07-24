import React, { useState } from 'react';
import { tauriApi } from '../lib/tauri';

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
    <div className="flex flex-col items-center justify-center h-full gap-5 px-6">
      <div className="text-center">
        <p className="text-[12px] font-medium text-foreground/80">Sign in to get started</p>
        <p className="text-[11px] text-muted-foreground mt-1.5">
          Connect your Gmail account to receive OTP codes
        </p>
      </div>

      <button
        type="button"
        onClick={handleLogin}
        disabled={loading}
        className="px-5 py-2 bg-primary/80 text-white text-[11px] font-medium rounded-lg hover:bg-primary transition-colors disabled:opacity-50"
      >
        {loading ? 'Connecting...' : 'Sign in with Google'}
      </button>

      {error && (
        <p className="text-[10px] text-destructive text-center">{error}</p>
      )}
    </div>
  );
};
