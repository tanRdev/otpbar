import React, { useState } from "react";
import { tauriApi } from "../lib/tauri";
import { AuthorizationStatus } from "../types/tauri";

interface AuthProps {
  authorization: AuthorizationStatus;
}

export const Auth: React.FC<AuthProps> = ({ authorization }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async () => {
    setLoading(true);
    setError(null);
    try {
      await tauriApi.beginAuthorization();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    try {
      await tauriApi.cancelAuthorization();
    } catch (e) {
      setError(String(e));
    }
  };

  const inProgress = ["starting", "awaiting_browser", "exchanging"].includes(
    authorization.status,
  );

  return (
    <div className="flex flex-col items-center justify-center h-full gap-5 px-6">
      <div className="text-center">
        <p className="text-[12px] font-medium text-foreground/80">
          Sign in to get started
        </p>
        <p className="text-[11px] text-muted-foreground mt-1.5">
          Connect your Gmail account to receive OTP codes
        </p>
      </div>

      <button
        type="button"
        onClick={handleLogin}
        disabled={loading || inProgress}
        className="px-5 py-2 bg-primary/80 text-white text-[11px] font-medium rounded-lg hover:bg-primary transition-colors disabled:opacity-50"
      >
        {loading || inProgress ? "Connecting..." : "Sign in with Google"}
      </button>

      {inProgress && (
        <button
          type="button"
          onClick={handleCancel}
          className="text-[11px] text-muted-foreground underline"
        >
          Cancel
        </button>
      )}

      {authorization.status === "configuration_missing" && (
        <p className="text-[10px] text-destructive text-center">
          Google Authorization is not configured in this build.
        </p>
      )}

      {error && (
        <p className="text-[10px] text-destructive text-center">{error}</p>
      )}
    </div>
  );
};
