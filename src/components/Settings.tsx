import React, { useState, useEffect } from "react";
import { tauriApi } from "../lib/tauri";

interface PrivacyPreferences {
  auto_copy_enabled: boolean;
  provider_auto_copy: Record<string, boolean>;
}

export const Settings: React.FC<{
  onBack: () => void;
}> = ({ onBack }) => {
  const [preferences, setPreferences] = useState<PrivacyPreferences | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const init = async () => {
      try {
        const prefs = await tauriApi.getPreferences();
        setPreferences(prefs);
      } catch {
        setError("Unable to load preferences.");
      } finally {
        setLoading(false);
      }
    };

    init();
  }, []);

  const handleToggleAutoCopy = async () => {
    if (!preferences) return;

    const newEnabled = !preferences.auto_copy_enabled;
    try {
      await tauriApi.setAutoCopyEnabled(newEnabled);
      setPreferences({ ...preferences, auto_copy_enabled: newEnabled });
    } catch {
      setError("Failed to update setting.");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <span className="text-[11px] text-muted-foreground">Loading...</span>
      </div>
    );
  }

  if (error || !preferences) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 px-6">
        <p className="text-[11px] text-muted-foreground text-center">
          {error || "Unable to load preferences."}
        </p>
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
    <div className="flex flex-col h-full w-full">
      <div className="flex items-center gap-2 px-3 py-2.5 shrink-0">
        <button
          type="button"
          onClick={onBack}
          className="px-2 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/15 transition-all rounded-md"
        >
          ← Back
        </button>
        <span className="text-[12px] font-medium text-foreground/70">
          Settings
        </span>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3">
        <div className="flex items-center justify-between py-3 px-3 rounded-lg hover:bg-white/10 transition-colors">
          <div>
            <p className="text-[12px] font-medium text-foreground/80">
              Auto-Copy OTP Codes
            </p>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              Copy codes automatically when received
            </p>
          </div>
          <button
            type="button"
            onClick={handleToggleAutoCopy}
            className={`relative w-9 h-5 rounded-full transition-colors ${
              preferences.auto_copy_enabled ? "bg-status-active" : "bg-black/10"
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform ${
                preferences.auto_copy_enabled
                  ? "translate-x-4"
                  : "translate-x-0"
              }`}
            />
          </button>
        </div>
      </div>
    </div>
  );
};
