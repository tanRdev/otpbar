import { useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { tauriApi } from "../lib/tauri";
import type { PrivacyData } from "../types/tauri";

export const PrivacyDashboard: React.FC<{
  onBack: () => void;
}> = ({ onBack }) => {
  const [privacyData, setPrivacyData] = useState<PrivacyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    const init = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await tauriApi.getPrivacyData();
        setPrivacyData(data);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load privacy data",
        );
      } finally {
        setLoading(false);
      }
    };

    init();

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const loadPrivacyData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await tauriApi.getPrivacyData();
      setPrivacyData(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load privacy data",
      );
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      setClearing(true);
      setError(null);
      setSuccessMessage(null);

      await tauriApi.clearHistory();

      const updatedData = await tauriApi.getPrivacyData();
      setPrivacyData(updatedData);

      setSuccessMessage("History cleared");

      const timeoutId = setTimeout(() => {
        setSuccessMessage(null);
        timeoutRef.current = null;
      }, 3000);
      timeoutRef.current = timeoutId;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to clear history");
    } finally {
      setClearing(false);
    }
  };

  const formatTimestamp = (timestamp: number | null): string => {
    if (!timestamp) return "Never";
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const formatRetention = (days: number): string => {
    if (days === 0) return "Forever";
    if (days === 1) return "1 day";
    return `${days} days`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <span className="text-[11px] text-muted-foreground">Loading...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 px-6">
        <p className="text-[11px] text-muted-foreground text-center">{error}</p>
        <button
          type="button"
          onClick={loadPrivacyData}
          className="text-[11px] text-foreground/50 underline underline-offset-2 hover:text-foreground transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!privacyData) return null;

  return (
    <div className="flex flex-col h-full w-full overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2.5 shrink-0">
        <button
          type="button"
          onClick={onBack}
          className="px-2 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-white/15 transition-all rounded-md"
        >
          ← Back
        </button>
        <span className="text-[12px] font-medium text-foreground/70">
          Privacy
        </span>
      </div>

      <div className="flex-1 overflow-y-auto px-3 pb-3 space-y-3">
        <section className="p-3 rounded-lg bg-white/10 space-y-2">
          <h2 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">
            Data Location
          </h2>
          <div className="space-y-1">
            <div className="flex justify-between text-[11px]">
              <span className="text-muted-foreground">Config</span>
              <code className="text-[10px] font-mono text-foreground/50 truncate ml-4 max-w-[140px]">
                {privacyData.dataLocations.configPath}
              </code>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-muted-foreground">History</span>
              <code className="text-[10px] font-mono text-foreground/50 truncate ml-4 max-w-[140px]">
                {privacyData.dataLocations.historyPath}
              </code>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-muted-foreground">Keychain</span>
              <span className="text-[10px] text-foreground/50">
                {privacyData.dataLocations.keychainItems.length} stored
              </span>
            </div>
          </div>
        </section>

        <section className="p-3 rounded-lg bg-white/10 space-y-2">
          <h2 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">
            Permissions
          </h2>
          <div className="space-y-0.5">
            {privacyData.permissions.scopes.map((scope) => (
              <div key={scope} className="flex items-center gap-2 text-[11px]">
                <CheckCircle2
                  size={10}
                  className="text-status-active shrink-0"
                />
                <code className="text-[10px] font-mono text-foreground/50">
                  {scope}
                </code>
              </div>
            ))}
          </div>
          <div className="flex gap-3 pt-1">
            <div className="flex items-center gap-1.5 text-[11px]">
              <div
                className={`w-1.5 h-1.5 rounded-full ${privacyData.permissions.hasAccessToken ? "bg-status-active" : "bg-black/10"}`}
              />
              <span className="text-muted-foreground">Access Token</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px]">
              <div
                className={`w-1.5 h-1.5 rounded-full ${privacyData.permissions.hasRefreshToken ? "bg-status-active" : "bg-black/10"}`}
              />
              <span className="text-muted-foreground">Refresh Token</span>
            </div>
          </div>
        </section>

        <section className="p-3 rounded-lg bg-white/10 space-y-2">
          <h2 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">
            Activity
          </h2>
          <div className="space-y-1 text-[11px]">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Codes</span>
              <span className="font-medium text-foreground/80">
                {privacyData.activity.totalCodes}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Last Activity</span>
              <span className="font-medium text-foreground/80">
                {formatTimestamp(privacyData.activity.lastActivity)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">History Retention</span>
              <span className="font-medium text-foreground/80">
                {formatRetention(privacyData.activity.historyRetention)}
              </span>
            </div>
          </div>
        </section>

        <section className="p-3 rounded-lg bg-white/10 space-y-3">
          <h2 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">
            Data Retention
          </h2>
          <div>
            <div className="flex justify-between text-[11px] mb-1.5">
              <span className="text-muted-foreground">History Size</span>
              <span className="text-muted-foreground">
                {privacyData.retention.currentSize} /{" "}
                {privacyData.retention.maxHistorySize}
              </span>
            </div>
            <div className="w-full bg-black/5 rounded-full h-1 overflow-hidden">
              <div
                className="h-full bg-status-accent/60 rounded-full transition-all"
                style={{
                  width: `${(privacyData.retention.currentSize / privacyData.retention.maxHistorySize) * 100}%`,
                }}
              />
            </div>
          </div>

          {successMessage && (
            <div className="flex items-center gap-1.5 text-[11px] text-status-active">
              <CheckCircle2 size={10} />
              <span>{successMessage}</span>
            </div>
          )}

          <button
            type="button"
            onClick={handleClearHistory}
            disabled={clearing}
            className="w-full px-3 py-2 text-[11px] font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors disabled:opacity-50"
          >
            {clearing ? "Clearing..." : "Clear All History"}
          </button>
        </section>
      </div>
    </div>
  );
};
