import { useEffect, useRef, useState } from 'react';
import {
  Shield,
  FolderOpen,
  Key,
  Clock,
  Settings,
  ArrowLeft,
  HardDrive,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { cn } from '../lib/utils';

interface PrivacyData {
  dataLocations: {
    configPath: string;
    historyPath: string;
    keychainItems: string[];
  };
  permissions: {
    scopes: string[];
    hasAccessToken: boolean;
    hasRefreshToken: boolean;
  };
  activity: {
    totalCodes: number;
    lastActivity: number | null;
    historyRetention: number;
  };
  retention: {
    maxHistorySize: number;
    currentSize: number;
  };
}

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
    loadPrivacyData();

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const loadPrivacyData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await window.__OTPBAR__.getPrivacyData();
      setPrivacyData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load privacy data');
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      setClearing(true);
      setError(null);
      setSuccessMessage(null);

      await window.__OTPBAR__.clearHistory();

      // Refresh privacy data after clearing
      const updatedData = await window.__OTPBAR__.getPrivacyData();
      setPrivacyData(updatedData);

      // Show success message
      setSuccessMessage('History cleared successfully');

      // Clear success message after 3 seconds
      const timeoutId = setTimeout(() => {
        setSuccessMessage(null);
        timeoutRef.current = null;
      }, 3000);
      timeoutRef.current = timeoutId;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear history');
    } finally {
      setClearing(false);
    }
  };

  const formatTimestamp = (timestamp: number | null): string => {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const formatRetention = (days: number): string => {
    if (days === 0) return 'Forever';
    if (days === 1) return '1 day';
    return `${days} days`;
  };

  if (loading) {
    return (
      <div className="flex flex-col h-full w-full">
        <div className="flex items-center justify-center h-full">
          <div className="flex flex-col items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-secondary/80 flex items-center justify-center border border-border/30">
              <Clock className="h-4 w-4 animate-spin text-muted-foreground" />
            </div>
            <span className="text-xs font-medium text-muted-foreground">Loading privacy data...</span>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col h-full w-full">
        <div className="flex items-center justify-center h-full">
          <div className="flex flex-col items-center gap-3 max-w-[250px] text-center">
            <div className="w-10 h-10 rounded-xl bg-destructive/10 flex items-center justify-center border border-border/30">
              <AlertCircle className="h-4 w-4 text-destructive" strokeWidth={1.5} />
            </div>
            <div className="flex flex-col gap-1">
              <h3 className="text-sm font-medium text-foreground/80">Error</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">{error}</p>
            </div>
            <button
              onClick={loadPrivacyData}
              className="mt-2 px-3 py-1.5 text-xs font-medium bg-secondary hover:bg-accent text-foreground rounded-lg border border-border/50 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!privacyData) return null;

  return (
    <div className="flex flex-col h-full w-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-border/40 shrink-0">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft size={14} />
          <span>Back</span>
        </button>
        <div className="flex-1" />
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-secondary/80 flex items-center justify-center border border-border/50">
            <Shield size={14} className="text-muted-foreground" strokeWidth={2} />
          </div>
          <h1 className="text-sm font-semibold text-foreground/90">Privacy Dashboard</h1>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
        {/* Data Location Panel */}
        <section className="rounded-xl bg-card border border-border/40 overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border/30 bg-secondary/30">
            <FolderOpen size={14} className="text-muted-foreground" strokeWidth={2} />
            <h2 className="text-xs font-semibold text-foreground/90 uppercase tracking-wider">Data Location</h2>
          </div>
          <div className="p-3 space-y-2">
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-medium text-muted-foreground uppercase">Config Directory</span>
              </div>
              <code className="block text-[11px] font-mono text-foreground/70 bg-secondary/50 px-2 py-1.5 rounded border border-border/30 break-all">
                {privacyData.dataLocations.configPath}
              </code>
            </div>
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-medium text-muted-foreground uppercase">History File</span>
              </div>
              <code className="block text-[11px] font-mono text-foreground/70 bg-secondary/50 px-2 py-1.5 rounded border border-border/30 break-all">
                {privacyData.dataLocations.historyPath}
              </code>
            </div>
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-medium text-muted-foreground uppercase">Keychain Items</span>
                <span className="text-[10px] font-medium text-status-accent">
                  {privacyData.dataLocations.keychainItems.length} stored
                </span>
              </div>
              <div className="flex flex-wrap gap-1">
                {privacyData.dataLocations.keychainItems.map((item, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-medium bg-secondary/50 rounded border border-border/30 text-foreground/70"
                  >
                    <Key size={8} />
                    {item}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Permissions Panel */}
        <section className="rounded-xl bg-card border border-border/40 overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border/30 bg-secondary/30">
            <Key size={14} className="text-muted-foreground" strokeWidth={2} />
            <h2 className="text-xs font-semibold text-foreground/90 uppercase tracking-wider">Permissions</h2>
          </div>
          <div className="p-3 space-y-3">
            <div className="space-y-1.5">
              <span className="text-[10px] font-medium text-muted-foreground uppercase">OAuth Scopes</span>
              <div className="space-y-1">
                {privacyData.permissions.scopes.map((scope, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <CheckCircle2 size={12} className="text-status-active shrink-0 mt-0.5" />
                    <code className="text-[11px] font-mono text-foreground/70 flex-1">
                      {scope}
                    </code>
                  </div>
                ))}
              </div>
            </div>
            <div className="pt-2 border-t border-border/20">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-medium text-muted-foreground uppercase">Token Status</span>
              </div>
              <div className="flex gap-2 mt-1.5">
                <div className="flex items-center gap-1.5 px-2 py-1 bg-secondary/30 rounded border border-border/30">
                  <div className={cn(
                    "w-1.5 h-1.5 rounded-full",
                    privacyData.permissions.hasAccessToken ? "bg-status-active" : "bg-muted-foreground/50"
                  )} />
                  <span className="text-[10px] text-foreground/70">Access Token</span>
                </div>
                <div className="flex items-center gap-1.5 px-2 py-1 bg-secondary/30 rounded border border-border/30">
                  <div className={cn(
                    "w-1.5 h-1.5 rounded-full",
                    privacyData.permissions.hasRefreshToken ? "bg-status-active" : "bg-muted-foreground/50"
                  )} />
                  <span className="text-[10px] text-foreground/70">Refresh Token</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Activity Timeline */}
        <section className="rounded-xl bg-card border border-border/40 overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border/30 bg-secondary/30">
            <Clock size={14} className="text-muted-foreground" strokeWidth={2} />
            <h2 className="text-xs font-semibold text-foreground/90 uppercase tracking-wider">Activity</h2>
          </div>
          <div className="p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">Total Codes Captured</span>
              <span className="text-xs font-semibold text-foreground">{privacyData.activity.totalCodes}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">Last Activity</span>
              <span className="text-xs font-medium text-foreground">
                {formatTimestamp(privacyData.activity.lastActivity)}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">History Retention</span>
              <span className="text-xs font-medium text-foreground">
                {formatRetention(privacyData.activity.historyRetention)}
              </span>
            </div>
          </div>
        </section>

        {/* Data Retention Controls */}
        <section className="rounded-xl bg-card border border-border/40 overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border/30 bg-secondary/30">
            <Settings size={14} className="text-muted-foreground" strokeWidth={2} />
            <h2 className="text-xs font-semibold text-foreground/90 uppercase tracking-wider">Data Retention</h2>
          </div>
          <div className="p-3 space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-muted-foreground">History Size</span>
                <span className="text-[10px] text-muted-foreground">
                  {privacyData.retention.currentSize} / {privacyData.retention.maxHistorySize}
                </span>
              </div>
              <div className="w-full bg-secondary/50 rounded-full h-1.5 overflow-hidden">
                <div
                  className="h-full bg-status-accent rounded-full transition-all"
                  style={{
                    width: `${(privacyData.retention.currentSize / privacyData.retention.maxHistorySize) * 100}%`
                  }}
                />
              </div>
            </div>
            <div className="pt-2 border-t border-border/20">
              {successMessage && (
                <div className="mb-2 px-2 py-1.5 bg-status-active/10 border border-status-active/30 rounded-lg flex items-center gap-1.5">
                  <CheckCircle2 size={10} className="text-status-active" />
                  <span className="text-[10px] font-medium text-status-active">{successMessage}</span>
                </div>
              )}
              <button
                onClick={handleClearHistory}
                disabled={clearing}
                className="w-full px-3 py-2 text-[11px] font-medium bg-destructive/10 hover:bg-destructive/20 text-destructive rounded-lg border border-destructive/30 transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <HardDrive size={12} className={clearing ? 'animate-pulse' : ''} />
                {clearing ? 'Clearing...' : 'Clear All History'}
              </button>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
