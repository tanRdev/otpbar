import React, { useState, useEffect, useRef } from 'react';
import { Copy, Check, Clock } from 'lucide-react';
import { CodeEntry } from '../types/tauri';
import { tauriApi } from '../lib/tauri';
import { cn } from '../lib/utils';

interface CodeCardProps {
  entry: CodeEntry;
}

export const CodeCard: React.FC<CodeCardProps> = ({ entry }) => {
  const [copied, setCopied] = useState(false);
  const [countdown, setCountdown] = useState<number | null>(null);
  const countdownRef = useRef<NodeJS.Timeout | null>(null);
  const countdownStartRef = useRef<number | null>(null);
  const isStartingRef = useRef(false);
  const isMountedRef = useRef(true);

  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      if (countdownRef.current) {
        clearInterval(countdownRef.current);
        countdownRef.current = null;
      }
      isStartingRef.current = false;
    };
  }, []);

  const handleCopy = async () => {
    if (isStartingRef.current) {
      return;
    }

    try {
      isStartingRef.current = true;
      await tauriApi.copyCodeWithExpiry(entry.code);
      if (!isMountedRef.current) return;
      setCopied(true);

      const config = await tauriApi.getClipboardConfig();
      const timeout = config.timeout_seconds;
      if (!isMountedRef.current) return;

      if (countdownRef.current) {
        clearInterval(countdownRef.current);
        countdownRef.current = null;
      }

      countdownStartRef.current = Date.now();
      setCountdown(timeout);

      countdownRef.current = setInterval(() => {
        if (!isMountedRef.current) return;

        const elapsed = Math.floor((Date.now() - (countdownStartRef.current || 0)) / 1000);
        const remaining = timeout - elapsed;

        if (remaining <= 0) {
          setCountdown(null);
          setCopied(false);
          if (countdownRef.current) {
            clearInterval(countdownRef.current);
            countdownRef.current = null;
          }
          isStartingRef.current = false;
        } else {
          setCountdown(remaining);
        }
      }, 1000);
    } catch (error) {
      console.error('Failed to copy code:', error);
      isStartingRef.current = false;
    }
  };

  const timeDisplay = React.useMemo(() => {
    try {
      const date = new Date(entry.timestamp);
      const now = new Date();
      if (now.getTime() - date.getTime() < 24 * 60 * 60 * 1000) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
      return date.toLocaleDateString();
    } catch (e) {
      return '';
    }
  }, [entry.timestamp]);

  const isRecent = React.useMemo(() => {
    try {
      const date = new Date(entry.timestamp);
      const now = new Date();
      return now.getTime() - date.getTime() < 5 * 60 * 1000;
    } catch {
      return false;
    }
  }, [entry.timestamp]);

  return (
    <div
      onClick={handleCopy}
      className={cn(
        "group relative flex items-center justify-between p-3 rounded-lg",
        "bg-card/60 border border-border/30",
        "cursor-pointer transition-all duration-200",
        "hover:bg-card hover:border-border/50",
        "shadow-inner-glow",
        copied && "bg-status-active/10 border-status-active/30"
      )}
    >
      <div className="flex flex-col gap-1.5 min-w-0">
        <div className="flex items-center gap-2">
          {isRecent && (
            <span className="w-1.5 h-1.5 rounded-full bg-status-active glow-active shrink-0" />
          )}
          <h3 className="text-sm font-medium text-foreground/90 truncate max-w-[160px]">
            {entry.provider || entry.sender}
          </h3>
        </div>

        <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <Clock size={10} className="opacity-50" />
          <span>{timeDisplay}</span>
          <span className="text-muted-foreground/40 mx-1">|</span>
          <span className="truncate max-w-[100px] opacity-70">{entry.sender}</span>
        </div>
      </div>

      <div className="flex items-center gap-2.5 pl-3 shrink-0">
        <div className="flex flex-col items-end gap-0.5">
          <span className={cn(
            "font-mono text-base font-semibold tracking-widest tabular-nums transition-colors",
            copied ? "text-status-active" : "text-foreground"
          )}>
            {entry.code}
          </span>
          {countdown !== null && (
            <div className="flex items-center gap-1 text-[10px] text-status-active font-medium tabular-nums">
              <Clock size={8} className="opacity-70" />
              <span>{countdown}s</span>
            </div>
          )}
        </div>

        <div className={cn(
          "flex items-center justify-center w-7 h-7 rounded-md transition-all duration-200",
          copied
            ? "bg-status-active text-primary-foreground"
            : "bg-secondary/80 text-muted-foreground opacity-0 group-hover:opacity-100"
        )}>
          {copied ? <Check size={12} strokeWidth={3} /> : <Copy size={12} />}
        </div>
      </div>
    </div>
  );
};
