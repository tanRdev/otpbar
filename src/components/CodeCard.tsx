import React, { useState, useEffect, useRef } from 'react';
import { CodeEntry } from '../types/tauri';
import { tauriApi } from '../lib/tauri';

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
    if (isStartingRef.current) return;

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
    } catch {
      return '';
    }
  }, [entry.timestamp]);

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-white/20 active:bg-white/25 transition-all cursor-default text-left rounded-lg"
    >
      <div className="min-w-0 flex-1">
        <p className="text-[10px] text-muted-foreground truncate uppercase tracking-wide">
          {entry.provider || entry.sender}
        </p>
        <p className="font-mono text-[17px] tracking-[0.2em] tabular-nums mt-1 font-medium text-foreground/90">
          {entry.code}
        </p>
      </div>
      <div className="flex flex-col items-end gap-1 ml-3 shrink-0">
        <span className="text-[10px] text-muted-foreground/70 tabular-nums">
          {timeDisplay}
        </span>
        {countdown !== null && (
          <span className="text-[10px] text-status-active font-medium tabular-nums">
            {countdown}s
          </span>
        )}
        {copied && countdown === null && (
          <span className="text-[10px] text-status-active font-medium">
            Copied
          </span>
        )}
      </div>
    </button>
  );
};
