import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { CodeEntry } from '../types/tauri';
import { tauriApi } from '../lib/tauri';

interface CodeCardProps {
  entry: CodeEntry;
}

export const CodeCard: React.FC<CodeCardProps> = ({ entry }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await tauriApi.copyCode(entry.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      onClick={handleCopy}
      className="group relative flex flex-col gap-1 p-3 border-b border-terminal-border hover:bg-terminal-selection cursor-pointer transition-colors duration-150"
    >
      <div className="flex justify-between items-baseline">
        <h3 className="text-sm font-bold tracking-wider uppercase text-terminal-fg/90 group-hover:text-terminal-fg">
          {entry.provider}
        </h3>
        <span className="text-xs text-terminal-dim font-mono">
          {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </span>
      </div>

      <div className="flex justify-between items-center mt-1">
        <span className="text-xl font-mono font-bold tracking-[0.1em] text-terminal-accent drop-shadow-[0_0_2px_rgba(74,246,38,0.3)]">
          {entry.code}
        </span>

        <div className="text-terminal-accent opacity-0 group-hover:opacity-100 transition-opacity">
          {copied ? <Check size={16} /> : <Copy size={16} />}
        </div>
      </div>

      <div className="text-[10px] text-terminal-dim truncate mt-1 opacity-60 group-hover:opacity-100 transition-opacity">
        FROM: {entry.sender.toUpperCase()}
      </div>

      {copied && (
        <div className="absolute inset-0 flex items-center justify-center bg-terminal-bg/80 backdrop-blur-[1px]">
          <span className="text-terminal-accent font-bold tracking-widest text-sm animate-pulse border border-terminal-accent px-2 py-1 bg-terminal-accent/10">
            COPIED
          </span>
        </div>
      )}
    </div>
  );
};
