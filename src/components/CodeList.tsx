import React from 'react';
import { CodeEntry } from '../types/tauri';
import { CodeCard } from './CodeCard';
import { RefreshCw } from 'lucide-react';

interface CodeListProps {
  codes: CodeEntry[];
  isLoading?: boolean;
}

export const CodeList: React.FC<CodeListProps> = ({ codes, isLoading }) => {
  if (codes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-terminal-dim p-8 text-center border-t border-terminal-border">
        {isLoading ? (
          <RefreshCw className="animate-spin mb-2 text-terminal-accent" />
        ) : (
          <div className="flex flex-col gap-2">
            <span className="text-xl font-bold opacity-30">NO DATA</span>
            <span className="text-xs uppercase tracking-widest opacity-50">Waiting for incoming OTPs...</span>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full overflow-y-auto max-h-[400px] border-t border-terminal-border scrollbar-thin scrollbar-thumb-terminal-border scrollbar-track-terminal-bg">
      {codes.map((entry) => (
        <CodeCard key={`${entry.message_id}-${entry.code}`} entry={entry} />
      ))}
    </div>
  );
};
