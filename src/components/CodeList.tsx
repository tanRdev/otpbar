import React from 'react';
import { CodeEntry } from '../types/tauri';
import { CodeCard } from './CodeCard';
import { Loader2, Inbox } from 'lucide-react';

interface CodeListProps {
  codes: CodeEntry[];
  isLoading?: boolean;
}

export const CodeList: React.FC<CodeListProps> = ({ codes, isLoading }) => {
  if (codes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-center">
        {isLoading ? (
          <div className="flex flex-col items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-secondary/80 flex items-center justify-center border border-border/30">
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            </div>
            <span className="text-xs font-medium text-muted-foreground">Syncing...</span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3 max-w-[200px]">
            <div className="w-10 h-10 rounded-xl bg-secondary/80 flex items-center justify-center border border-border/30 shadow-inner-glow">
              <Inbox className="h-4 w-4 text-muted-foreground" strokeWidth={1.5} />
            </div>
            <div className="flex flex-col gap-1">
              <h3 className="text-sm font-medium text-foreground/80">No codes</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Waiting for OTP messages...
              </p>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full h-full overflow-y-auto">
      <div className="px-2 py-2 space-y-1.5">
        {codes.map((entry) => (
          <CodeCard key={`${entry.message_id}-${entry.code}`} entry={entry} />
        ))}
      </div>
    </div>
  );
};
