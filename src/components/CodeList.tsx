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
      <div className="flex flex-col items-center justify-center h-full gap-2 text-muted-foreground">
        {isLoading ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-[11px]">Syncing...</span>
          </>
        ) : (
          <>
            <Inbox className="h-5 w-5 opacity-25" />
            <span className="text-[11px] opacity-50">Waiting for OTP messages...</span>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full h-full overflow-y-auto gap-0.5 px-1">
      {codes.map((entry) => (
        <CodeCard key={`${entry.message_id}-${entry.code}`} entry={entry} />
      ))}
    </div>
  );
};
