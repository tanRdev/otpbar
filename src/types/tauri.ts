export interface CodeEntry {
  code: string;
  sender: string;
  provider: string;
  timestamp: number;
  message_id: string;
}

export interface AuthResult {
  success: boolean;
  error?: string;
}

export type Codes = CodeEntry[];
