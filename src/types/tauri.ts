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

export interface ClipboardConfig {
  timeout_seconds: number;
}

export interface PrivacyPreferences {
  auto_copy_enabled: boolean;
  provider_auto_copy: Record<string, boolean>;
}

export type Codes = CodeEntry[];

export interface PrivacyData {
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
