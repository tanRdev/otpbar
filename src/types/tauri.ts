export interface CodeEntry {
  code: string;
  sender: string;
  provider: string;
  timestamp: number;
  message_id: string;
}

export type AuthorizationStatusValue =
  | "unknown_restoring"
  | "disconnected"
  | "starting"
  | "awaiting_browser"
  | "exchanging"
  | "connected"
  | "cancelled"
  | "denied"
  | "callback_invalid"
  | "configuration_missing"
  | "credential_store_unavailable"
  | "refresh_required"
  | "failed";

export interface AuthorizationStatus {
  status: AuthorizationStatusValue;
}

export interface ClipboardConfig {
  timeout_seconds: number;
}

export interface SafeCommandError {
  code:
    | "clipboard_permission_denied"
    | "clipboard_unavailable"
    | "clipboard_atomic_clear_unavailable";
  message: string;
  retryable: boolean;
}

export type CommandEnvelope<T> =
  { status: "success"; data: T } | { status: "error"; error: SafeCommandError };

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
