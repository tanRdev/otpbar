// Application constants
export const APP_CONFIG = {
  // Tray icon configuration
  TRAY_ICON_SIZE: 44,
  TRAY_ICON_PADDING: 3,
  TRAY_ICON_BOX_HEIGHT: 8,
  TRAY_ICON_BOX_WIDTH: 12,
  TRAY_ICON_DOT_RADIUS: 1.5,

  // Polling and timing
  POLL_INTERVAL_MS: 8000,
  AUTH_TIMEOUT_MS: 300000, // 5 minutes
  NOTIFICATION_COOLDOWN_MS: 3000,

  // Gmail configuration
  EMAIL_LOOKBACK_MS: 300000, // 5 minutes
  MAX_MESSAGES_PER_POLL: 10,
  SEEN_MESSAGE_CACHE_SIZE: 50,
  SEEN_MESSAGE_KEEP_SIZE: 30,

  // Auth server
  DEFAULT_AUTH_PORT: 8234,

  // UI configuration
  WINDOW_WIDTH: 320,
  WINDOW_HEIGHT: 420,

  // Code history
  MAX_RECENT_CODES: 10,
} as const;

// Keytar service configuration
export const KEYTAR_CONFIG = {
  SERVICE_NAME: 'otpbar',
  ACCOUNT_NAME: 'gmail-refresh-token',
} as const;

// Gmail OAuth scopes
export const GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
] as const;
