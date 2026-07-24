(() => {
  const callbacks = new Map();
  let nextCallbackId = 1;

  const sampleCodes = [
    {
      code: '482913',
      sender: 'GitHub',
      provider: 'GitHub',
      timestamp: Date.now() - 90_000,
      message_id: 'mock-github',
    },
    {
      code: '731204',
      sender: 'Notion',
      provider: 'Notion',
      timestamp: Date.now() - 3_900_000,
      message_id: 'mock-notion',
    },
    {
      code: '006842',
      sender: 'Chase',
      provider: 'Chase',
      timestamp: Date.now() - 90_000_000,
      message_id: 'mock-chase',
    },
  ];

  const getScenario = () => {
    const requested = new URLSearchParams(window.location.search).get('scenario');
    return requested || localStorage.getItem('otpbar-audit-scenario') || 'signed-out';
  };
  const isAuthenticated = () => getScenario() !== 'signed-out';

  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
    unregisterListener() {},
  };

  window.__TAURI_INTERNALS__ = {
    transformCallback(callback, once = false) {
      const id = nextCallbackId++;
      callbacks.set(id, (...args) => {
        callback?.(...args);
        if (once) callbacks.delete(id);
      });
      return id;
    },
    unregisterCallback(id) {
      callbacks.delete(id);
    },
    convertFileSrc(path) {
      return path;
    },
    async invoke(command, args = {}) {
      const scenario = getScenario();

      if (command === 'plugin:event|listen') return 1;
      if (command === 'plugin:event|unlisten') return null;
      if (command === 'get_auth_status') return isAuthenticated();
      if (command === 'get_codes') {
        if (scenario === 'startup-error') throw new Error('Mock host unavailable');
        if (sessionStorage.getItem('otpbar-audit-cleared') === 'true') return [];
        return scenario === 'empty' || scenario === 'signed-out' ? [] : sampleCodes;
      }
      if (command === 'start_auth') {
        localStorage.setItem('otpbar-audit-scenario', 'empty');
        return { success: true, error: null };
      }
      if (command === 'logout') {
        localStorage.setItem('otpbar-audit-scenario', 'signed-out');
        return true;
      }
      if (command === 'get_clipboard_config') return { timeout_seconds: 30 };
      if (command === 'copy_code_with_expiry' || command === 'copy_code') return true;
      if (command === 'get_preferences') {
        return {
          auto_copy_enabled: true,
          provider_auto_copy: { default: true, GitHub: false },
        };
      }
      if (command === 'set_auto_copy_enabled' || command === 'set_provider_auto_copy') return null;
      if (command === 'get_privacy_data') {
        const cleared = sessionStorage.getItem('otpbar-audit-cleared') === 'true';
        return {
          dataLocations: {
            configPath: '/Users/example/Library/Application Support/otpbar',
            historyPath: '/Users/example/Library/Application Support/otpbar/code_history.json',
            keychainItems: [
              'gmail-access-token',
              'gmail-refresh-token',
              'gmail-token-expiry',
            ],
          },
          permissions: {
            scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
            hasAccessToken: true,
            hasRefreshToken: true,
          },
          activity: {
            totalCodes: cleared ? 0 : 3,
            lastActivity: cleared ? null : Date.now() - 90_000,
            historyRetention: 0,
          },
          retention: {
            maxHistorySize: 50,
            currentSize: cleared ? 0 : 3,
          },
        };
      }
      if (command === 'clear_history') {
        sessionStorage.setItem('otpbar-audit-cleared', 'true');
        return null;
      }
      if (command === 'quit_app' || command === 'hide_window') return null;

      throw new Error(`Unhandled mock Tauri command: ${command} ${JSON.stringify(args)}`);
    },
  };
})();
