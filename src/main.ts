import 'dotenv/config';
import {
  app,
  clipboard,
  Notification,
  ipcMain,
  shell,
  nativeImage,
  Menu,
  IpcMainInvokeEvent
} from 'electron';
import { menubar, Menubar } from 'menubar';
import * as http from 'http';
import * as path from 'path';
import * as url from 'url';
import * as fs from 'fs';
import { GmailClient, EmailMessage } from './gmail';
import { extractOTP } from './parser';
import { APP_CONFIG } from './constants';

// Hide dock icon on macOS
if (process.platform === 'darwin') {
  app.dock?.hide();
}

interface CodeEntry {
  code: string;
  sender: string;
  timestamp: number;
  messageId: string;
}

let mb: Menubar | null = null;
let gmail: GmailClient | null = null;
let recentCodes: CodeEntry[] = [];
let pollInterval: NodeJS.Timeout | null = null;
let authServer: http.Server | null = null;
let authTimeout: NodeJS.Timeout | null = null;
let isAuthInProgress = false;
let lastNotificationTime = 0;
let trayIcon: Electron.NativeImage | null = null;

function createTrayIcon() {
  const size = APP_CONFIG.TRAY_ICON_SIZE;

  const iconPath = path.join(__dirname, '..', 'tray-icon.png');
  if (fs.existsSync(iconPath)) {
    const img = nativeImage.createFromPath(iconPath);
    img.setTemplateImage(true);
    return img;
  }

  const canvas = Buffer.alloc(size * size * 4);

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;

      const padding = APP_CONFIG.TRAY_ICON_PADDING;
      const innerX = x - padding;
      const innerY = y - padding;
      const innerSize = size - (padding * 2);
      const boxHeight = APP_CONFIG.TRAY_ICON_BOX_HEIGHT;
      const boxWidth = APP_CONFIG.TRAY_ICON_BOX_WIDTH;
      const boxY = Math.floor((innerSize - boxHeight) / 2);
      const boxX = Math.floor((innerSize - boxWidth) / 2);

      const inBox = innerX >= boxX && innerX < boxX + boxWidth && innerY >= boxY && innerY < boxY + boxHeight;

      const dots = [
        [boxX + 2, boxY + 2],
        [boxX + 5, boxY + 2],
        [boxX + 8, boxY + 2],
        [boxX + 2, boxY + 4],
        [boxX + 5, boxY + 4],
        [boxX + 8, boxY + 4]
      ];

      const isDot = dots.some(([dx, dy]) => {
        const dist = Math.sqrt(Math.pow(x - (dx + padding), 2) + Math.pow(y - (dy + padding), 2));
        return dist <= APP_CONFIG.TRAY_ICON_DOT_RADIUS;
      });

      const inStroke = inBox && !isDot;

      if (inStroke) {
        canvas[idx] = 0;
        canvas[idx + 1] = 0;
        canvas[idx + 2] = 0;
        canvas[idx + 3] = 255;
      } else if (isDot) {
        canvas[idx] = 0;
        canvas[idx + 1] = 0;
        canvas[idx + 2] = 0;
        canvas[idx + 3] = 255;
      } else {
        canvas[idx + 3] = 0;
      }
    }
  }

  const img = nativeImage.createFromBuffer(canvas, { width: size, height: size });
  img.setTemplateImage(true);
  return img;
}

function createMenubar(): void {
  if (!trayIcon) {
    trayIcon = createTrayIcon();
  }

  mb = menubar({
    index: `file://${path.join(__dirname, '..', 'index.html')}`,
    icon: trayIcon,
    preloadWindow: true,
    showDockIcon: false,
    browserWindow: {
      width: APP_CONFIG.WINDOW_WIDTH,
      height: APP_CONFIG.WINDOW_HEIGHT,
      resizable: false,
      transparent: true,
      backgroundColor: '#00000000',
      vibrancy: 'menu',
      visualEffectState: 'active',
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false
      }
    }
  });

  mb.on('ready', async () => {
    // Add right-click context menu
    const contextMenu = Menu.buildFromTemplate([
      { label: 'otpbar', enabled: false },
      { type: 'separator' },
      { label: 'Quit', click: () => app.quit() }
    ]);
    mb!.tray?.on('right-click', () => {
      mb!.tray?.popUpContextMenu(contextMenu);
    });

    gmail = new GmailClient();
    try {
      await gmail.init();
      const hasAuth = await gmail.tryRestoreAuth();
      if (hasAuth) {
        startPolling();
      }
    } catch (err) {
      new Notification({
        title: 'Initialization Error',
        body: 'Could not initialize Gmail client. Please check your credentials.',
        silent: false
      }).show();
    }
  });

  mb.on('show', () => {
    mb?.window?.webContents.send('codes-updated', recentCodes);
  });

  // Hide window when clicking outside (blur event)
  mb.on('after-show', () => {
    if (mb?.window) {
      mb.window.once('blur', () => {
        mb?.hideWindow();
      });
    }
  });
}

function startPolling(): void {
  if (pollInterval) clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    try {
      const messages = await gmail!.getRecentUnread();
      for (const msg of messages) {
        const searchText = `${msg.subject} ${msg.snippet} ${msg.body}`;
        const otp = extractOTP(searchText);

        if (otp && !recentCodes.find(c => c.code === otp && c.messageId === msg.id)) {
          const entry: CodeEntry = {
            code: otp,
            sender: extractSenderName(msg.from),
            timestamp: Date.now(),
            messageId: msg.id
          };
          recentCodes.unshift(entry);
          recentCodes = recentCodes.slice(0, APP_CONFIG.MAX_RECENT_CODES);

          clipboard.writeText(otp);

          const now = Date.now();
          if (now - lastNotificationTime >= APP_CONFIG.NOTIFICATION_COOLDOWN_MS) {
            new Notification({
              title: 'OTP Copied',
              body: `${otp} from ${entry.sender}`,
              silent: false
            }).show();
            lastNotificationTime = now;
          }

          mb?.window?.webContents.send('codes-updated', recentCodes);
        }
      }
    } catch (err) {
      new Notification({
        title: 'Gmail Connection Error',
        body: 'Could not fetch emails. Please check your internet connection.',
        silent: false
      }).show();
    }
  }, APP_CONFIG.POLL_INTERVAL_MS);
}

function extractSenderName(from: string): string {
  const match = from.match(/^([^<]+)/);
  return match ? match[1].trim() : from;
}

function cleanupAuth(): void {
  if (authTimeout) {
    clearTimeout(authTimeout);
    authTimeout = null;
  }
  if (authServer) {
    authServer.close();
    authServer = null;
  }
  isAuthInProgress = false;
}

function startAuthServer(): Promise<void> {
  return new Promise((resolve, reject) => {
    // Clean up any existing auth state
    cleanupAuth();

    const handleCallback = async (req: any, res: any) => {
      const parsed = url.parse(req.url || '', true);
      if (parsed.pathname === '/callback' && parsed.query.code) {
        try {
          await gmail!.exchangeCode(parsed.query.code as string);
          startPolling();
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Success</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;
      background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      text-align: center;
      padding: 40px;
    }
    .checkmark {
      width: 64px;
      height: 64px;
      margin: 0 auto 24px;
      background: #34C759;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      animation: scale 0.3s ease;
    }
    @keyframes scale {
      0% { transform: scale(0); }
      50% { transform: scale(1.1); }
      100% { transform: scale(1); }
    }
    .checkmark svg { width: 32px; height: 32px; }
    h1 {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 8px;
      letter-spacing: -0.5px;
    }
    p {
      color: rgba(255,255,255,0.6);
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="checkmark">
      <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
    </div>
    <h1>You're all set</h1>
    <p>You can close this tab</p>
  </div>
  <script>
    try { window.close(); } catch(e) {}
  </script>
</body>
</html>`);
          mb?.window?.webContents.send('auth-complete');
          cleanupAuth();
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body style="font-family: -apple-system, BlinkMacSystemFont, system-ui; padding: 40px; text-align: center; background: #1a1a1a; color: #fff;">
                <h1 style="color: #ff453a;">✗ Authentication Failed</h1>
                <p style="color: #888;">${(err as Error).message}</p>
              </body>
            </html>
          `);
          mb?.window?.webContents.send('auth-error', (err as Error).message);
          cleanupAuth();
        }
      }
    };

    authServer = http.createServer(handleCallback);

    authServer.on('error', (err) => {
      cleanupAuth();
      reject(err);
    });

    const port = gmail ? (gmail as any).authPort : 8234;
    authServer.listen(port, () => {
      isAuthInProgress = true;

      // Set timeout for auth completion
      authTimeout = setTimeout(() => {
        if (isAuthInProgress) {
          cleanupAuth();
          mb?.window?.webContents.send('auth-cancelled');
        }
      }, APP_CONFIG.AUTH_TIMEOUT_MS);

      resolve();
    });
  });
}

// IPC Handlers
ipcMain.handle('get-codes', (): CodeEntry[] => recentCodes);

ipcMain.handle('get-auth-status', (): boolean => gmail?.isAuthenticated() ?? false);

ipcMain.handle('start-auth', async (): Promise<{ success: boolean; error?: string }> => {
  try {
    if (isAuthInProgress) {
      return { success: false, error: 'Authentication already in progress' };
    }

    await startAuthServer();
    const authUrl = gmail!.getAuthUrl();
    await shell.openExternal(authUrl);
    return { success: true };
  } catch (err) {
    cleanupAuth();
    return { success: false, error: (err as Error).message };
  }
});

ipcMain.handle('copy-code', (_: IpcMainInvokeEvent, code: string): boolean => {
  clipboard.writeText(code);
  return true;
});

ipcMain.handle('logout', async (): Promise<boolean> => {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  cleanupAuth();
  await gmail?.clearAuth();
  recentCodes = [];
  return true;
});

ipcMain.handle('quit-app', (): void => {
  app.quit();
});

ipcMain.handle('hide-window', (): void => {
  mb?.hideWindow();
});

// App lifecycle
app.on('ready', createMenubar);

app.on('window-all-closed', (e: Event) => {
  e.preventDefault();
});

app.on('before-quit', () => {
  if (pollInterval) clearInterval(pollInterval);
  cleanupAuth();
});
