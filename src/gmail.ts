import { google, gmail_v1 } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import * as keytar from 'keytar';
import { APP_CONFIG, KEYTAR_CONFIG, GMAIL_SCOPES } from './constants';

let REDIRECT_URI = `http://localhost:${APP_CONFIG.DEFAULT_AUTH_PORT}/callback`;

export interface EmailMessage {
  id: string;
  from: string;
  subject: string;
  snippet: string;
  body: string;
}

export class GmailClient {
  private oauth2Client: OAuth2Client | null = null;
  private gmail: gmail_v1.Gmail | null = null;
  private authenticated = false;
  private seenMessageIds = new Set<string>();
  private authPort: number = APP_CONFIG.DEFAULT_AUTH_PORT;

  async findAvailablePort(): Promise<number> {
    const net = require('net');
    return new Promise((resolve) => {
      const server = net.createServer();
      server.listen(0, () => {
        const port = server.address() ? (server.address() as any).port : 8234;
        server.close(() => resolve(port));
      });
      server.on('error', () => resolve(APP_CONFIG.DEFAULT_AUTH_PORT));
    });
  }

  async init(): Promise<void> {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      throw new Error('Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in .env');
    }

    this.authPort = await this.findAvailablePort();
    REDIRECT_URI = `http://localhost:${this.authPort}/callback`;

    this.oauth2Client = new google.auth.OAuth2(
      clientId,
      clientSecret,
      REDIRECT_URI
    );
  }

  isAuthenticated(): boolean {
    return this.authenticated;
  }

  async tryRestoreAuth(): Promise<boolean> {
    if (!this.oauth2Client) await this.init();

    const refreshToken = await keytar.getPassword(
      KEYTAR_CONFIG.SERVICE_NAME,
      KEYTAR_CONFIG.ACCOUNT_NAME
    );
    if (refreshToken) {
      this.oauth2Client!.setCredentials({ refresh_token: refreshToken });
      this.gmail = google.gmail({ version: 'v1', auth: this.oauth2Client! });
      this.authenticated = true;
      return true;
    }
    return false;
  }

  getAuthUrl(): string {
    if (!this.oauth2Client) {
      throw new Error('GmailClient not initialized');
    }
    return this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: [...GMAIL_SCOPES],
      prompt: 'consent'
    });
  }

  async exchangeCode(code: string): Promise<void> {
    if (!this.oauth2Client) {
      throw new Error('GmailClient not initialized');
    }

    const { tokens } = await this.oauth2Client.getToken(code);
    this.oauth2Client.setCredentials(tokens);

    if (tokens.refresh_token) {
      await keytar.setPassword(
        KEYTAR_CONFIG.SERVICE_NAME,
        KEYTAR_CONFIG.ACCOUNT_NAME,
        tokens.refresh_token
      );
    }

    this.gmail = google.gmail({ version: 'v1', auth: this.oauth2Client });
    this.authenticated = true;
  }

  async getRecentUnread(): Promise<EmailMessage[]> {
    if (!this.gmail) return [];

    try {
      const afterTimestamp = Math.floor((Date.now() - APP_CONFIG.EMAIL_LOOKBACK_MS) / 1000);
      const query = `is:unread after:${afterTimestamp}`;

      const res = await this.gmail.users.messages.list({
        userId: 'me',
        q: query,
        maxResults: APP_CONFIG.MAX_MESSAGES_PER_POLL
      });

      if (!res.data.messages) return [];

      const messages: EmailMessage[] = [];
      for (const m of res.data.messages) {
        if (!m.id || this.seenMessageIds.has(m.id)) continue;
        this.seenMessageIds.add(m.id);

        const full = await this.gmail.users.messages.get({
          userId: 'me',
          id: m.id,
          format: 'full'
        });

        const headers = full.data.payload?.headers || [];
        const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
        const subject = headers.find(h => h.name === 'Subject')?.value || '';

        let body = '';
        if (full.data.payload?.body?.data) {
          body = Buffer.from(full.data.payload.body.data, 'base64').toString();
        } else if (full.data.payload?.parts) {
          const textPart = full.data.payload.parts.find(
            p => p.mimeType === 'text/plain'
          );
          if (textPart?.body?.data) {
            body = Buffer.from(textPart.body.data, 'base64').toString();
          }
        }

        messages.push({
          id: m.id,
          from,
          subject,
          snippet: full.data.snippet || '',
          body
        });
      }

      // Cleanup old seen IDs
      if (this.seenMessageIds.size > APP_CONFIG.SEEN_MESSAGE_CACHE_SIZE) {
        const arr = Array.from(this.seenMessageIds);
        this.seenMessageIds = new Set(arr.slice(-APP_CONFIG.SEEN_MESSAGE_KEEP_SIZE));
      }

      return messages;
    } catch (err) {
      return [];
    }
  }

  async markAsRead(messageId: string): Promise<void> {
    // No-op: keeping emails unread (gmail.modify scope removed)
  }

  async clearAuth(): Promise<void> {
    await keytar.deletePassword(
      KEYTAR_CONFIG.SERVICE_NAME,
      KEYTAR_CONFIG.ACCOUNT_NAME
    );
    this.authenticated = false;
    this.gmail = null;
    this.seenMessageIds.clear();
  }
}
