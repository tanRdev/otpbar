import { contextBridge, ipcRenderer } from 'electron';

interface CodeEntry {
  code: string;
  sender: string;
  timestamp: number;
  messageId: string;
}

interface AuthResult {
  success: boolean;
  error?: string;
}

export interface API {
  getCodes: () => Promise<CodeEntry[]>;
  getAuthStatus: () => Promise<boolean>;
  startAuth: () => Promise<AuthResult>;
  copyCode: (code: string) => Promise<boolean>;
  logout: () => Promise<boolean>;
  quitApp: () => Promise<void>;
  hideWindow: () => Promise<void>;
  extractProvider: (sender: string) => string;
  onCodesUpdate: (callback: (codes: CodeEntry[]) => void) => void;
  onAuthComplete: (callback: () => void) => void;
  onAuthCancelled: (callback: () => void) => void;
  onAuthError: (callback: (error: string) => void) => void;
}

// Provider mappings and extraction logic
const PROVIDER_MAPPINGS: Record<string, string> = {
  google: 'Google',
  gmail: 'Google',
  apple: 'Apple',
  microsoft: 'Microsoft',
  outlook: 'Microsoft',
  amazon: 'Amazon',
  facebook: 'Facebook',
  meta: 'Meta',
  instagram: 'Instagram',
  twitter: 'Twitter',
  'x.com': 'X',
  github: 'GitHub',
  linkedin: 'LinkedIn',
  paypal: 'PayPal',
  stripe: 'Stripe',
  venmo: 'Venmo',
  cashapp: 'Cash App',
  square: 'Square',
  coinbase: 'Coinbase',
  binance: 'Binance',
  robinhood: 'Robinhood',
  chase: 'Chase',
  wellsfargo: 'Wells Fargo',
  bankofamerica: 'Bank of America',
  aws: 'AWS',
  heroku: 'Heroku',
  digitalocean: 'DigitalOcean',
  cloudflare: 'Cloudflare',
  shopify: 'Shopify',
  ebay: 'eBay',
  etsy: 'Etsy',
  doordash: 'DoorDash',
  grubhub: 'Grubhub',
  postmates: 'Postmates',
  uber: 'Uber',
  lyft: 'Lyft',
  spotify: 'Spotify',
  netflix: 'Netflix',
  notion: 'Notion',
  figma: 'Figma',
  canva: 'Canva',
  zoom: 'Zoom',
  webex: 'Webex',
  asana: 'Asana',
  trello: 'Trello',
  airbnb: 'Airbnb',
  twilio: 'Twilio',
  auth0: 'Auth0',
  okta: 'Okta',
  dropbox: 'Dropbox',
  slack: 'Slack',
  discord: 'Discord',
  salesforce: 'Salesforce',
  atlassian: 'Atlassian',
  jira: 'Jira',
  adobe: 'Adobe',
  oracle: 'Oracle',
  namecheap: 'Namecheap',
  godaddy: 'GoDaddy',
};

function extractProvider(sender: string): string {
  if (!sender) return 'Unknown';

  const senderLower = sender.toLowerCase();

  // Check against known provider mappings
  for (const [key, value] of Object.entries(PROVIDER_MAPPINGS)) {
    if (senderLower.includes(key)) {
      return value;
    }
  }

  // Try to extract name before email
  const nameMatch = sender.match(/^([^<@]+)/);
  if (nameMatch) {
    const name = nameMatch[1].trim();
    // Clean up common suffixes
    const cleanName = name.replace(
      /\s*(no-?reply|noreply|support|security|verify|verification|accounts?|team|notifications?)\s*/gi,
      ''
    ).trim();

    if (cleanName && cleanName.length > 1 && cleanName.length < 30) {
      return cleanName;
    }
    if (name && name.length > 1 && name.length < 30) {
      return name;
    }
  }

  // Try to extract domain
  const domainMatch = sender.match(/@([^.>]+)/);
  if (domainMatch) {
    const domain = domainMatch[1];
    return domain.charAt(0).toUpperCase() + domain.slice(1);
  }

  return 'Unknown';
}

contextBridge.exposeInMainWorld('api', {
  getCodes: () => ipcRenderer.invoke('get-codes'),
  getAuthStatus: () => ipcRenderer.invoke('get-auth-status'),
  startAuth: () => ipcRenderer.invoke('start-auth'),
  copyCode: (code: string) => ipcRenderer.invoke('copy-code', code),
  logout: () => ipcRenderer.invoke('logout'),
  quitApp: () => ipcRenderer.invoke('quit-app'),
  hideWindow: () => ipcRenderer.invoke('hide-window'),
  extractProvider: (sender: string) => extractProvider(sender),
  onCodesUpdate: (callback: (codes: CodeEntry[]) => void) => {
    ipcRenderer.on('codes-updated', (_, codes) => callback(codes));
  },
  onAuthComplete: (callback: () => void) => {
    ipcRenderer.on('auth-complete', () => callback());
  },
  onAuthCancelled: (callback: () => void) => {
    ipcRenderer.on('auth-cancelled', () => callback());
  },
  onAuthError: (callback: (error: string) => void) => {
    ipcRenderer.on('auth-error', (_, error) => callback(error));
  }
} satisfies API);
