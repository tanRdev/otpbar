const authView = document.getElementById('auth-view');
const codesView = document.getElementById('codes-view');
const codesList = document.getElementById('codes-list');
const authBtn = document.getElementById('auth-btn');
const authBtnText = document.getElementById('auth-btn-text');
const authError = document.getElementById('auth-error');
const logoutBtn = document.getElementById('logout-btn');
const quitBtn = document.getElementById('quit-btn');
const refreshBtn = document.getElementById('refresh-btn');
const statusEl = document.getElementById('status');
const versionEl = document.getElementById('version');

let codes = [];
let authInProgress = false;
let refreshInterval = null;

async function init() {
  stopPeriodicRefresh();
  versionEl.textContent = `v${typeof APP_VERSION !== 'undefined' ? APP_VERSION : '1.0.0'}`;
  const isAuth = await window.api.getAuthStatus();
  if (isAuth) {
    showCodesView();
  } else {
    showAuthView();
  }
  setupKeyboardHandlers();
}

function showAuthView() {
  authView.classList.remove('hidden');
  codesView.classList.add('hidden');
  hideError();
  stopPeriodicRefresh();
}

function showCodesView() {
  authView.classList.add('hidden');
  codesView.classList.remove('hidden');
  refreshCodes();
  startPeriodicRefresh();
}

function startPeriodicRefresh() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(() => {
    if (!authView.classList.contains('hidden')) return;
    refreshCodes();
  }, 3000);
}

function stopPeriodicRefresh() {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
  }
}

function showError(message) {
  authError.textContent = message;
  authError.classList.remove('hidden');
}

function hideError() {
  authError.classList.add('hidden');
  authError.textContent = '';
}

async function refreshCodes() {
  codes = await window.api.getCodes();
  renderCodes();
}

// Extract provider/brand from sender (delegated to TypeScript module)
function extractProvider(sender) {
  return window.api.extractProvider(sender);
}

function renderCodes() {
  if (codes.length === 0) {
    codesList.innerHTML = `
      <div class="empty">
        <svg class="empty-icon" viewBox="0 0 32 32" fill="none">
          <circle cx="14" cy="14" r="9" stroke="currentColor" stroke-width="2"/>
          <path d="M21 21L27 27" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
        <span>No recent codes</span>
      </div>
    `;
    return;
  }

  codesList.innerHTML = codes.map(c => {
    const provider = extractProvider(c.sender);
    return `
      <div class="otp-card" data-code="${c.code}">
        <div class="otp-card-header">
          <span class="otp-provider">${escapeHtml(provider)}</span>
          <span class="otp-time">${timeAgo(c.timestamp)}</span>
        </div>
        <div class="otp-code">${c.code}</div>
        <div class="otp-hint">Click to copy</div>
      </div>
    `;
  }).join('');

  codesList.querySelectorAll('.otp-card').forEach(el => {
    el.addEventListener('click', async () => {
      await window.api.copyCode(el.dataset.code);
      el.classList.add('copied');
      el.querySelector('.otp-hint').textContent = 'Copied!';
      setTimeout(() => {
        el.classList.remove('copied');
        el.querySelector('.otp-hint').textContent = 'Click to copy';
      }, 1500);
    });
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function timeAgo(ts) {
  const seconds = Math.floor((Date.now() - ts) / 1000);
  if (seconds < 60) return 'just now';
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  return `${hours}h ago`;
}

// Keyboard handlers for ESC key to close window
function setupKeyboardHandlers() {
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      window.api.hideWindow();
    }
  });
}

// Event listeners
authBtn.addEventListener('click', async () => {
  if (authInProgress) return;

  authInProgress = true;
  authBtn.disabled = true;
  authBtn.classList.add('loading');
  authBtnText.textContent = 'Opening browser...';
  hideError();

  const result = await window.api.startAuth();

  if (!result.success) {
    authInProgress = false;
    authBtn.disabled = false;
    authBtn.classList.remove('loading');
    authBtnText.textContent = 'Sign in with Google';
    showError(result.error || 'Failed to start authentication');
  }
});

// Refresh button handler
refreshBtn.addEventListener('click', async () => {
  refreshBtn.classList.add('refreshing');
  await refreshCodes();
  setTimeout(() => {
    refreshBtn.classList.remove('refreshing');
  }, 500);
});

logoutBtn.addEventListener('click', async () => {
  await window.api.logout();
  codes = [];
  showAuthView();
});

quitBtn.addEventListener('click', () => {
  window.api.quitApp();
});

// Listen for updates from main process
window.api.onCodesUpdate((newCodes) => {
  codes = newCodes;
  renderCodes();
});

window.api.onAuthComplete(() => {
  authInProgress = false;
  authBtn.disabled = false;
  authBtn.classList.remove('loading');
  authBtnText.textContent = 'Sign in with Google';
  showCodesView();
});

window.api.onAuthCancelled(() => {
  authInProgress = false;
  authBtn.disabled = false;
  authBtn.classList.remove('loading');
  authBtnText.textContent = 'Sign in with Google';
  showError('Authentication was cancelled. Please try again.');
});

window.api.onAuthError((error) => {
  authInProgress = false;
  authBtn.disabled = false;
  authBtn.classList.remove('loading');
  authBtnText.textContent = 'Sign in with Google';
  showError(error || 'Authentication failed. Please try again.');
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  init();
});
