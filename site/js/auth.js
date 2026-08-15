// Shared account widget — user chip + sign in / create account modal.
// Used by both index.html (dashboard) and lab.html. Exposes window.Auth.
(function () {
  'use strict';
  const API = (window.CONFIG && window.CONFIG.API_BASE) || '';
  let user = null;
  let solved = [];
  const listeners = [];

  function api(url, opts) {
    return fetch(API + url, Object.assign({ credentials: 'include' }, opts || {}))
      .then(r => r.json()).catch(() => ({ user: null, ok: false }));
  }

  function notify() { listeners.forEach(fn => { try { fn({ user, solved }); } catch (e) {} }); }

  // ---------- chip ----------
  function chip() {
    return `<button class="btn gray btn-sm auth-chip" data-a="${user ? 'open' : 'login'}">${user ? '👤 ' + esc(user) : 'Sign in'}</button>` +
      (user ? `<button class="btn gray btn-sm" data-a="logout" title="Sign out">Sign out</button>` : '');
  }
  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function renderChip() {
    const host = document.getElementById('auth-area');
    if (!host) return;
    host.innerHTML = chip();
  }
  function bindChip() {
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-a]');
      if (!btn) return;
      const act = btn.getAttribute('data-a');
      if (act === 'login') openModal();
      else if (act === 'open') openModal();
      else if (act === 'logout') signOut();
    });
  }

  // ---------- modal ----------
  function openModal() {
    if (document.getElementById('auth-modal')) return;
    const modal = document.createElement('div');
    modal.className = 'auth-overlay';
    modal.id = 'auth-modal';
    modal.innerHTML = `
      <div class="auth-card">
        <button class="auth-x" title="Close" aria-label="Close">&times;</button>
        <h3 id="auth-title">Sign in</h3>
        <p class="auth-sub" id="auth-sub">Your progress is saved to your account and follows you across devices.</p>
        <form id="auth-form" autocomplete="off">
          <label class="auth-label" for="auth-username">Username</label>
          <input id="auth-username" class="auth-input" autocomplete="username" spellcheck="false" required>
          <label class="auth-label" for="auth-password">Password</label>
          <input id="auth-password" class="auth-input" type="password" autocomplete="current-password" required>
          <div class="auth-err" id="auth-err"></div>
          <button class="btn primary auth-submit" type="submit" id="auth-submit">Sign in</button>
        </form>
        <button class="auth-link" id="auth-toggle"></button>
      </div>`;
    document.body.appendChild(modal);
    let mode = 'login';
    const title = document.getElementById('auth-title');
    const sub = document.getElementById('auth-sub');
    const submit = document.getElementById('auth-submit');
    const toggle = document.getElementById('auth-toggle');
    const errEl = document.getElementById('auth-err');

    function setMode(m) {
      mode = m;
      const isLogin = m === 'login';
      title.textContent = isLogin ? 'Sign in' : 'Create account';
      sub.textContent = isLogin
        ? 'Your progress is saved to your account and follows you across devices.'
        : 'Pick a username (3-20 chars) and a password (6+ chars).';
      submit.textContent = isLogin ? 'Sign in' : 'Create account';
      toggle.textContent = isLogin ? 'New here? Create an account' : 'Already have an account? Sign in';
      document.getElementById('auth-password').setAttribute('autocomplete', isLogin ? 'current-password' : 'new-password');
    }
    setMode('login');

    toggle.addEventListener('click', () => setMode(mode === 'login' ? 'register' : 'login'));
    modal.querySelector('.auth-x').addEventListener('click', close);
    modal.addEventListener('mousedown', (e) => { if (e.target === modal) close(); });

    function close() { modal.remove(); }

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('auth-username').value.trim();
      const password = document.getElementById('auth-password').value;
      errEl.textContent = '';
      submit.disabled = true;
      submit.textContent = '…';
      try {
        const d = await api('/api/' + (mode === 'login' ? 'login' : 'register'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        if (d.ok && d.user) {
          user = d.user;
          solved = Array.isArray(d.solved) ? d.solved : [];
          close();
          notify();
          renderChip();
        } else {
          errEl.textContent = d.error || 'Something went wrong.';
        }
      } catch (err) {
        errEl.textContent = 'Network error — is the worker running?';
      }
      submit.disabled = false;
      submit.textContent = mode === 'login' ? 'Sign in' : 'Create account';
    });
    setTimeout(() => document.getElementById('auth-username').focus(), 0);
  }

  async function signOut() {
    await api('/api/logout', { method: 'POST' });
    user = null;
    solved = [];
    notify();
    renderChip();
  }

  // ---------- reset ----------
  async function resetProgress() {
    const d = await api('/api/reset', { method: 'POST' });
    return d.ok === true;
  }

  // ---------- init ----------
  async function init() {
    bindChip();
    renderChip();
    const d = await api('/api/me');
    user = d.user || null;
    solved = Array.isArray(d.solved) ? d.solved : [];
    renderChip();
    notify();
  }

  window.Auth = {
    get user() { return user; },
    get solved() { return solved.slice(); },
    refresh: init,
    openModal,
    signOut,
    resetProgress,
    onChange(fn) { listeners.push(fn); }
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();