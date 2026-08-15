(function () {
  const LS_KEY = 'waa-theme';
  const DEFAULT = 'light';
  const THEMES = [
    { id: 'light',     name: 'Light',       emoji: '☀️', accent: '#0969da' },
    { id: 'dark',      name: 'Dark',        emoji: '🌙', accent: '#4493f8' },
    { id: 'sakura',    name: 'Sakura',      emoji: '🌸', accent: '#e255a1' },
    { id: 'dracula',   name: 'Dracula',     emoji: '🧛', accent: '#bd93f9' },
    { id: 'nord',      name: 'Nord',        emoji: '❄️', accent: '#88c0d0' },
    { id: 'solarized', name: 'Solarized',   emoji: '🌅', accent: '#268bd2' },
    { id: 'cyberpunk', name: 'Cyberpunk',   emoji: '⚡', accent: '#00fff9' },
    { id: 'forest',    name: 'Forest',      emoji: '🌲', accent: '#8fd694' },
    { id: 'midnight',  name: 'Midnight',    emoji: '🌌', accent: '#7aa2f7' },
    { id: 'tokyo',     name: 'Tokyo Night', emoji: '🌃', accent: '#7aa2f7' }
  ];

  function getTheme() {
    const s = localStorage.getItem(LS_KEY);
    return THEMES.some(t => t.id === s) ? s : DEFAULT;
  }

  function info(id) {
    return THEMES.find(t => t.id === id) || THEMES[0];
  }

  function renderButton(btn) {
    const t = info(getTheme());
    btn.innerHTML = t.emoji + ' ' + t.name;
  }

  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(LS_KEY, theme); } catch (e) { /* private mode */ }
    const btn = document.getElementById('theme-btn');
    if (btn) renderButton(btn);
    document.querySelectorAll('#theme-picker .theme-item').forEach(el => {
      el.classList.toggle('active', el.dataset.theme === theme);
    });
    document.dispatchEvent(new CustomEvent('themechange', { detail: { theme } }));
  }

  function build() {
    const host = document.getElementById('theme-picker');
    if (!host) return;
    const cur = getTheme();

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'theme-btn';
    btn.className = 'btn gray btn-sm theme-btn';
    btn.title = 'Change theme';
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-label', 'Change theme');

    const menu = document.createElement('div');
    menu.className = 'theme-menu';
    menu.setAttribute('role', 'menu');

    THEMES.forEach(t => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'theme-item';
      item.dataset.theme = t.id;
      item.setAttribute('role', 'menuitem');
      const sw = document.createElement('span');
      sw.className = 'swatch';
      sw.style.background = t.accent;
      const label = document.createTextNode(t.emoji + ' ' + t.name);
      item.appendChild(sw);
      item.appendChild(label);
      item.addEventListener('click', () => {
        apply(t.id);
        close();
      });
      menu.appendChild(item);
    });

    host.appendChild(btn);
    host.appendChild(menu);

    function close() {
      host.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
      document.removeEventListener('click', onDoc);
      document.removeEventListener('keydown', onKey);
    }
    function open() {
      renderButton(btn);
      document.querySelectorAll('#theme-picker .theme-item').forEach(el => {
        el.classList.toggle('active', el.dataset.theme === getTheme());
      });
      host.classList.add('open');
      btn.setAttribute('aria-expanded', 'true');
      setTimeout(() => document.addEventListener('click', onDoc), 0);
      document.addEventListener('keydown', onKey);
    }
    function onDoc(e) {
      if (!host.contains(e.target)) close();
    }
    function onKey(e) {
      if (e.key === 'Escape') close();
    }
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      host.classList.contains('open') ? close() : open();
    });

    renderButton(btn);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', build);
  } else {
    build();
  }

  // Apply early to avoid flash of the wrong theme (script runs before </body>).
  apply(getTheme());

  window.WATheme = { apply, getTheme, THEMES };
})();