// Dashboard logic — loads labs.json, renders topic cards, tracks solved labs.
(function () {
  const state = { solved: new Set(), data: null, filters: { q: '', diff: '', status: '' } };
  const LS_KEY = 'waa-solved';

  function api(url) {
    return fetch(url, { credentials: 'include' }).then(r => r.json()).catch(() => ({ solved: false }));
  }

  function loadLocalSolved() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return new Set();
      const arr = JSON.parse(raw);
      return new Set(Array.isArray(arr) ? arr.filter(x => typeof x === 'string') : []);
    } catch (e) { return new Set(); }
  }
  function saveLocalSolved() {
    try { localStorage.setItem(LS_KEY, JSON.stringify([...state.solved])); } catch (e) {}
  }

  async function loadSolved() {
    if (!state.data) return;
    const ids = Object.keys(state.data.labs);
    // status endpoint returns solved state per lab via the session cookie
    const results = await Promise.all(ids.map(id => api(CONFIG.API_BASE + '/api/status/' + id)));
    const local = loadLocalSolved();
    state.solved.clear();
    ids.forEach((id, i) => { if ((results[i] && results[i].solved) || local.has(id)) state.solved.add(id); });
    saveLocalSolved();
    render();
    updateProgress();
    renderMastery();
  }

  // Push any locally-solved labs (from a previous anonymous session on this device)
  // to the account so nothing is lost after signing in.
  async function syncLocalToServer() {
    if (!state.data || !window.Auth || !Auth.user) return;
    const local = loadLocalSolved();
    const missing = [...local].filter(id => !Auth.solved.includes(id));
    if (!missing.length) return;
    try {
      await fetch(CONFIG.API_BASE + '/api/mark-many', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: missing })
      });
    } catch (e) { /* worker down; local cache still updated */ }
  }

  function setupAuth() {
    const btn = document.getElementById('btn-reset-progress');
    const gate = document.getElementById('gate');
    const appContent = document.getElementById('app-content');
    const gateBtn = document.getElementById('gate-signin');
    if (gateBtn) gateBtn.addEventListener('click', () => { if (window.Auth) Auth.openModal(); });

    const applyGate = (user) => {
      const showLabs = !!user;
      if (gate) gate.style.display = showLabs ? 'none' : '';
      if (appContent) appContent.style.display = showLabs ? '' : 'none';
      if (btn) btn.style.display = showLabs ? '' : 'none';
    };

    const update = ({ user }) => {
      applyGate(user);
      if (btn) btn.style.display = user ? '' : 'none';
    };
    if (window.Auth) {
      Auth.onChange(update);
      update({ user: Auth.user });
      Auth.onChange(async (auth) => {
        if (auth.user) {
          await syncLocalToServer();
          await loadSolved();
        }
      });
    } else {
      applyGate(false);
    }
    if (btn) btn.addEventListener('click', async () => {
      if (!window.Auth || !Auth.user) return;
      if (!confirm('Reset your saved progress? This removes all solved labs from your account. This cannot be undone.')) return;
      const ok = await Auth.resetProgress();
      if (ok) {
        try { localStorage.removeItem(LS_KEY); } catch (e) {}
        await loadSolved();
      } else {
        alert('Could not reset progress — is the worker running?');
      }
    });
  }

  function exportProgress() {
    const blob = new Blob([JSON.stringify({
      app: 'web-attack-academy',
      version: 1,
      exportedAt: new Date().toISOString(),
      solved: [...state.solved].sort()
    }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'waa-progress.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function importProgress(file) {
    const reader = new FileReader();
    reader.onload = async () => {
      let data;
      try { data = JSON.parse(reader.result); } catch (e) { alert('Invalid progress file.'); return; }
      const ids = (data && Array.isArray(data.solved)) ? data.solved.filter(x => typeof x === 'string') : [];
      ids.forEach(id => state.solved.add(id));
      saveLocalSolved();
      try {
        await fetch(CONFIG.API_BASE + '/api/mark-many', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids })
        });
      } catch (e) { /* worker down; local cache still updated */ }
      render();
      updateProgress();
      renderMastery();
    };
    reader.readAsText(file);
  }

  function updateProgress() {
    const total = Object.keys(state.data.labs).length;
    const done = state.solved.size;
    const el = document.getElementById('global-progress');
    if (el) el.innerHTML = `<strong>${done}</strong> / ${total} solved`;
  }

  function renderMastery() {
    const host = document.getElementById('mastery');
    if (!host) return;
    const labs = state.data.labs;
    const topics = state.data.topics;
    const total = Object.keys(labs).length;
    const done = state.solved.size;
    const pct = total ? Math.round(done / total * 100) : 0;

    // difficulty breakdown: solved per difficulty level
    const diff = [0, 0, 0, 0, 0, 0];       // total per level (idx 1..5)
    const diffSolved = [0, 0, 0, 0, 0, 0];
    for (const id of Object.keys(labs)) {
      const lv = Math.max(1, Math.min(5, labs[id].difficulty || 1));
      diff[lv]++; if (state.solved.has(id)) diffSolved[lv]++;
    }
    const maxLevel = diffSolved.slice(1).reduce((acc, n, i) => n > 0 ? i + 1 : acc, 0);

    // topics
    const topicRows = topics.map(t => {
      const d = t.labs.filter(id => state.solved.has(id)).length;
      const tPct = t.labs.length ? Math.round(d / t.labs.length * 100) : 0;
      return `<div class="m-row">
        <span class="m-topic" style="color:${t.color}"><span class="m-dot" style="background:${t.color}"></span>${t.name}</span>
        <div class="m-bar"><div class="m-fill" style="width:${tPct}%;background:${t.color}"></div></div>
        <span class="m-num">${d}/${t.labs.length}</span>
      </div>`;
    }).join('');

    host.style.display = 'block';
    host.innerHTML = `
      <div class="m-overall">
        <div class="m-score">
          <div class="m-big">${pct}%</div>
          <div class="m-label">Mastery</div>
        </div>
        <div class="m-detail">
          <div class="m-statline">
            <span><strong>${done}</strong>/<strong>${total}</strong> labs solved</span>
            <span>Highest difficulty solved: <strong>${maxLevel || '—'}</strong></span>
          </div>
          <div class="m-bar big"><div class="m-fill" style="width:${pct}%;background:var(--accent)"></div></div>
        </div>
      </div>
      <div class="m-cols">
        <div class="m-col">
          <h4>By topic</h4>
          ${topicRows || '<div class="muted">No topics.</div>'}
        </div>
        <div class="m-col">
          <h4>By difficulty</h4>
          ${[1, 2, 3, 4, 5].map(lv => diff[lv] ? `
            <div class="m-row">
              <span class="m-topic">${'●'.repeat(lv)}${'○'.repeat(5 - lv)}</span>
              <div class="m-bar"><div class="m-fill" style="width:${Math.round(diffSolved[lv] / diff[lv] * 100)}%;background:var(--accent)"></div></div>
              <span class="m-num">${diffSolved[lv]}/${diff[lv]}</span>
            </div>` : '').join('')}
        </div>
      </div>`;
  }

  function render() {
    const container = document.getElementById('grid');
    container.innerHTML = '';
    const q = state.filters.q.toLowerCase();
    let visible = 0;
    for (const topic of state.data.topics) {
      const labs = topic.labs.filter(id => {
        const lab = state.data.labs[id];
        const solved = state.solved.has(id);
        if (state.filters.diff && String(lab.difficulty) !== state.filters.diff) return false;
        if (state.filters.status === 'solved' && !solved) return false;
        if (state.filters.status === 'unsolved' && solved) return false;
        if (q) {
          const hay = (topic.name + ' ' + lab.title + ' ' + (lab.objective || '') + ' ' + id).toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });
      if (!labs.length) continue;
      visible += labs.length;
      const card = document.createElement('div');
      card.className = 'topic-card';
      const doneInTopic = labs.filter(id => state.solved.has(id)).length;
      card.innerHTML = `
        <div class="topic-head" style="background:${topic.color}">
          <h2>${topic.name}</h2>
          <span class="count">${doneInTopic}/${labs.length}</span>
        </div>
        <div class="topic-progress"><div class="topic-progress-fill" style="width:${labs.length ? Math.round(doneInTopic / labs.length * 100) : 0}%;background:${topic.color}"></div></div>
        <div class="lab-list">${labs.map(id => {
          const lab = state.data.labs[id];
          const solved = state.solved.has(id);
          return `<a class="lab-item ${solved ? 'solved-title' : ''}" href="lab.html?id=${id}">
            <span class="dot ${solved ? 'solved' : 'unsolved'}"></span>
            <span class="title">${lab.title}</span>
            <span class="diff">${'●'.repeat(lab.difficulty)}${'○'.repeat(5 - lab.difficulty)}</span>
          </a>`;
        }).join('')}</div>`;
      container.appendChild(card);
    }
    if (!visible) {
      container.innerHTML = '<p class="muted">No labs match the current filters.</p>';
    }
  }

  function setupToolbar() {
    const bind = (sel, key) => {
      const el = document.getElementById(sel);
      el.addEventListener('input', () => {
        state.filters[key] = sel === 'search' ? el.value.trim() : el.value;
        render();
      });
    };
    bind('search', 'q');
    bind('f-diff', 'diff');
    bind('f-status', 'status');
    document.getElementById('btn-reset').addEventListener('click', () => {
      state.filters = { q: '', diff: '', status: '' };
      document.getElementById('search').value = '';
      document.getElementById('f-diff').value = '';
      document.getElementById('f-status').value = '';
      render();
    });
    document.getElementById('btn-export').addEventListener('click', exportProgress);
    document.getElementById('btn-import').addEventListener('change', (e) => {
      const f = e.target.files && e.target.files[0];
      if (f) importProgress(f);
      e.target.value = '';
    });
  }

  fetch('data/labs.json').then(r => r.json()).then(d => {
    state.data = d;
    setupToolbar();
    setupAuth();
    loadSolved();
  }).catch(() => {
    document.getElementById('grid').innerHTML = '<p class="muted">Could not load labs.json.</p>';
  });
})();