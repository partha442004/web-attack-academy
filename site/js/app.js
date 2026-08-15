// Dashboard logic — loads labs.json, renders topic cards, tracks solved labs.
(function () {
  const state = { solved: new Set(), data: null, filters: { q: '', diff: '', status: '' } };

  function api(url) {
    return fetch(url, { credentials: 'include' }).then(r => r.json()).catch(() => ({ solved: false }));
  }

  async function loadSolved() {
    if (!state.data) return;
    const ids = Object.keys(state.data.labs);
    // status endpoint returns solved state per lab via the session cookie
    const results = await Promise.all(ids.map(id => api(CONFIG.API_BASE + '/api/status/' + id)));
    state.solved.clear();
    ids.forEach((id, i) => { if (results[i] && results[i].solved) state.solved.add(id); });
    render();
    updateProgress();
    renderMastery();
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
  }

  function setupTheme() {
    const btn = document.getElementById('theme-toggle');
    const saved = localStorage.getItem('waa-theme');
    const apply = (dark) => {
      document.documentElement.dataset.theme = dark ? 'dark' : 'light';
      btn.textContent = dark ? '☀️ Light' : '🌙 Dark';
      localStorage.setItem('waa-theme', dark ? 'dark' : 'light');
    };
    btn.addEventListener('click', () => {
      apply(document.documentElement.dataset.theme !== 'dark');
    });
    apply(saved === 'dark');
  }

  fetch('data/labs.json').then(r => r.json()).then(d => {
    state.data = d;
    setupToolbar();
    setupTheme();
    loadSolved();
  }).catch(() => {
    document.getElementById('grid').innerHTML = '<p class="muted">Could not load labs.json.</p>';
  });
})();