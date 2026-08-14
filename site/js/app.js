// Dashboard logic — loads labs.json, renders topic cards, tracks solved labs.
(function () {
  const state = { solved: new Set(), data: null };

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
  }

  function updateProgress() {
    const total = Object.keys(state.data.labs).length;
    const done = state.solved.size;
    const el = document.getElementById('global-progress');
    if (el) el.innerHTML = `<strong>${done}</strong> / ${total} solved`;
  }

  function render() {
    const container = document.getElementById('grid');
    container.innerHTML = '';
    for (const topic of state.data.topics) {
      const card = document.createElement('div');
      card.className = 'topic-card';
      const doneInTopic = topic.labs.filter(id => state.solved.has(id)).length;
      card.innerHTML = `
        <div class="topic-head" style="background:${topic.color}">
          <h2>${topic.name}</h2>
          <span class="count">${doneInTopic}/${topic.labs.length}</span>
        </div>
        <div class="lab-list">${topic.labs.map(id => {
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
  }

  fetch('data/labs.json').then(r => r.json()).then(d => {
    state.data = d;
    loadSolved();
  }).catch(() => {
    document.getElementById('grid').innerHTML = '<p class="muted">Could not load labs.json.</p>';
  });
})();