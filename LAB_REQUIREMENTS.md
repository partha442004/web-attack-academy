# Web Attack Academy — Lab Requirements Specification

## Core Lab Structure (Implemented)

| Component | Status | Description |
|-----------|--------|-------------|
| Title + Difficulty + Status | ✅ | Pill badges, solved banner |
| Objective (Markdown) | ✅ | Rich text, code blocks, hints |
| Hints (3 levels) | ✅ | Hint 1, Hint 2, Solution |
| Request Inspector | ✅ | Raw HTTP builder, headers, body |
| Request Console | ✅ | Live logs, solve events |
| Challenge Iframe | ✅ | Sandboxed Cloudflare Worker |

---

## Required Enhancements (Priority Order)

### 1. Lab Metadata & Discovery
- [ ] **Tags/Categories**: `sqli`, `xss`, `ssrf`, `idor`, `auth-bypass`, `crypto`, `logic`
- [ ] **Prerequisites**: Linked labs that must be solved first
- [ ] **Estimated Time**: `5min`, `15min`, `30min+`
- [ ] **Author/Version**: Attribution, schema version
- [ ] **Difficulty Sub-tier**: `★☆☆☆☆` through `★★★★★` with tooltip breakdown

### 2. In-Lab Progress & Guidance
- [ ] **Step Tracker**: Visual progress (Step 1/4 → Step 2/4…) inside lab
- [ ] **Objective Checkboxes**: Auto-check when console detects solve criteria
- [ ] **Contextual Cheatsheet**: Slide-out panel with vuln-class reference (payloads, headers, tools)
- [ ] **Interactive Hint Unlock**: Hints reveal progressively (time/gate based)

### 3. Request/Response Tooling
- [ ] **Request History**: Timeline of all attempts with diff view
- [ ] **Copy as cURL / Fetch / Python**: One-click export
- [ ] **Response Diff**: Highlight changes between attempts
- [ ] **Save/Load Reproducer**: JSON export of full request chain
- [ ] **Parameter Fuzzer**: Built-in payload lists per vuln type

### 4. Post-Solve Experience
- [ ] **Full Walkthrough**: Expandable solution with explanation, not just payload
- [ ] **Mitigation Guide**: How to fix in real code (language-specific snippets)
- [ ] **Related Labs**: "Try next: XSS-2, SSRF-1" with prerequisite links
- [ ] **Lab Rating**: 👍/👎 + optional comment → feeds quality signal

### 5. Accessibility & UX
- [ ] **Keyboard Shortcuts**: `Ctrl+Enter` send, `Ctrl+/` focus search, `?` help
- [ ] **Focus Management**: Trap focus in modals, restore on close
- [ ] **Screen Reader**: Live regions for console updates, ARIA labels
- [ ] **Reduced Motion**: Respect `prefers-reduced-motion`

### 6. Mobile/Responsive
- [ ] **Collapsible Panels**: Request inspector / console hide on mobile
- [ ] **Touch-Friendly**: Larger tap targets, swipe gestures
- [ ] **Viewport Iframe**: Responsive challenge frame

### 7. Lab Authoring (Meta)
- [ ] **Lab Schema v2**: `labs.json` with all new fields
- [ ] **Visual Lab Builder**: Web UI to create labs without JSON editing
- [ ] **Validation CLI**: `npm run validate:labs` checks schema, reachable URLs
- [ ] **Template Labs**: Starter repos for each vuln class

---

## labs.json Schema v2 (Proposed)

```json
{
  "id": "sqli-1",
  "title": "SQL Injection - Login Bypass",
  "topic": "SQL Injection",
  "difficulty": 1,
  "tags": ["sqli", "auth-bypass", "union"],
  "prerequisites": [],
  "estimatedTimeMinutes": 10,
  "author": "security-team",
  "version": "1.0.0",
  "objective": "Markdown with **bold**, `code`, ```blocks```",
  "hints": [
    "Look at the login form — what parameter is reflected?",
    "Try `' OR '1'='1` in the username field",
    "Full payload: `admin' --`"
  ],
  "solution": {
    "payload": "admin' --",
    "explanation": "The query concatenates input directly...",
    "mitigation": {
      "js": "Use parameterized queries: `db.prepare('SELECT * FROM users WHERE user=?').get(username)`",
      "python": "cursor.execute('SELECT * FROM users WHERE user=%s', (username,))"
    }
  },
  "cheatsheet": {
    "payloads": ["' OR 1=1--", "' UNION SELECT null,version()--"],
    "tools": ["sqlmap", "nosqlmap"],
    "references": ["https://owasp.org/.../SQL_Injection"]
  },
  "verification": {
    "type": "console-log",
    "match": "LAB_SOLVED:sqli-1"
  },
  "related": ["sqli-2", "sqli-3", "auth-1"]
}
```

---

## Implementation Checklist (Next Sprint)

| Task | Effort | Impact |
|------|--------|--------|
| Add `tags`, `prerequisites`, `estimatedTime` to labs.json | S | High |
| Step tracker UI in lab header | M | High |
| Cheatsheet slide-out panel | M | High |
| Request history + copy-as-cURL | M | High |
| Full solution walkthrough modal | M | Medium |
| Keyboard shortcuts (`Ctrl+Enter`, `?`) | S | Medium |
| Lab rating widget | S | Medium |
| Mobile panel collapse | M | Medium |
| Lab schema validation script | S | High |

---

## Design Principles

1. **Zero-friction learning**: No setup, instant feedback, progressive disclosure
2. **Real tooling**: Request inspector mirrors Burp/Postman workflows
3. **Teach, don't just test**: Hints → Solution → Mitigation → Related
4. **Accessible by default**: WCAG 2.1 AA, keyboard-first
5. **Extensible**: New vuln classes add via schema, not code changes