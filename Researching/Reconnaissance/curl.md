---
title: "curl"
created: 2026-03-11
type: tool
tags: [tool, recon, http]
---

# curl

Command-line tool to transfer data to or from a server. Supports HTTP, HTTPS, FTP, SFTP, SCP, SMTP, and many more protocols. Essential for manual web testing — send custom requests, inspect headers, follow redirects, and handle cookies.

---

## Basic Usage

```bash
curl http://target.com
```

## Flags

| Flag | Purpose |
|------|---------|
| `-X <method>` | HTTP method (GET, POST, PUT, DELETE) |
| `-d <data>` | Send POST data |
| `-H <header>` | Add/override a header |
| `-b <cookies>` | Send cookies (string or file) |
| `-c <file>` | Save response cookies to file |
| `-L` | Follow redirects |
| `-s` | Silent mode (no progress bar) |
| `-v` | Verbose — show request/response headers |
| `-I` | Fetch headers only (HEAD request) |
| `-o <file>` | Save output to file |
| `-O` | Save with remote filename |
| `-k` | Skip TLS certificate verification |
| `-A <agent>` | Set User-Agent string |
| `-x <proxy>` | Use a proxy (e.g., Burp: `http://127.0.0.1:8080`) |
| `-u user:pass` | Basic authentication |

---

## Common Pentest Examples

### GET with custom header

```bash
curl -H "Authorization: Bearer <token>" http://target.com/api/users
```

### POST with form data

```bash
curl -X POST -d "username=admin&password=test" http://target.com/login
```

### POST with JSON

```bash
curl -X POST -H "Content-Type: application/json" -d '{"user":"admin"}' http://target.com/api
```

### Send cookies

```bash
curl -b "session=abc123; admin=true" http://target.com/dashboard
```

### View response headers only

```bash
curl -I http://target.com
```

### Follow redirects and save output

```bash
curl -L -o page.html http://target.com/redirect
```

### Proxy through Burp Suite

```bash
curl -x http://127.0.0.1:8080 -k http://target.com
```

---

## Related Notes

- [[ffuf]] — automated fuzzing
- [[Hydra]] — login brute-forcing
- [[HTTP Server]]
