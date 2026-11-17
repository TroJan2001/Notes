---
title: "Python Recon Scripts"
created: 2026-11-17
type: technique
tags: [python, recon, scripting, technique]
---

Python patterns for web reconnaissance and data gathering during the enumeration phase.

## Subdomain Enumeration with `requests`

Wordlist-driven HTTP probing — same logic as Gobuster/Sublist3r under the hood:

```python
import requests

def enumerate_subdomains(domain, wordlist):
    found = []
    for sub in wordlist:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url, timeout=3)
            found.append(url)
        except (requests.ConnectionError, requests.Timeout):
            pass
    return found
```

## Directory Enumeration with `requests`

Append wordlist entries to a target URL path and check status codes:

```python
def enumerate_directories(target_url, wordlist, extension=".html"):
    found = []
    for entry in wordlist:
        url = f"{target_url}/{entry}{extension}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code != 404:
                found.append((r.status_code, url))
        except (requests.ConnectionError, requests.Timeout):
            pass
    return found
```

Key status codes: **200** = exists, **301** = redirect (follow it), **403** = forbidden but exists (look harder), **404** = skip.

## Web Scraping with `BeautifulSoup`

Extract links, emails, credentials, or hidden fields from HTML:

```python
import requests
from bs4 import BeautifulSoup

r = requests.get("http://target.com")
soup = BeautifulSoup(r.text, "html.parser")

# Extract all links
links = [a["href"] for a in soup.find_all("a", href=True)]

# Extract all form fields (find hidden inputs, CSRF tokens)
for form in soup.find_all("form"):
    for inp in form.find_all("input"):
        print(inp.get("name"), inp.get("value"), inp.get("type"))

# Extract emails with regex
import re
emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
```

Install: `pip3 install beautifulsoup4`

## Automated File Downloads

Streaming download for large files — constant memory regardless of file size:

```python
def download_file(url, output_path):
    r = requests.get(url, stream=True, timeout=30)
    r.raise_for_status()
    with open(output_path, "wb") as f:   # wb = binary mode, critical
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
```

Always use `"wb"` mode — text mode corrupts binary files.

## Programmatic Nmap with `python-nmap`

Wrap nmap in Python for scripted scanning workflows:

```python
import nmap

scanner = nmap.PortScanner()
scanner.scan("192.168.1.0/24", "22,80,443", arguments="-sV")

for host in scanner.all_hosts():
    for port in scanner[host]["tcp"]:
        state = scanner[host]["tcp"][port]["state"]
        service = scanner[host]["tcp"][port]["name"]
        print(f"{host}:{port} — {state} ({service})")
```

Install: `pip3 install python-nmap` (requires nmap installed on system)

## Related Notes

- [[Python Network Scripts]] — ARP scanning, packet manipulation
- [[Python Exploitation Scripts]] — hash cracking, brute-force, Impacket
- [[Python Pentest Libraries]] — full library reference
