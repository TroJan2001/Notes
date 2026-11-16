---
title: "Mobile Dynamic Analysis"
created: 2026-11-16
type: technique
tags: [mobile, dynamic-analysis, technique]
---

Dynamic analysis means running the app and observing what it **actually does** — network traffic, data storage, log output, runtime behavior. Catches vulnerabilities invisible to static analysis.

## Traffic Interception

Same concept as Burp Suite on web apps — route the device's traffic through a proxy.

**Setup:** Configure device Wi-Fi proxy to Burp's IP/port, install Burp's CA cert on the device.

**What to look for:**
- Data sent over HTTP instead of HTTPS (instant M5 finding)
- Sensitive data in request/response bodies (passwords, PII, tokens)
- Auth tokens transmitted insecurely
- Calls to unexpected third-party services
- API endpoints with weak or missing authentication

## SSL Pinning and Bypassing It

Some apps hardcode which certificate(s) they trust — not any CA-signed cert, only a specific one. When Burp presents its own cert, the app refuses to communicate.

SSL pinning is a **security control**, not a vulnerability. But pentesters need to bypass it.

**Objection** — runtime mobile exploration toolkit:
- Disables SSL pinning on a running app without source code access
- Can also inspect exported components and runtime data
- Built on top of Frida

## Runtime Instrumentation with Frida

**Frida** is the primary framework for mobile runtime testing. Attach to a running app and:

- List all classes and methods
- **Hook** specific functions to see data passing through them
- Bypass authentication checks (e.g., force `isAuthenticated()` to return `true`)
- Bypass biometric checks, root detection, certificate pinning
- Extract data from memory
- Modify return values and arguments

Objection provides convenient pre-built Frida commands. When those aren't enough, write custom Frida scripts.

## Insecure Logging

Developers forget to strip debug logging before release. Monitor device logs while exercising the app:

```bash
adb logcat | grep -i "password\|token\|key\|secret"
```

Sensitive data in logs (usernames, tokens, API responses, passwords) is an M9: Insecure Data Storage finding. On older Android versions, any app could read the system log.

## Biometric Bypass

Bad implementation: app asks the OS "did fingerprint check pass?" and trusts the boolean. Frida hooks that function and returns `true`.

Good implementation: biometric unlocks a **cryptographic key** in hardware (Android Keystore / iOS Secure Enclave). The key is required for the server request — can't be faked.

## Related Notes

- [[Mobile Static Analysis]] — examining without running
- [[Mobile Pentesting Methodology]] — the four-phase approach
- [[Common Mobile Vulnerabilities]] — OWASP categories
