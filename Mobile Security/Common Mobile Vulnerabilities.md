---
title: "Common Mobile Vulnerabilities"
created: 2026-11-16
type: concept
tags: [mobile, vulnerabilities, owasp, concept]
---

The most common vulnerability categories found during mobile pentests, mapped to the OWASP Mobile Top 10.

## Insecure Data Storage (M9)

The app stores sensitive data where an attacker can read it.

**Where to check:**
- SharedPreferences (Android) / NSUserDefaults (iOS) — plaintext key-value stores
- SQLite databases without encryption
- Log files with debug output containing credentials
- SD card / shared storage readable by other apps
- HTTP response caches containing sensitive API data

**Fix:** Use platform secure storage (Android Keystore, iOS Keychain), encrypt local data, don't cache sensitive responses.

## Improper Credential Usage (M1)

Hardcoded secrets in the app package — API keys, passwords, encryption keys, internal URLs embedded in source code or resource files.

Once the APK/IPA is distributed, anyone can decompile it and extract these in minutes.

**Fix:** Never hardcode secrets. Use server-side configuration, environment variables, or secure key management services.

## Security Misconfiguration (M8)

The app misuses or ignores platform security features.

**Common findings:**
- Over-requested permissions (camera, mic, contacts on an app that doesn't need them)
- `android:debuggable="true"` in production
- `android:allowBackup="true"` allowing ADB data extraction
- Exported components without permission restrictions
- `NSAllowsArbitraryLoads = true` disabling iOS HTTPS enforcement (also M5)

## Insecure Communication (M5)

Data transmitted without proper encryption.

- HTTP instead of HTTPS for sensitive requests
- ATS disabled on iOS (`NSAllowsArbitraryLoads`)
- Weak TLS versions or cipher suites
- Certificate validation disabled in code

## Insecure Authentication (M3)

Authentication and session management flaws:

- Session tokens that never expire
- Tokens stored in plaintext on device (overlaps M9)
- No re-authentication for sensitive actions (password change, money transfer)
- Biometric bypass — trusting the OS boolean instead of using hardware-backed crypto keys
- Missing server-side session validation

## Exposed Components (M8)

Activities, services, or content providers marked as `exported` without access controls. Any app on the device can call them directly.

Example: an exported `AdminPanelActivity` with no permission attribute — a malicious app launches it and bypasses login entirely.

## Insufficient Binary Protections (M7)

The compiled app isn't hardened against reverse engineering.

| Protection | Purpose | Without it |
|-----------|---------|-----------|
| **Obfuscation** | Scrambles class/method names | Decompiled code reads like original source |
| **Tamper detection** | Verifies app integrity at startup | Attacker modifies APK, injects code, redistributes |
| **Root/jailbreak detection** | Detects modified devices | Attacker has full filesystem access, Frida hooks, sandbox bypass |

Root/jailbreak detection is especially critical for banking, healthcare, and any app handling sensitive data — a rooted device breaks the sandbox model.

## Related Notes

- [[Mobile Static Analysis]] — finding these in code review
- [[Mobile Dynamic Analysis]] — finding these at runtime
- [[Mobile Pentesting Methodology]] — systematic approach
