---
title: "Mobile Static Analysis"
created: 2026-11-16
type: technique
tags: [mobile, static-analysis, technique]
---

Static analysis means pulling apart the app package and examining it **without running it**. Often yields the quickest findings.

## Step 1: Get the Package

- Client provides it (grey/white-box engagement)
- Pull from device: `adb pull /data/app/<package>/base.apk` (Android)
- Download from app store

## Step 2: Unpack and Decompile

**Android (APK):**
- `apktool d app.apk` — decodes resources and manifest, outputs smali bytecode
- `jadx app.apk` — decompiles DEX bytecode back to readable Java-like source
- Or just rename to `.zip` and unzip for raw contents

**iOS (IPA):**
- Rename to `.zip` and extract
- Binary is a Mach-O file inside `Payload/<AppName>.app/`
- `.plist` files are immediately readable

## Step 3: Read the Manifest

**Android — `AndroidManifest.xml`:**

| What to check | Why it matters | OWASP |
|---------------|---------------|-------|
| Over-requested permissions | Camera, contacts, mic on a calculator app? More permissions = bigger blast radius if compromised | M8 |
| `android:exported="true"` on components | Other apps can call them directly, bypassing authentication | M8 |
| `android:debuggable="true"` | Attacker can attach debugger, dump memory, intercept calls | M8 |
| `android:allowBackup="true"` | App data extractable via ADB backup | M8 |

**iOS — `Info.plist`:**

| What to check | Why it matters | OWASP |
|---------------|---------------|-------|
| `NSAllowsArbitraryLoads = true` | Disables App Transport Security, allows HTTP traffic | M5, M8 |
| Unnecessary permission descriptions | Camera, mic, contacts listed without legitimate need | M8 |
| Custom URL schemes | Can be triggered by malicious links if unvalidated | M8 |

## Step 4: Hunt for Hardcoded Secrets

Developers leave things behind. Search everywhere:

- **Decompiled source code** — API keys, passwords, encryption keys in Java/Kotlin/Swift/ObjC
- **String resource files** — `strings.xml` (Android), `.plist` files (iOS)
- **Config files** — bundled JSON, XML, YAML configs
- **Asset databases** — SQLite files in the assets directory

Quick grep across unpacked directory:
```bash
grep -ri "api_key\|password\|secret\|token\|private_key" .
```

These are OWASP M1: Improper Credential Usage findings.

## Step 5: Automated Scanning with MobSF

**Mobile Security Framework (MobSF)** — open-source tool that automates static analysis:

1. Upload APK or IPA to the web interface
2. It scans permissions, manifest, code, and resources
3. Produces a detailed report with severity ratings

What MobSF checks:
- Permissions analysis
- Manifest misconfigurations
- Hardcoded secrets in code and resources
- Binary security flags
- Transport security settings
- Tracker detection

Use MobSF as a **first pass** — surfaces obvious issues fast. Then do manual review for business logic flaws, subtle data handling issues, and context-dependent vulnerabilities that automation misses.

## Related Notes

- [[Mobile App Architecture]] — what's inside the package
- [[Mobile Dynamic Analysis]] — runtime testing
- [[Common Mobile Vulnerabilities]] — OWASP categories
