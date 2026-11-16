---
title: "Mobile App Architecture"
created: 2026-11-16
type: concept
tags: [mobile, architecture, concept]
---

Understanding what's inside a mobile app package is the foundation of mobile pentesting. You can't find vulnerabilities if you don't know where to look.

## The Application Package

When a developer builds a mobile app, the output is a **package file** — a zip-like archive containing everything the app needs to run:

| Platform | Format | Extension |
|----------|--------|-----------|
| Android | Android Package Kit | `.apk` |
| iOS | iOS App Store Package | `.ipa` |

Both can be unzipped and inspected. Inside you'll find:

- **Compiled code** — the application logic (DEX bytecode on Android, Mach-O binary on iOS)
- **Manifest / config file** — declares permissions, components, and behavior to the OS
- **Resources** — images, layouts, strings, fonts
- **Assets** — local databases, certificates, embedded config files

## The Manifest

The first file to check on every engagement. It's the app's declaration to the OS.

**Android** — `AndroidManifest.xml`:
- App name, package name, SDK versions
- Requested permissions
- Components and whether they're exported
- Flags like `debuggable` and `allowBackup`

**iOS** — `Info.plist`:
- App identifier, version
- Permission usage descriptions (camera, location, etc.)
- `NSAppTransportSecurity` settings (HTTPS enforcement)
- URL schemes the app handles

## The Sandbox

Each app runs in its own **isolated container**. By default, App A cannot read App B's files or interact with its processes. The OS enforces this by giving each app its own user ID and private filesystem space.

The sandbox defines the attack surface — if an app weakens its own isolation (misconfiguration) or you find a sandbox escape, that's a serious finding.

## Application Components (Android)

Apps are built from distinct components, each serving a different purpose:

| Component | Purpose | Example |
|-----------|---------|---------|
| **Activity** | A single screen the user sees | Login screen, settings page |
| **Service** | Background task with no UI | Music playback, data sync |
| **Broadcast Receiver** | Responds to system-wide events | Battery low, SMS received |
| **Content Provider** | Shares structured data with other apps | Contacts database |

Each component can be:
- **Internal** — only accessible within the app
- **Exported** (`android:exported="true"`) — accessible to other apps on the device

An exported component that shouldn't be exposed = attack surface. A malicious app can call it directly, bypassing authentication.

## Inter-App Communication

The sandbox doesn't mean zero communication — the OS provides **supervised channels**:

- **Intents** (Android) — messages routed through the OS. Explicit (targets a specific app) or implicit (any app that can handle it)
- **Content Providers** — controlled data-sharing interfaces queried through the OS
- **URL Schemes / Deep Links** — custom URL patterns (`myapp://action?param=value`) that trigger app functionality
- **App Extensions** (iOS) — controlled plugins for sharing, widgets, etc.

Security risk: sensitive data passed through implicit intents or unvalidated deep links can be intercepted by malicious apps.

## Related Notes

- [[Mobile Pentesting Methodology]] — the four-phase approach
- [[Mobile Static Analysis]] — pulling apart the package
- [[Common Mobile Vulnerabilities]] — OWASP Mobile Top 10 categories
