---
title: "Legacy Packages"
created: 2026-03-11
type: concept
tags: [concept, enumeration, linux, privesc]
---

We can check for packages that might be not upgraded which give us the chance to escalate our privileges.

To look for packages:

```bash
dpkg -l
or
apt list --upgradeable
```