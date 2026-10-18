---
title: "Name Resolution"
created: 2026-03-11
type: concept
tags: [concept, network, protocols, windows]
---

# Windows Name Resolution Stack

Before any remote protocol can communicate (like SMB, RPC, or LDAP), the system needs to **resolve the target hostname to an IP address**.

Windows follows this approximate order:

```txt
1. HOSTS file
2. DNS
3. mDNS (UDP 5353)
4. LLMNR (UDP 5355)
5. [[NetBIOS]] Name Service (NBT-NS, UDP 137)
```

We’ll now go into each one.

---

## 🔹 1. HOSTS File

**Location:** `C:\Windows\System32\drivers\etc\hosts`  
**Scope:** Local only  
**Purpose:** Static hostname-to-IP mapping

### 🧩 How It Works

- This is a plaintext file checked **before** any external name resolution.
    
- Entries look like:
    
    `192.168.1.44  internalapp.local 127.0.0.1     localhost`
    
- Useful for hard-coded overrides or internal testing.
    

### 🧠 Use Cases

- Dev/test environments
    
- Blocking known malicious domains
    
- Overriding DNS during migration
    

### 🔐 Risks

- Can be abused by malware to redirect traffic
    
- Should be monitored or locked down
    

---

## 🔹 2. DNS (Domain Name System)

**Port:** UDP/TCP 53  
**Scope:** Global  
**Purpose:** Resolve FQDNs via authoritative servers

### 🧩 How It Works

- Windows sends a unicast DNS query to the configured server (e.g. `8.8.8.8`)
    
- Receives a response like:
    
    `A → fileserver.corp → 10.0.1.15`
    
- Primary and preferred method in enterprise and internet scenarios
    

### 🧠 Use Cases

- Internal Active Directory domain resolution
    
- External web access (`example.com`)
    

### 🔐 Risks

- Subject to DNS spoofing / poisoning if not secured (e.g., no DNSSEC)
    

---

## 🔹 3. mDNS (Multicast DNS)

**Port:** UDP 5353  
**Scope:** Local subnet  
**Purpose:** Resolve `.local` hostnames via multicast  
**Introduced:** Windows 10+ (Bonjour-like functionality)

### 🧩 How It Works

- Sends a query to:
    
    `224.0.0.251:5353 → A? printer.local`
    
- All devices listen and respond if the name matches
    

### 🧪 Example

`mDNS query → 224.0.0.251:5353 → A? 3dprinter.local Response   ← 3dprinter.local = 192.168.1.77`

### 📸 Wireshark Filter

`udp.port == 5353`

### 🔐 Risks

- Passive enumeration (device names/services)
    
- Not as spoofable, but useful for recon
    

---

## 🔹 4. LLMNR (Link-Local Multicast Name Resolution)

**Port:** UDP 5355  
**Scope:** Local subnet  
**Purpose:** Resolve hostnames when DNS/mDNS fail

### 🧩 How It Works

- Sends a multicast query to:
    
    `224.0.0.252:5355 → Who has devhost?`
    
- Any device with that name responds
    

### 🧪 Example

`LLMNR query → 224.0.0.252:5355 → Who has "devhost"? Response     ← devhost = 192.168.1.44`

### 📸 Wireshark Filter

`udp.port == 5355`

### 🔐 Risks

- Spoofable — commonly exploited with **Responder**
    
- Attackers can intercept SMB auth and capture NTLM hashes
    
- Should be disabled in secure environments
    

---

## 🔹 5. NetBIOS Name Service (NBT-NS)

**Port:** UDP 137  
**Scope:** Local broadcast  
**Purpose:** Legacy name resolution (pre-DNS/AD)

### 🧩 How It Works

- Sends a broadcast like:
    
    `"Who has PRINTSRV01?"`
    
- The real host replies with its IP
    

### 🧪 Example

`Broadcast → 255.255.255.255:137 Response  ← PRINTSRV01 is at 192.168.1.50`

### 📸 Wireshark Filter

`udp.port == 137`

### 🔐 Risks

- Legacy and fully spoofable
    
- Easily abused by **Responder** or **NBNSpoof**
    
- Disable via adapter settings unless legacy support is required
    

---

# 📊 Summary Table: Name Resolution Protocols

|Protocol|Port|Scope|Purpose|Modern?|Risks|
|---|---|---|---|---|---|
|**HOSTS**|—|Local|Static name-to-IP entries|✅|Malware abuse|
|**DNS**|53/udp/tcp|Global|Authoritative FQDN resolution|✅|Spoofing|
|**mDNS**|5353/udp|Local|`.local` resolution via multicast|✅ Win10+|Recon|
|**LLMNR**|5355/udp|Local|Hostname fallback when DNS fails|✅ Vista+|Spoofable|
|**NBT-NS**|137/udp|Broadcast|NetBIOS legacy fallback|❌ Legacy|Spoofable|

---

# 🛡️ Security Hardening Recommendations

|Action|How to Implement|
|---|---|
|❌ Disable LLMNR|GPO → `Computer Configuration > Admin Templates > Network > DNS Client`|
|❌ Disable NBT-NS|Adapter Settings → `Disable NetBIOS over TCP/IP`|
|✅ Lock down HOSTS file|Use ACLs or AppLocker to restrict write access|
|✅ Monitor mDNS/LLMNR|Wireshark: `udp.port == 5353|
|✅ Enforce DNS-only|GPO + local policy + firewall restrictions on fallback protocols