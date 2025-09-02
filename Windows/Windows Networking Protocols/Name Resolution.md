# Windows Name Resolution Stack (Detailed)

Before any remote protocol can communicate (like SMB, RPC, or LDAP), the system needs to **resolve the target hostname to an IP address**.

Windows follows this approximate order:

```txt
1. HOSTS file 
2. DNS
3. NetBIOS Name Service (NBT-NS, UDP 137) 
4. LLMNR (UDP 5355) 
5. mDNS (UDP 5353) 
6. WSD / WS-Discovery (UDP/TCP 3702)`
```

We’ll now go into each one.

---

## 🔹 1. NetBIOS Name Service (NBT-NS)

**Port:** UDP 137  
**Legacy:** Yes (pre-Windows 2000, but still often enabled)  
**Purpose:** Resolve **NetBIOS names** to IP addresses (not FQDNs)

### 🧩 How It Works

- NetBIOS names are 15-character machine identifiers used in LANs.
    
- When a NetBIOS name is unresolved, Windows sends a **broadcast** query:
    
    `“Who has NETBIOSNAME?”`
    
- Any host that owns that name responds with its IP.
    

### 🧪 Example

- You're trying to access: `\\PRINTSRV01\share`
    
- Windows sends:
    
    `Name query request for PRINTSRV01 → Broadcasted to 255.255.255.255:137 (or subnet-wide)`
    
- The target responds:
    
    `Name query response: PRINTSRV01 is at 192.168.1.50`
    

### 📸 Wireshark Filter

`udp.port == 137`

### 🔐 Risks / Abuse

- **Responder tool** can spoof NBT-NS responses → steal NTLM hashes via SMB.
    
- **No authentication** of replies.
    
- Legacy, but dangerous when enabled.
    

---
## 🔹 2. LLMNR (Link-Local Multicast Name Resolution)

**Port:** UDP 5355  
**Scope:** Local subnet  
**Introduced:** Windows Vista+  
**Purpose:** Resolve **hostnames** (not FQDNs) when DNS fails

### 🧩 How It Works

- Used when DNS fails or the hostname is local-only.
    
- Sends a **multicast** query to IPv4 `224.0.0.252` (and IPv6 equivalent).
    
    `"Who has HOSTNAME.local?"`
    
- The host with that name replies with its IP.
    

### 🧪 Example

- Trying: `ping devhost`
    
- No DNS entry, so:
    
    `LLMNR query → 224.0.0.252:5355 → Who has "devhost"?`
    
- The real `devhost` replies: "It’s me: 192.168.1.44"

### 📸 Wireshark Filter

`udp.port == 5355`

### 🔐 Risks / Abuse

- Like NBT-NS, attackers can spoof answers (Responder again).
    
- **LLMNR + SMB = NTLMv2 hash leak**
    
- Should be **disabled** via Group Policy.
    

---
## 🔹 3. mDNS (Multicast DNS)

**Port:** UDP 5353  
**Scope:** Local subnet  
**Purpose:** Resolves `.local` hostnames in a DNS-like way  
**Introduced:** Apple Bonjour, now used in Windows 10/11

## 🟣 What is `.local`?

`.local` is a **special name ending** that devices use to **identify themselves on your local network**, like:

```txt
#Examples:
raspberrypi.local
printer.local 
macbook.local
```

When someone types something like `ping printer.local`, your computer **does not** ask the DNS server.  
Instead, it asks nearby devices on the network:

> “Hey, does anyone here go by the name `printer.local`?”

That’s called **multicast DNS (mDNS)**, it's like shouting out the question to the whole local network.

### 🧩 How It Works

- Similar to DNS, but uses multicast.
    
- Queries like:
    
    `A query for "printer.local"`
    
- Sent to `224.0.0.251` (IPv4) or `ff02::fb` (IPv6).
    
- The device with that name replies with its IP.
    
### 🧪 Example

- Windows 11 user opens `\\3dprinter.local`
    
- Packet sent:
    
    `mDNS query → 224.0.0.251:5353 → A? 3dprinter.local`
    
- Response:
    
    `3dprinter.local = 192.168.1.77`
    

### 📸 Wireshark Filter

`udp.port == 5353`

### 🧠 Use Cases

- Apple devices (Bonjour)
    
- Network printers
    
- Windows 10/11 with **Function Discovery Provider Host** enabled
    

### 🔐 Risks

- Not as vulnerable as LLMNR/NBT-NS, but still relies on trust.
    
- Can be used for passive discovery (e.g., service names, device types).
    

---
## 🔹 4. WSD (Web Services Discovery)

**Ports:** UDP 3702 (query), TCP (device response)  
**Scope:** Local subnet  
**Purpose:** Device discovery (printers, cameras, etc.)  
**Protocol:** Based on SOAP over UDP/TCP

**Note:** WSD is for **finding services** like printers, scanners, and cameras — not just resolving hostnames.
### 🧩 How It Works

- Windows sends a SOAP-based probe:
    
    `UDP 3702: "Are there any printers or scanners?"`
    
- Devices reply over TCP with metadata (model, address, etc.)
    

### 🧪 Example

- You open **Add Printer** dialog
    
- Windows sends:
    
    `SOAP probe → 239.255.255.250:3702`
    
- Canon printer replies:
    
    `"I'm here at 192.168.1.40, model: Canon XYZ"`
    

### 📸 Wireshark Filter

`udp.port == 3702`

### 🧠 Uses

- Discovery of plug-and-play network devices
    
- Windows clients prefer WSD over SMB browser service now
    

### 🔐 Risks

- Lower risk for spoofing (requires proper SOAP-formatted response)
    
- Useful for reconnaissance
    

---

# 📊 Summary Table: Comparison

| Protocol   | Port     | Scope                          | Use                                                                       | Modern?  | Risks     |
| ---------- | -------- | ------------------------------ | ------------------------------------------------------------------------- | -------- | --------- |
| **NBT-NS** | 137/udp  | Broadcast                      | NetBIOS → IP                                                              | ❌ Legacy | Spoofable |
| **LLMNR**  | 5355/udp | Multicast                      | Resolve hostnames (like printer1) when DNS fails                          | ✅ Vista+ | Spoofable |
| **mDNS**   | 5353/udp | Multicast                      | Resolve `.local` names (e.g. `printer.local`) like DNS, but via multicast | ✅ Win10+ | Recon     |
| **WSD**    | 3702/udp | Multicast (query), TCP (reply) | Discover **devices** and their **services** (like printers/scanners)      | ✅        | Low risk  |

---

## 🛡️ Security Hardening Recommendations

|Action|How|
|---|---|
|❌ Disable LLMNR|GPO → `Computer Configuration > Admin Templates > Network > DNS Client`|
|❌ Disable NBT-NS|Adapter settings → `Disable NetBIOS over TCP/IP`|
|✅ Monitor mDNS/WSD|Filter in Wireshark, look for `.local`, port 3702|
|✅ Enforce DNS-only resolution|Use `hosts` file for static names, disable fallbacks|
