**NetBIOS** is a legacy API and protocol suite originally designed for small networks in the 1980s. It allows applications on separate computers to communicate over a LAN (Local Area Network). Microsoft later adapted it to work over TCP/IP, even though it was originally designed for non-routable protocols like NetBEUI.

- **Not a protocol by itself** — it's an API used by programs, and protocols like **NetBIOS over TCP/IP (NBT)** implement the functionality.
    
- Still present in many Windows systems for backward compatibility and legacy applications.

| Term             | Description                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------- |
| **NetBIOS Name** | A 16-character name (15 characters + suffix) used to identify a device/application on a LAN |
| **Sessions**     | Persistent connections between two NetBIOS-enabled devices                                  |
| **Datagrams**    | Connectionless messages sent to multiple hosts                                              |
| **Name Service** | Resolves NetBIOS names to IP addresses (UDP 137)                                            |
## 🔧 NetBIOS Components

### 1. **Name Service (UDP 137)**

- Resolves NetBIOS names → IP addresses
    
- Works like DNS, but only for NetBIOS names
    
- Can be **broadcast-based** or use a centralized **WINS server**
#### 🧪 Example

When a computer wants to access `\\HR-SERVER`, it sends a **broadcast** like:

`"Who has HR-SERVER<20>? Tell 192.168.1.10"`

Where:

- `HR-SERVER` is the NetBIOS name
    
- `<20>` = hex code for “File Server Service”
    
- All machines respond if they match
    

> 🛡️ Vulnerability: This is what tools like **Responder** exploit. If the real HR-SERVER is offline or slow, an attacker can reply and receive sensitive authentication info.

---
### 2. **Datagram Service (UDP 138)**

- Used for sending **connectionless** messages
    
- Often for **broadcasting** announcements (e.g., “I am here”)
    
#### 🧪 Example

A PC announces itself on the LAN:

`"HR-SERVER is available at 192.168.1.50"`

No connection is required, just a message fired off to the local subnet.

---

### 3. **Session Service (TCP 139)**

- Establishes a **connection-oriented** session between two hosts
    
- Used for **file sharing, remote administration**, etc.
    
- Used to tunnel **SMB traffic** in legacy configurations
    

> ⚠️ TCP 139 is how SMB worked before SMB over port 445 was introduced. Still sometimes seen in segmented or older networks.

---
## 🧠 NetBIOS Name Details

- **Name length**: 16 bytes (15 characters + 1-byte suffix)
    
- **Suffix** identifies service type (e.g., <20> = File Server)
    
|Suffix (Hex)|Meaning|
|---|---|
|00|Workstation Service|
|03|Messenger Service|
|20|File Server Service (SMB)|
|1B|Domain Master Browser|

> 📘 Tip: You can see suffixes using `nbtstat -A <IP>` or `nbtstat -n` in Windows.

---

## 🧪 Tools & Commands

### 🔹 Windows `nbtstat` Examples

```bash
nbtstat -n         # Show local NetBIOS names nbtstat -A 192.168.1.100  # Remote NetBIOS table by IP nbtstat -a HR-SERVER      # Remote NetBIOS table by name
```

### 🔹 Linux/Responder Enumeration

```bash
python3 Responder.py -I eth0
```

> Captures NetBIOS name requests and poisons them (e.g., responds to “Who has HR-SERVER?” with attacker's IP)

---
## 💡 NetBIOS vs DNS

| Feature         | NetBIOS                                           | DNS                           |
| --------------- | ------------------------------------------------- | ----------------------------- |
| Name Type       | 15-char NetBIOS names                             | FQDN (e.g., host.example.com) |
| Port            | UDP 137                                           | UDP/TCP 53                    |
| Discovery Style | Broadcast or WINS (Windows Internet Name Service) | Centralized or hierarchical   |
| Routable?       | ❌ Local LAN only                                  | ✅ Yes                         |

---

## 🔐 Security Implications

- **Broadcast-based name resolution is spoofable**
    
- **Responder, Metasploit, and NBNS Spoof** tools rely on this
    
- **NetBIOS over TCP/IP (NBT)** should be disabled unless required
    
- Modern systems prefer **DNS** + **SMB over TCP 445**
    

---

## ✅ Recommendations

|Action|Why|
|---|---|
|Disable NBT-NS if unused|Prevent spoofing attacks|
|Use DNS for all resolution|Modern and secure|
|Monitor UDP 137/138 traffic|Detect unexpected NetBIOS use|
|Use Responder in lab|Understand internal attack surface|