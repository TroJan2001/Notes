---
title: "RPC"
created: 2026-03-11
type: concept
tags: [concept, network, protocols, windows]
---

# 🔹 RPC (Remote Procedure Call)

RPC = a mechanism that allows a program on one computer to execute a procedure (function) on another computer **as if it were local**.

- **Goal:** Hide the complexity of networking. A function call like `result = doSomething(x, y)` could transparently run across the network.
    
- **How:** Parameters are serialized (marshalled), sent over a transport, executed remotely, and results are returned.
    

---

## 🔹 General Concept

- **Client stub** marshals parameters into a message.
    
- **Transport** delivers the message (TCP, SMB pipe, HTTP, etc.).
    
- **Server stub** unmarshals, calls the real function, returns results.
    
- **Looks local, but is remote.**
    

---

## 🔹 RPC Transports (Common Flavors)

### 1. **SunRPC (ONC RPC)**

- Origin: Sun Microsystems (1980s).
    
- Transport: UDP/TCP, dynamic ports via `rpcbind` (port 111).
    
- Uses: NFS, mountd, lockd, ypbind.
    
- Weak security (no encryption).
    

### 2. **MSRPC (Microsoft RPC)**

- Microsoft’s implementation of **DCE/RPC**.
    
- Transports:
    
    - **TCP/135 + dynamic high ports** (`ncacn_ip_tcp`).
        
    - **SMB Named Pipes** (`ncacn_np`) like `\\HOST\IPC$\pipe\samr`.
        
    - **HTTP(S)** (`ncacn_http`), e.g. Outlook/Exchange.
        
- Uses: Core Windows services (SAMR, LSA, Netlogon, Spooler, WMI, AD replication).
    
- Auth: NTLM or Kerberos.
    

### 3. **gRPC**

- Modern (Google, 2015).
    
- Transport: HTTP/2.
    
- Serialization: Protobuf.
    
- Uses: Cloud microservices, APIs.
    
- Security: TLS + mTLS.
    

### 4. **Others**

- **Java RMI** (port 1099, dynamic).
    
- **CORBA** (older OO-RPC).
    
- **JSON-RPC / XML-RPC** (simple HTTP-based RPCs).
    

---

## 🔹 MSRPC Endpoints

- **Endpoint = concrete network address where an RPC service listens.**
    
- Can be:
    
    - A **TCP port** (e.g. 49158/tcp).
        
    - A **Named Pipe** (e.g. `\\HOST\IPC$\pipe\samr`).
        
    - An **HTTP path** (e.g. `/rpc/rpcproxy.dll`).
        
- Services register their **UUID** (unique identifier) + endpoint with the **Endpoint Mapper (EPM)** on **port 135**.
    

### Example (SAMR)

```
UUID: 12345778-1234-abcd-ef00-0123456789ac
Bindings:
- ncacn_np: \\pipe\samr
- ncacn_ip_tcp:49158
```

👉 Client asks EPM: _“Where is SAMR?”_ → gets endpoint info → connects via chosen transport.

---

## 🔹 Stack Examples

### RPC over TCP

```
TCP/135 → Endpoint Mapper → High port (e.g. 49158/tcp) → MSRPC → Service
```

### RPC over SMB (Named Pipes)

```
TCP/445 → SMB → IPC$ → \\pipe\samr → MSRPC → Service
```

### RPC over HTTP

```
TCP/443 → HTTP/2 → MSRPC → Service
```

---
## 🔹 Security / Pentest Relevance

- **Endpoint enumeration**: Use EPM to list RPC endpoints (UUIDs, transports).
    
- **Null sessions (legacy)**: Historically, IPC$ allowed anonymous access → enumeration.
    
- **Abuse**: Many AD attacks (SAMR user enum, LSA secrets, Netlogon vulns, Spooler relay) rely on RPC over SMB pipes.
    
- **Firewalling**: Blocking high TCP ports often forces clients to use RPC over SMB instead.
    

---
