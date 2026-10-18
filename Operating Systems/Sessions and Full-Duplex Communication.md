### 🔹 What Is a Session?

A **session** is a logical, stateful connection between two endpoints (e.g., processes, sockets, systems), maintained over time to exchange data.

- In **networking**, sessions are established using protocols like TCP, where sequence numbers, ACKs, and window sizes track the state of the connection.
- In **IPC**, a session refers to an ongoing connection (e.g., a named pipe or socket) that allows continuous communication.

---
### 🔁 Bidirectional vs Full Duplex

| Term              | Meaning                                                    |
| ----------------- | ---------------------------------------------------------- |
| **Bidirectional** | Data can flow in both directions (e.g., send then receive) |
| **Full Duplex**   | Data can flow in **both directions simultaneously**        |
#### 💡 Example:
- **Walkie-talkie**: bidirectional but not full duplex (only one side talks at a time)
- **Phone call**: full duplex (both speak and hear at the same time)

---
### 🔧 How Full Duplex Works (TCP-level Example)

- TCP connections are inherently **full duplex**
- Two independent byte streams (A→B and B→A)
- Each stream tracks:
  - **SEQ number** (what you're sending)
  - **ACK number** (what you've received)

**OS-level socket buffers** handle simultaneous read/write.

---
### 🧪 TCP Full Duplex in Wireshark:

| Packet Direction | SEQ  | ACK  | Meaning |
|------------------|------|------|---------|
| Client → Server  | 1001 | 2001 | Send data |
| Server → Client  | 2001 | 1001 | Respond at the same time |

---
### 📦 IPC Mechanisms That Support Full Duplex

| IPC Type                 | Full Duplex?   | Notes                                          |
| ------------------------ | -------------- | ---------------------------------------------- |
| **TCP Socket**           | ✅ Yes          | Two-way communication, simultaneous            |
| **UNIX Domain Socket**   | ✅ Yes          | Local full-duplex stream socket                |
| **Named Pipe (Windows)** | ✅ Yes          | Duplex by design (if created that way)         |
| **Named Pipe (Unix)**    | ⚠️ Half-duplex | Traditionally one-way; duplex needs two FIFOs  |
| **Anonymous Pipe**       | ⚠️ Half-duplex | Unidirectional; full duplex requires two pipes |
| **Shared Memory**        | ✅ Yes          | Bidirectional but requires manual sync         |
| **Message Queue**        | ❌ No           | One-way by nature (send or receive per queue)  |

---

### 🌐 WebSockets and Application-Layer Full Duplex

WebSockets provide **full duplex communication at the application layer**, built on top of TCP:

- Starts as an HTTP request
- Then upgrades to WebSocket (via `Upgrade:` header)
- Enables **both client and server** to send/receive at any time

Useful for:
- Realtime web apps
- Chat systems
- Push notifications
- Multiplayer games

**Browser Example:**

```js
const ws = new WebSocket("wss://example.com/chat");
ws.onmessage = msg => console.log("Message:", msg.data);
ws.send("Hello from client!");
