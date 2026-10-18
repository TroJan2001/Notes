
It is important to understand IPC because **processes cannot directly access each other’s memory**.  
The operating system provides mechanisms to allow processes to **exchange data, coordinate actions, and share resources**.

Two main categories:  

- **Shared Memory** (fastest, requires synchronization)  
- **Message Passing** (kernel-mediated, safer, includes pipes, message queues, sockets)  

Additional IPC forms: **signals, semaphores, memory-mapped files, and higher-level frameworks (COM, D-Bus).**

---

## 1. Shared Memory

Processes map the same region of RAM into their address space.  
- Very fast (no copying).  
- Needs synchronization (mutexes, semaphores).  

**Commands (Linux System V style):**
```bash
# Create 1 MB shared memory segment
ipcmk -M 1M
# List existing shared memory segments
ipcs -m
```

```c
# Program Example (C):
# Copy code
int shmid = shmget(IPC_PRIVATE, 1024, IPC_CREAT | 0666);
char *data = shmat(shmid, NULL, 0);
strcpy(data, "hello from process A");
```

**Full Duplex:** ✅ Yes  
**Bidirectional:** ✅ Yes (but must implement your own synchronization)
## 2. Signals (Unix/Linux)

Asynchronous notifications used for control, not data transfer.

**Example:**

```bash
# Send SIGUSR1 to process with PID 1234
kill -SIGUSR1 1234
```

Used for: terminate (`SIGKILL`), pause/resume (`SIGSTOP`, `SIGCONT`), reload configs

**Full Duplex:** ❌  
**Bidirectional:** ❌
## 3. Semaphores

Counters used to coordinate access to resources (especially shared memory).

**Commands:**

```bash
# Create a semaphore 
ipcmk -S 
# List semaphores 
ipcs -s`
```

```c
# Program Example (C):
sem_t sem; 
sem_init(&sem, 0, 1);   
// binary semaphore 
sem_wait(&sem);         // lock 
// critical section 
sem_post(&sem);         // unlock
```

**Full Duplex:** ❌  
**Bidirectional:** ❌
## 4. Memory-Mapped Files

Allows multiple processes to share data through a file mapped into memory.

```c
#Program Example:
int fd = open("sharedfile", O_RDWR | O_CREAT, 0666);
char *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); 
strcpy(addr, "shared via file mapping");`
```
Use case: databases, large logs, shared caches.

## 5. Pipes

### Unnamed Pipe

- Temporary, kernel-only.
    
- Between related processes (parent-child).

**Example:**

```bash
ls | grep ".txt"
```

The shell creates a pipe: `ls` writes → kernel buffer → `grep` reads.

**Full Duplex:** ❌  
**Bidirectional:** ⚠️ One-way only (half-duplex). Full duplex needs two pipes.
### Named Pipe (FIFO)

- Persistent special file (`p` type).
    
- Can be used by unrelated processes.
    

**Example:**

```bash
mkfifo /tmp/mypipe 
echo "hello" > /tmp/mypipe    # writer 
cat < /tmp/mypipe             # reader
```

- **On Unix:**
    
    > **Full Duplex:** ❌  
    > **Bidirectional:** ❌ (You need **two FIFOs** for full duplex)
    
- **On Windows:**
    
    > **Full Duplex:** ✅ Yes  
    > **Bidirectional:** ✅ Yes (if created with `PIPE_ACCESS_DUPLEX`)
---

## 6. Message Queues

Preserve **message boundaries** (one send = one receive).  
Support metadata (type, priority).

**Commands:**

```bash
# Create queue 
ipcmk -Q 
# List queues
ipcs -q 
# Remove queue
ipcrm -q <id>
```

```c
# Program Example (C):
msgsnd(qid, "hello", ...);
msgrcv(qid, buf, ...);
```

**Full Duplex:** ❌  
**Bidirectional:** ❌ (unless two queues are created)

---
## 7. Sockets

Endpoints for communication. Work locally (UNIX sockets) or across networks (TCP/UDP).

**Types:**

- Stream (SOCK_STREAM) → connection-oriented (like TCP).
    
- Datagram (SOCK_DGRAM) → connectionless (like UDP).
    
- Raw (SOCK_RAW) → direct packets (root only).
    
- UNIX domain → local only, path-based (`/tmp/socket`).
    

**Examples:**

```bash
# TCP socket 
nc -lvp 4444         # terminal 1 (server) 
nc 127.0.0.1 4444    # terminal 2 (client)  
# UNIX domain socket
socat UNIX-LISTEN:/tmp/mysock,fork STDOUT
socat UNIX-CONNECT:/tmp/mysock -
```

**Full Duplex:** ✅ Yes  
**Bidirectional:** ✅ Yes

---
## 8. Higher-Level IPC

### Windows

- **Mailslots** → one-way, broadcast messages.
    
- **COM/DCOM** → object-based IPC (DCOM supports remote calls).
    
- **Clipboard/DDE** → GUI data exchange.
    

### Unix/Linux

- **D-Bus** → message bus (used by NetworkManager, systemd).
    
- **TIPC** → cluster IPC, service discovery.