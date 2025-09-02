It is important to understand IPC because **processes cannot directly access each other’s memory**. The operating system provides mechanisms to allow processes to **exchange data, coordinate actions, and share resources**.

Primarily, we are concerned with two broad approaches:

- **Shared Memory** (fastest, but requires synchronization)
    
- **Message Passing** (kernel-mediated, safer, includes pipes, message queues and sockets)

---

# Shared Memory

Shared memory allows two or more processes to map the same portion of **RAM** into their address space. Once mapped, they can read/write directly without system calls.

**Useful Commands (Linux System V style):**

`# Create a new shared memory segment
```bash
ipcmk -M 1M  
# List all shared memory segments
ipcs -m
# Attach/detach shared memory (programmatically: shmat/shmdt)`
```  

|**Tag**|**Function**|
|---|---|
|`ipcmk -M`|Create shared memory|
|`ipcs -m`|Show current shared memory|
|`shmget/shmat`|System calls for creating and attaching segments|

**Note:** Synchronization must be done separately using semaphores/mutexes; otherwise, race conditions occur.

---

# Message Passing

Processes exchange data via **kernel buffers**. Data is copied: sender → kernel → receiver. Safer than shared memory but slower.

**Forms of message passing:**

- **Pipes (stream of bytes)**
    
- **Message Queues (discrete structured messages)**
    
- **Sockets (local/network)**
    

---

# Pipes

### Unnamed Pipe

- Created with `pipe(fd)` inside a program.
    
- Exists only in **kernel memory**.
    
- Works between **related processes** (parent-child).
    
- Example:
    

```bash
ls | grep ".txt"
```

The shell creates an **unnamed pipe** to connect `ls` output to `grep` input.

### Named Pipe (FIFO)

- Created with `mkfifo` or `mknod`.
    
- Appears in filesystem as special file (type `p`).
    
- Used by **any processes** (even unrelated).
    
- Example:
    

```bash
mkfifo /tmp/mypipe
echo "hello" > /tmp/mypipe   # writer
cat < /tmp/mypipe            # reader
```

|**Tag**|**Function**|
|---|---|
|`mkfifo`|Create a named pipe|
|`ls -l`|See type `p` for FIFO|
|`read/write`|Consume/produce bytes|

**Note:** Data is consumed once read. Unlike files, you cannot re-read old content.

---

# Message Queues

Unlike pipes, message queues preserve **message boundaries**. Each send = one receive. Metadata (type/priority) is supported.

**Useful Commands:**

```bash
# Create a message queue
ipcmk -Q

# List message queues
ipcs -q

# Remove a queue
ipcrm -q <id>
```

| **Tag**         | **Function**                          |
| --------------- | ------------------------------------- |
| `ipcmk -Q`      | Create a queue                        |
| `ipcs -q`       | List queues                           |
| `msgsnd/msgrcv` | System calls to send/receive messages |

**Note:** Queues persist in the kernel until explicitly removed (`ipcrm`). They support multiple producers and consumers.

---

# Sockets

Sockets are **endpoints for communication**. Unlike pipes and queues, they allow processes to communicate **locally or over a network**.

**Types of sockets:**
- **Stream (SOCK_STREAM)** → connection-oriented, reliable (TCP).
- **Datagram (SOCK_DGRAM)** → connectionless, fast but unreliable (UDP).
- **Raw (SOCK_RAW)** → direct packet access (requires root).
- **UNIX Domain** → local-only, use filesystem pathnames (e.g., `/tmp/socket`).

**Useful Commands:**
```bash
# Start a TCP listener on port 4444
nc -lvp 4444

# Connect to it
nc <IP> 4444

# UNIX domain socket example
socat UNIX-LISTEN:/tmp/mysock,fork STDOUT
socat UNIX-CONNECT:/tmp/mysock -
```

|**Tag**|**Function**|
|---|---|
|`socket()`|Create a socket|
|`bind()`|Assign address/port|
|`listen()`|Wait for incoming connections|
|`accept()`|Accept a connection|
|`connect()`|Connect to another socket|
# File vs Pipe

| Feature  | **File**                | **Unnamed Pipe**       | **Named Pipe (FIFO)**   |
| -------- | ----------------------- | ---------------------- | ----------------------- |
| Storage  | Disk (persistent)       | RAM (temporary)        | RAM (temporary)         |
| Data     | Persistent, re-readable | Consumed after read    | Consumed after read     |
| Access   | Random access (`lseek`) | Sequential only        | Sequential only         |
| Relation | Any process, any time   | Related (parent-child) | Any process, concurrent |
| Lifetime | Until deleted           | Until both ends closed | Until removed           |

---

# File Descriptors (FDs)

Every open file, pipe, or socket is accessed via a **file descriptor** (an integer).

- Standard FDs:
    
    - `0` = stdin
        
    - `1` = stdout
        
    - `2` = stderr
        

**Pipe Example in Shell:**

- `pipe(fd)` creates `fd[0]` (read) and `fd[1]` (write).
    
- Shell uses `dup2()` so one process’s stdout becomes the pipe write end, and another process’s stdin becomes the pipe read end.

**Analogy:** Like a **ticket number** — you don’t hold the file/pipe itself, only a reference number that OS resolves.

---
