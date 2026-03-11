# 🔹 What is NFS?

- **NFS = Network File System**
    
- Developed by **Sun Microsystems** in the 1980s.
    
- Goal: Let a client computer mount a remote directory and use it as if it were part of the local filesystem.
    

👉 In simple terms: NFS makes **remote files look like local files**.

---

# 🔹 How NFS Works

1. **Server exports a directory**
    
    - Defined in `/etc/exports` (Linux/Unix).
        
    - Example: `/srv/share 192.168.1.0/24(rw,sync,no_root_squash)`
        
2. **Client mounts the export**
    
    - Example:
        
        `mount -t nfs server:/srv/share /mnt/share`
        
    - After this, `/mnt/share` on the client behaves like a local folder, but all data is actually on the server.
        
3. **File operations**
    
    - Client’s open/read/write syscalls are sent as **RPC requests** to the server.
        
    - The server processes them and responds back.
        

---

# 🔹 Protocols Behind NFS

NFS is built on **SunRPC (ONC RPC)**:

- **rpcbind/portmapper (TCP/UDP 111)**
    
    - First, the client asks the portmapper: “Which port is NFS running on?”
        
- **NFS service** itself (usually TCP/2049 now, but can be dynamic in older versions).
    
- Additional daemons:
    
    - `mountd` (handles mount requests)
        
    - `nlockmgr` (file locking)
        
    - `statd` (status monitoring, crash recovery)
        

---

# 🔹 NFS Versions

|Version|Year|Key Features|
|---|---|---|
|NFSv2|1989|Basic functionality, UDP only|
|NFSv3|1995|64-bit file sizes, TCP support, async writes|
|NFSv4|2000|Statefulness, ACLs, Kerberos security, firewall-friendly (single port 2049)|
|NFSv4.1+|2010|Parallel NFS, better performance|

---

# 🔹 NFS vs SMB (Windows File Sharing)

|Feature|NFS|SMB|
|---|---|---|
|Origin|Unix / Sun Microsystems|Microsoft / IBM (LAN Manager)|
|Default Port|2049/tcp (via RPC)|445/tcp (direct) or 139/tcp (NetBIOS)|
|Authentication|Traditionally host-based; NFSv4 uses Kerberos|NTLM / Kerberos (AD integrated)|
|Use Case|Unix/Linux server shares, HPC clusters|Windows domains, file/print sharing|
|Transport|SunRPC (rpcbind, mountd, etc.)|Direct TCP, SMB protocol|

---

# 🔹 Example Recon Output

If you scan a Unix/Linux box:

```bash
nmap -sV -p111,2049 192.168.1.50
```

You might see:

```bash
111/tcp open  rpcbind 2049/tcp open  nfs_acl
```

Then with `showmount`:

`showmount -e 192.168.1.50`

Output:

`Export list for 192.168.1.50: /srv/share 192.168.1.0/24`

That means `/srv/share` is available to the whole subnet.

---

✅ In short:

- **NFS = the Unix/Linux “SMB equivalent.”**
    
- Both provide remote file access.
    
- NFS is SunRPC-based, SMB is Microsoft/NetBIOS/TCP-based.
    
- In Windows, SMB is dominant; in Linux/Unix/HPC, NFS is.