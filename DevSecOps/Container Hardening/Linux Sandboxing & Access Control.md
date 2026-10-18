## 1️⃣ Access Control Models

### **1.1 Discretionary Access Control (DAC)**

- **Who sets rules:** Resource owner (user)
    
- **Who enforces rules:** Kernel (system), following user-defined permissions
    
- **Root/admin power:** Root can override all rules
    
- **Example:**
    
    `-rw-r--r--  alice file.txt`
    
    - Owner `alice` allows read/write for herself, read for others
        
    - Kernel enforces these permissions
        
- **Notes:** Flexible but risky; a compromised user can abuse their permissions.
    
---

### **1.2 Mandatory Access Control (MAC)**

- **Who sets rules:** Admin/root defines policies
    
- **Who enforces rules:** Kernel/system **mandatory enforcement**
    
- **Root/admin power:** Can define/change policies, but cannot bypass them at runtime unless the policy is disabled
    
- **Examples:**
    
    - **SELinux:** Labels every object; policies specify which domains can access which files
        
    - **AppArmor:** Uses filesystem paths to allow/deny access
        
- **Key difference from DAC:** Rules are **mandatory**, not discretionary. Even root is temporarily blocked from disallowed actions.
    

**SELinux example:**

- Policy: `httpd_t cannot read shadow_t`
    
- Web server running as root tries to read `/etc/shadow` → blocked by kernel
    

**AppArmor example:**

- Policy allows `/var/www/html/index.html` but denies `/var/www/html/secret.html`
    

**Strengths:** Reduces accidental privilege escalation, process containment.

**Limitation:** Root can **eventually bypass by editing policies or disabling enforcement**, unless combined with external enforcement (hypervisor, TPM).

---

### **1.3 Role-Based & Attribute-Based Access Control (RBAC / ABAC)**

- **Who sets rules:** Admin
    
- **Who enforces rules:** System/kernel
    
- **Example RBAC:** Database roles
    
    - `DBAdmin` → full access
        
    - `Developer` → read-only
        
- **Example ABAC:**
    
    - Finance employees can access `/finance-reports` **only from office network**
        

**Takeaway:** Admin defines roles/attributes, system enforces access.

---

### **1.4 Lattice-Based Access Control (LBAC)**

- **Who sets rules:** Admin defines security levels (Confidential < Secret < Top Secret)
    
- **Who enforces rules:** Kernel/system
    
- **Example:** A Secret clearance user cannot read Top Secret files
    

---

### **1.5 Summary Table: Who Defines & Who Enforces**

|Model|Who Defines Rules|Who Enforces Rules|Root/Admin Ability|
|---|---|---|---|
|DAC|Resource owner|Kernel follows user rules|Full override|
|MAC|Admin/root|Kernel mandatory enforcement|Can change policy, cannot bypass enforcement without modification|
|RBAC/ABAC|Admin|System/kernel|Defines roles/attributes|
|LBAC|Admin|System/kernel|Defines security levels|

---

## 2️⃣ seccomp — Syscall Filtering Sandbox

- **Definition:** Linux feature allowing userspace programs to define filters on allowed system calls
    
- **Scope:** Process-level syscall restriction
    
- **Who sets rules:** Admin or program itself
    
- **Who enforces rules:** Kernel enforces **per-process filters**
    

**Key points (source: [StackExchange](https://security.stackexchange.com/questions/196881/docker-when-to-use-apparmor-vs-seccomp-vs-cap-drop?ref=conradk.com)):**

> “Seccomp is a Linux feature that allows a userspace program to set up syscall filters. These filters specify which system calls are permitted, and what arguments they are permitted to have. It is a very low-level filter that reduces the attack surface area of the kernel. For example, a bug in `keyctl()` that allows simple calls to that syscall to elevate privileges would not necessarily be usable for privesc in a program which has restricted access to that call. Writing a good seccomp policy is more involved than using Docker. You must modify the source code of the program to get the most out of seccomp, otherwise the most you can do is restrict the obviously unsafe syscalls.”

- **Example:** Docker uses default seccomp profiles to block dangerous syscalls like `mount` or `ptrace`.
    
- **Limitation:** No file/path awareness; must modify program to create effective filters.

---

## 3️⃣ AppArmor — MAC with Path-Based Policies

- **Definition:** LSM (Linux Security Module) framework for Mandatory Access Control
    
- **Scope:** Files, paths, capabilities, network access
    
- **Who sets rules:** Admin/root
    
- **Who enforces rules:** Kernel
    
- **Example:**
    
    - Allow `/etc/passwd`, deny `/etc/shadow`
        
    - Limit network access or capabilities of a process
        
- **Strengths:** Simpler than SELinux, easier to write for paths, good for process confinement
    
- **Limitation:** Less fine-grained than SELinux; cannot distinguish files by labels or context
    

---

## 4️⃣ Capabilities — Fine-Grained Privilege Control

- **Definition:** Mechanism to split root privileges into discrete units; processes can **drop capabilities**
    
- **Example capabilities:** `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`
    
- **Who sets rules:** Process itself can drop its capabilities; admin/root can define which capabilities to assign
    
- **Who enforces rules:** Kernel
    
- **Use case:** Reduce damage if a privileged process is compromised
    
- **Limitation:** Limited number of capabilities; some are still effectively root-equivalent
    

**Reference (StackExchange):**

> “Capabilities and capability dropping is a general technique whereby a privileged process revokes a subset of the privileges it is endowed with. A root process can drop, for example, the capabilities required to create raw connections to the network, or the capabilities required to bypass standard UNIX file permissions (DAC), even though it remains root. This technique is not very fine-grained as there are only a limited number of capabilities that can be dropped, but it reduces the damage a program can do if it has been compromised nonetheless. Furthermore, some capabilities are root-equivalent in certain situations, meaning that they can be used to regain full root privileges.”

---

## 5️⃣ Comparison Table: seccomp vs AppArmor vs Capabilities

|Feature|Scope|Granularity|Enforcement|Root Bypass Potential|
|---|---|---|---|---|
|seccomp|Syscalls per process|Low-level, syscall-based|Kernel|Cannot bypass while filter is active; must restart/change process|
|AppArmor|Files, paths, process network/capabilities|Medium, path-based|Kernel/MAC|Root can edit policy, disable enforcement|
|Capabilities|Privileges of process|Coarse-grained|Kernel|Root can regain privileges; limited fine-grained control|

---

## 6️⃣ Takeaways

1. **Root vs System Enforcement**
    
    - In DAC: root can do anything
        
    - In MAC/AppArmor/SELinux: root can define policy but kernel enforces it
        
    - External enforcement (TPM, hypervisor) required to **fully restrict root**
        
2. **Defense-in-depth:** Combine multiple layers
    
    - DAC for classic Unix permissions
        
    - MAC (SELinux/AppArmor) for mandatory enforcement
        
    - seccomp to reduce syscall attack surface
        
    - Capabilities to reduce root-equivalent privileges in a process
        
3. **Use case summary**
    
    - **Docker:** Uses AppArmor + seccomp + capabilities for container isolation
        
    - **SELinux:** More granular, enterprise-level confinement
        
    - **AppArmor:** Easier path-based confinement
        
    - **seccomp:** Very fine syscall filtering, minimal overhead
        
    - **Capabilities:** Reduce damage if privileged process is compromised
        

---

### **References**

- [StackExchange: Docker — When to use AppArmor vs seccomp vs cap-drop](https://security.stackexchange.com/questions/196881/docker-when-to-use-apparmor-vs-seccomp-vs-cap-drop?ref=conradk.com)
- [Conradk.com — Process Security in Linux](https://www.conradk.com/process-security-linux/)