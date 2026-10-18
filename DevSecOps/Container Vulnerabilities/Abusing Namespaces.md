### How Can We Abuse Namespaces

This exploit takes advantage of situations where a container shares the same namespace as the host operating system, allowing the container to interact with processes on the host.

This scenario commonly occurs when a container requires access to host processes, such as for debugging purposes or when dependencies on host resources exist. As a result, when viewing processes within the container using `ps aux`, you'll observe the host's processes listed alongside those of the container.
### Example:

The command leveraging `nsenter` to execute processes within the same namespace as another process, along with the explanation of how the exploit works, can be combined as follows:

```bash
nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

This command utilizes `nsenter` to enter the namespaces of the init process (PID 1) on the host system. By leveraging the `--target` switch with the value "1", it gains access to the special system process ID's namespace, effectively inheriting its privileges.

Specifically:

- `--mount`, `--uts`, `--ipc`, and `--net` switches enter the mount, UTS, IPC, and network namespaces, respectively, of the target process (init process).
- This allows for interaction with various system resources, including filesystem mounts, hostnames, inter-process communication, and network-related features.
- By specifying `/bin/bash`, a bash shell is launched within this privileged namespace, providing access to system resources with root privileges.