Running containers in "privileged” mode is a big problem, since this will assign all the capabilities to the container which allows an attacker to get full control over the host if he could compromise the container "easy to escape".

![](../../Attachments/Pasted%20image%2020240509004540.png)

# Capabilities
According to Hacktricks, Linux capabilities divide **root privileges into smaller, distinct units**, allowing processes to have a subset of privileges. This minimizes the risks by not granting full root privileges unnecessarily.

Briefly, instead of giving a full access for a container over the host to do a small task only give it the required privileges. Also, if we don't use capabilities then nothing would be flexible! and the privileges would be like 0 or 1, either give full root privileges or don't give any at all!

The following capabilities examples taken from "Container Hardening" on TryHackMe show some capabilities we use and their use cases:

![](../../Attachments/Pasted%20image%2020240509010126.png)

Note: Process capabilities refer to the permissions held by a running process, while file capabilities determine the privileges granted when the file is executed.
### Useful Commands

To display the capabilities on the processes indicated by the pid value(s) given on the command line, we can use the following command:

```bash
getpcaps <PID>
```

To display the capabilities granted when the file is executed, we can use the following command:

```bash
getcap filename
```

To display the capabilities of the current process, we can use the following command:

```bash
capsh --print
```

To assign the `NET_BIND_SERVICE` capability to a container running a web server on port 80 (or any port under 1024) we need to include the `--cap-add=NET_BIND_SERVICE` when running the container:

```bash
docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE -p 80:80 mywebserver
```

A very good resources: https://tbhaxor.com/understanding-linux-capabilities/#type-of-capabilities.

https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work