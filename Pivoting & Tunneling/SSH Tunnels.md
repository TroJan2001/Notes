SSH port forwarding is a mechanism in SSH for tunneling application ports from the client machine to the server machine, or vice versa.
# Local Port Forwarding

![](../Attachments/Pasted%20image%2020250322162352.png)
![](../Attachments/Pasted%20image%2020250322164020.png)

Local port forwarding allows a client machine to forward a port to a server machine via SSH. The SSH client listens for incoming connections on a configured port and tunnels them to an SSH server, which then connects to a destination port, **potentially** on a different machine.

Organizations often route all incoming SSH traffic through a jump server, which is a hardened system or commercial solution. These jump servers allow authenticated incoming port forwarding, providing users transparent access to internal resources like web servers, mail servers, file servers, printers, and version control repositories.
### Example
In OpenSSH, local port forwarding is set using the `-L` option:

```bash
ssh -L 80:intra.example.com:80 gw.example.com
```

This forwards connections on port 80 of the local machine to port 80 on `intra.example.com` through `gw.example.com`. We can restrict this to local programs by specifying a bind address:

```bash
ssh -L 127.0.0.1:80:intra.example.com:80 gw.example.com
```

### Typical uses of local port forwarding include:
- Tunneling sessions and file transfers through jump servers.
- Accessing services on an internal network from outside.
- Connecting to remote file shares over the internet.
# Remote Port Forwarding

![](../Attachments/Pasted%20image%2020250322163931.png)
![](../Attachments/Pasted%20image%2020250322163936.png)

Remote port forwarding allows a remote server to forward a port to a client machine via SSH. The SSH server listens for incoming connections on a specified port and tunnels them back to the SSH client, which then connects to a destination port on its local machine or another system.

By default, OpenSSH restricts remote forwarded ports to connections from the server machine, but this can be configured using the `GatewayPorts` option in the `sshd_config` file. Organizations can choose to allow external access to forwarded ports or restrict access to specific IP addresses for greater security.

### Example:
Remote port forwarding in OpenSSH uses the `-R` option.

```bash
ssh -R 8080:localhost:80 public.example.com
```

This command allows anyone on the remote server to connect to port 8080, which is then tunneled back to the client. The client makes a TCP connection to port 80 on its local machine, but we can specify other hosts or IP addresses instead of `localhost`.

This feature is useful for exposing internal services, like an internal web server, to the public internet. It can be used by employees working remotely or, potentially, by attackers.

By default, OpenSSH restricts access to remote forwarded ports to the server host. However, the `GatewayPorts` option in the `sshd_config` file can control this:
- `GatewayPorts no`: Blocks access from outside the server.
- `GatewayPorts yes`: Allows access from anywhere on the internet.
- `GatewayPorts clientspecified`: Permits the client to specify an IP address for allowed connections.

```bash
ssh -R 52.194.1.73:8080:localhost:80 host147.aws.example.com
```

This restricts access to port 8080 to only the IP address `52.194.1.73`.

OpenSSH also supports using `0` as the forwarded port, which prompts the server to dynamically allocate a port and report it back to the client.

### Typical uses of remote port forwarding include:
- Exposing internal services like web servers to the public internet.
- Giving external access to internal resources, such as a database or file server.
- Allowing remote employees to access applications or services within a private network.
# Dynamic Port Forwarding

![](../Attachments/Pasted%20image%2020250322163820.png)

Dynamic port forwarding allows a client machine to create a SOCKS proxy through an SSH connection, enabling it to forward traffic to multiple destinations through the SSH server. Instead of forwarding a single port, the client sets up a dynamic tunnel where traffic from a local port is forwarded to the remote server, and the server decides the final destination.

Typical uses of dynamic port forwarding include:
- Routing all traffic through a secure SSH tunnel (SOCKS proxy).
- Accessing internal resources on a private network from a remote location.
- Bypassing geo-restrictions or firewalls by using the SSH server as a proxy.

### Example
To set up dynamic port forwarding in OpenSSH, use the `-D` option.

```bash
ssh -D 1080 user@host147.aws.example.com
```

This command creates a SOCKS proxy on port 1080 of the local machine, routing traffic through `host147.aws.example.com`.

We can configure our browser or other applications to use the SOCKS proxy (using proxychains for example) on port 1080 to securely route all traffic through the SSH server.

After we create the SSH tunnel with the `-D` option like in the previous command, we need to configure ProxyChains:

we can install ProxyChains if it's not already installed:

```bash
sudo apt-get install proxychains
```

We edit the ProxyChains configuration file to specify the SOCKS proxy:

```bash
sudo nano /etc/proxychains.conf
```

In the configuration file, we find the section that specifies proxy types and add the following line at the end:

```bash
socks5 127.0.0.1 1080
```

This tells ProxyChains to use the SOCKS proxy at `127.0.0.1` on port `1080`.

No we can use ProxyChains to route applications' traffic through the SOCKS proxy. For example, to route `curl` through the proxy:

```bash
proxychains curl http://example.com
```

This will make `curl` send all its traffic through the SOCKS proxy on port `1080`, which tunnels the requests securely through `host147.aws.example.com`.

Note that `curl` can also be used without ProxyChains. as it internally supports socks5.

```bash
curl --proxy socks5://127.0.0.1:1080 http://example.com
```

We can use ProxyChains with other applications like browsers, `wget`, and more to route their traffic through the SSH tunnel.
### Typical uses of dynamic port forwarding include:
- Routing all traffic through a secure SSH tunnel (SOCKS proxy).
- Accessing internal resources on a private network from a remote location.
- Bypassing geo-restrictions or firewalls by using the SSH server as a proxy.

For more on tunneling: chisel & logilo-ng.
https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel
https://notes.benheater.com/books/network-pivoting/page/pivoting-with-ligolo-ng
# Resources
https://ittavern.com/visual-guide-to-ssh-tunneling-and-port-forwarding/
https://www.youtube.com/watch?v=AtuAdk4MwWw