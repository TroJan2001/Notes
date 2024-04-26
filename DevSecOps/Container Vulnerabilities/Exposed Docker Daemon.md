
We have 2 types of Docker Daemon:

1- Unix Socket Docker Daemon: which means there is a daemon running locally that can be exploited if we have enough permissions (sudo, docker group).

For example we can mount the host file system using the following command:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

2- The Docker Engine - TCP Sockets Edition: The Docker Engine will listen on a port when configured to be run remotely

By default, the engine will run on port 2375, which could be used to start containers, delete containers ... etc (RCE).