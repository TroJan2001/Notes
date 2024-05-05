# Using SSH and docker context

Prerequisites: You must have SSH access to the remote device, and your user account on the remote device **must have permission to execute Docker commands**.

Instead of exposing docker daemon, we can use ssh to authenticate to our remote machine and then use docker commands on the remote machines as follows:

```bash
docker context create --docker host=ssh://myuser@remotehost --description="Development Environment" development-environment-host Successfully created context "development-environment-host"

# Then we simply use this command to switch to the context "profile" we created
docker context use development-environment-host
# we can simply use the folloing command to switch back to default mode
docker context use default
```

so like this we didn't expose our docker daemon, we need to authenticate using ssh to the server first, and we used docker context which we can think as profile, because we might also have docker on our machine so how it can know where to send docker commands, so when we create context we tell the docker to authenticate to ssh on this remote machine and then send docker commands to the docker commands after we authenticate.

**Note that this is a powerful way to secure docker, unless the used ssh password is weak.**
# TLS Encryption

This is the second way of securing the communication with docker remotely, and it requires some certificates for mutual authentication process, check "https://docs.docker.com/engine/security/protect-access/", docker will use port 2376 instead of 2375 for remote access over TLS.

Suppose we created those certificates for both client and server, we have to run the following commands

on server:

```bash
dockerd --tlsverify --tlscacert=myca.pem --tlscert=myserver-cert.pem --tlskey=myserver-key.pem -H=0.0.0.0:2376
```

on client:

```bash
docker --tlsverify --tlscacert=myca.pem --tlscert=client-cert.pem --tlskey=client-key.pem -H=SERVERIP:2376 info
```

Note: TLS its not completely secure, it has an attack vector if someone can verify his certificate .

Note: The following YouTube video "Docker Nuggets" has a very good explanation of docker remote access: https://www.youtube.com/watch?v=YX2BSioWyhI.