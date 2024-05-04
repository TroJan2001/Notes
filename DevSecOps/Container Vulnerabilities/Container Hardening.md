

# Using SSH and docker context

Instead of exposing docker daemon, we can use ssh to authenticate to our remote machine and then use docker commands on the remote machines as follows:

```bash
docker context create --docker host=ssh://myuser@remotehost --description="Development Environment" development-environment-host Successfully created context "development-environment-host"

# Then we simply use this command to switch to the context "profile" we created
docker context use development-environment-host
# we can simply use the folloing command to switch back to default mode
docker context use default
```

so like this we didn't expose our docker daemon, we need to authenticate using ssh to the server first, and we used docker context which we can think as profile, because we might also have docker on our machine so how it can know where to send docker commands, so when we create context we tell the docker to authenticate to ssh on this remote machine and then send docker commands to the docker commands after we authenticate.

