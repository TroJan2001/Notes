
Docker is a container platform and engine that is used to run Docker "images" as containers.

Each Docker image is built of a base image, such as Alpine or Ubuntu, that is specifically built for use in containers and is lightweight. To build a Docker image, a Dockerfile must be created, which defines the base image for a container and any commands to be run.

# Useful Commands

Using Docker Hub, we can pull Docker images created by others or push our own.

```bash
docker pull <user>/<image>
```

Alternatively, a container image can be automatically pulled when running the container for the first time. Once a container is pulled for the first time, it will be cached locally, and Docker will look for it locally before attempting to download it.

```bash
docker run <user>/<image>
```

Once the image is started, we can verify that the Docker engine is running the container by listing the processes running in Docker using the below command, `you may notice that the container will be assigned a random identifier, IP address, and network interface`.

```bash
docker ps
```

Example: to start the example Flask app in a Docker container, exposing the webserver to port 5000:

```bash
docker run -p 5000:5000 -d cryillic/thm_example_app 
```

- `-p 5000:5000`: This flag is used to map ports between the host system and the container. In this case, it maps port 5000 on the host to port 5000 in the container. This means that any traffic sent to port 5000 on the host will be forwarded to port 5000 inside the container. This is commonly used when you want to expose network services running in the container to the host or external network.
- `-d`: This flag stands for "detached" mode. When you run a container in detached mode, it means the container runs in the background, and the terminal prompt becomes available for other commands without being attached to the container's standard input/output. This is useful for running containers as services or background processes.
-  `cryillic/thm_example_app`: This is the name of the Docker image from which you are creating the container. Docker images are essentially templates for containers, containing all the necessary files and configurations to run a specific application or service.