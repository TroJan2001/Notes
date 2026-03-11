Kubernetes, also known as K8s, is an open-source system for automating deployment, scaling, and management of containerized applications.
# Kubernetes Architecture 

![](../Attachments/Pasted%20image%2020240416074205.png)
# kubectl

The Kubernetes command-line tool, [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/), allows you to run commands against Kubernetes clusters.
### Useful Commands

To apply our deployment and service configurations that we have in our YAML configuration files, we can use the following command:

```bash
kubectl apply -f example-deployment.yaml
```

 To check the status of resources, we use the following command:
 
```bash
kubectl get pods -n example-namespace
```

The following command can be used to show the details of a resource (or a group of resources):

```bash
kubectl describe pod example-pod -n example-namespace
```

To view the application logs of the erroring pod, we use the following command:

```bash
kubectl logs example-pod -n example-namespace
```

To get inside a container we can use the following command:

```bash
kubectl exec -it example-pod -n example-namespace -- sh
# Note that we can add -c or --container to specify the container inside the pod if there are multiple containers
```

To create a secure tunnel between our local machine and a running pod in our cluster:

```bash
kubectl port-forward service/example-service 8090:8080
```