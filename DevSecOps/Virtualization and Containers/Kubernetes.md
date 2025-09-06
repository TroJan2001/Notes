**Kubernetes**, also shortened to "**K8s**," is one such solution known as an **orchestration platform**. An orchestration platform aims to integrate into other products, such as Docker, and extend their capabilities or "synchronize" them with other products or applications.

Kubernetes relies on these traditional virtualization models like hypervisors and containers and extends their uses, features, and capabilities.

These capabilities and features include the following:

- **Horizontal scaling**: Unlike traditional "vertical" scaling, "horizontal" scaling refers to adding devices or machines to handle increased workload, rather than adding logic resources such as CPU or RAM.
- **Extensibility**: Clusters can be modified dynamically without affecting containers outside of the intended group.
- **Self-healing**: K8s can automatically restart, replace, reschedule, and kill containers that are not properly functioning based on user-defined health checks.
- **Automated rollouts and rollbacks**: K8s can progressively roll out changes to containers. As changes are made, it will monitor the application's health and decide whether to continue the rollout or rollback. This ensures the constant uptime of your cluster even if some containers fail.
# Useful Commands

To start all clusters:

```bash
minikube start
```

To get the number pods are running on the provided cluster:

```bash
kubectl get pods
```

To get the deployments:

```bash
kubectl get deployments
```

To get the services:

```bash
kubectl get services
```

To get the replicas:

```bash
kubectl get rs
```

To delete a deployment:

```bash
kubectl delete deployment <deployment name>
```