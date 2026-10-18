Containers have a lot in common with virtual machines, but instead of being completely abstracted from the host operating system, containers share some properties with the host operating system. Containers have their own filesystem, a portion of computing resources (CPU, RAM), a process space, and more.   

Apart from the obvious benefits of being lightweight, containers are also _portable_ and _robust_ because they are not completely abstracted.   

Container engines are our second type of virtualization. As virtual machines use a hypervisor to create an abstraction layer for virtualization, containers use a container engine to create an abstraction layer using logical resources.