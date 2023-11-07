
Hypervisors are separated into two categories that are determined by their position relative to the hardware. They can either directly create a lightweight operating system on top of the hardware that is the hypervisor or add a hypervisor as an application on top of a pre-existing operating system.


### Type 1 Hypervisors

**Type 1 hypervisors**, also known as **bare metal hypervisors**, create an abstraction layer directly between hardware and virtual machines without a common operating system between them. Instead, the hypervisor is the operating system and is often _headless_, with only a web-based management portal remotely accessed. These hypervisors are designed for scale and to deploy a large number of virtual machines at once. They are extremely lightweight to dedicate the most resources to virtual machines.

Examples of type 1 hypervisors include VMware ESXi, Proxmox, VMware vSphere, Xen, and KVM.

### Type 2 Hypervisors

**Type 2 hypervisors**, also known as **hosted hypervisors**, create an abstraction layer from a software application built on top of a pre-existing operating system. Unlike type 1 hypervisors, type 2 hypervisors are often managed directly from the application through a GUI. These hypervisors are often designed for end-users or individuals such as developers and are not strictly designed to run a large number of virtual machines for scale.

Examples of type 2 hypervisors include VMware Workstation, VMware Fusion, VirtualBox, Parallels, and QEMU.