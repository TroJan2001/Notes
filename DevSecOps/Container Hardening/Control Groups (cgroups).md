cgroups enable the allocation or prioritization of resources for containers, preventing the possibility of faulty or malicious containers monopolizing system resources.

Example: Without implementing cgroups, a poorly designed container might consume excessive CPU or memory, leading to a scenario where critical system processes struggle to execute, ultimately causing system instability or failure.
# Useful Commands

| **Resource Type** | **Argument**                                                  | **Usage Example**                           |
| ----------------- | ------------------------------------------------------------- | ------------------------------------------- |
| CPU               | `--cpus` (in core count)                                      | `docker run -it --cpus="1" mycontainer`     |
| Memory            | `--memory` (in k, m, g for kilobytes, megabytes or gigabytes) | `docker run -it --memory="20m" mycontainer` |
we can also use `docker update` command to update the settings of a container `docker update --memory="40m" mycontainer`.