One of the first things you should always check when looking for privesc openings is what sudo permissions the user has available to them. This could be simply done by using the `sudo -l` command.
### Misconfigured Binaries and GTFOBins  

If you find a misconfigured binary during your enumeration, or when you check what binaries a user account you have access to can access, a good place to look up how to exploit them is GTFOBins. GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. It provides a really useful breakdown of how to exploit a misconfigured binary and is the first place you should look if you find one on a CTF or Pentest.
# Exploiting Vi Editor

First, we start with `sudo -l` command to list all commands we can run as root from the current user.

Then, lets suppose we get this output: `User test may run the following commands on polobox:(root) NOPASSWD: /usr/bin/vi`

so we know that test user can run vi as root without password, and all what we have to do next, type `:!sh` to get a root bash inside the vi editor.
`