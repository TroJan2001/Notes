
John the Ripper is one of the most well known, well-loved and versatile hash cracking tools out there. It combines a fast cracking speed, with an extraordinary range of compatible hash types. This room will assume no previous knowledge, so we must first cover some basic terms and concepts before we move into practical hash cracking.

# Useful Commands

### Basic Commands

The basic syntax of John the Ripper commands is as follows. We will cover the specific options and modifiers used as we use them.  

```bash
john [options] [path to file]
```

An example of basic command is as follows:

```bash
	john --wordlist=[path to wordlist] [path to file]
```

To determine the type of the hash we want to crack, we can use the `hashid` command like so:

```bash
hashid hash.txt
```

Now we know our most likely type of hashing algorithm used, so we can specify the hashing crack algorithm like so:

```bash
john --format=[format] --wordlist=[path to wordlist] [path to file]
```

**A very important note on Formats:**

When you are telling john to use formats, if you're dealing with a standard hash type, e.g. md5 as in the example above, you have to prefix it with`raw-` to tell john you're just dealing with a standard hash type, though this doesn't always apply. To check if you need to add the prefix or not, you can list all of John's formats using `john --list=formats` and either check manually, or grep for your hash type using something like `john --list=formats | grep -iF "md5"`.