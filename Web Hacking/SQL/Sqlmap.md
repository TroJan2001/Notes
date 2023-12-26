
sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.

### Sqlmap 

To view the sqlmap help menu, we use the following command:

```bash
sqlmap -h
```


**Basic** commands:

|**Options**|**Description**|
|---|---|
|-u URL, --url=URL|Target URL (e.g. "http://www.site.com/vuln.php?id=1")|
|--data=DATA|Data string to be sent through POST (e.g. "id=1")|
|--random-agent|Use randomly selected HTTP User-Agent header value|
|-p TESTPARAMETER|Testable parameter(s)|
|--level=LEVEL|Level of tests to perform (1-5, default 1)|
|--risk=RISK|Risk of tests to perform (1-3, default 1)|

### **Enumeration** commands:

These options can be used to enumerate the back-end database management system information, structure, and data contained in tables.

|Options|Description|
|---|---|
|-a, --all|Retrieve everything|
|-b, --banner|Retrieve DBMS banner|
|--current-user|Retrieve DBMS current user|
|--current-db|Retrieve DBMS current database|
|--passwords|Enumerate DBMS users password hashes|
|--dbs|Enumerate DBMS databases|
|--tables|Enumerate DBMS database tables|
|--columns|Enumerate DBMS database table columns|
|--schema|Enumerate DBMS schema|
|--dump|Dump DBMS database table entries|
|--dump-all|Dump all DBMS databases tables entries|
|--is-dba|Detect if the DBMS current user is DBA|
|-D DB_NAME|DBMS database to enumerate|
|-T TABLE_NAME|DBMS database table(s) to enumerate|
|-C COL|DBMS database table column(s) to enumerate|

### Operating System access commands

These options can be used to access the back-end database management system on the target operating system.

|Options|Description|
|---|---|
|--os-shell|Prompt for an interactive SQL shell|
|--sql-shell|Prompt for an OOB shell, Meterpreter or VNC|
|--os-pwn|Prompt for an OOB shell, Meterpreter or VNC|
|--os-cmd=OSCMD|Execute an operating system command|
|--priv-esc|Database process user privilege escalation|
|--os-smbrelay|One-click prompt for an OOB shell, Meterpreter or VNC|

Note that the tables shown above aren't all the possible switches to use with sqlmap. For a more extensive list of options, run `sqlmap -hh` to display the advanced help message.

**Simple HTTP GET Based Test**  
  
```bash
sqlmap -u https://testsite.com/page.php?id=7 --dbs
```

Here we have used two flags: -u to state the vulnerable URL and --dbs to enumerate the database.

**Simple HTTP POST Based Test**  

First, we need to identify the vulnerable POST request and save it. In order to save the request, Right Click on the request, select 'Copy to file', and save it to a directory as req.txt for example. You could also copy the whole request and save it to a text file as well.

Then we use the following command:

```bash
sqlmap -r req.txt
```

we can also add `-p` if we want to specify a specific vulnerable parameter.


