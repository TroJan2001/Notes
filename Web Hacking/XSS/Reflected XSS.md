
Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.

![](../../Attachments/Pasted%20image%2020231105005810.png)

**How to test for Reflected XSS:**  

You'll need to test every possible point of entry; these include:

- Parameters in the URL Query String
- URL File Path
- Sometimes HTTP Headers (although unlikely exploitable in practice)  

Once you've found some data which is being reflected in the web application, you'll then need to confirm that you can successfully run your JavaScript payload; your payload will be dependent on where in the application your code is reflected.