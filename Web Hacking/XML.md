
Before we move on to learn about XXE exploitation we'll have to understand XML properly.  

**What is XML?**  
  
XML (eXtensible Markup Language) is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. It is a markup language used for storing and transporting data.  
  
**Why we use XML?**  
  
1. XML is platform-independent and programming language independent, thus it can be used on any system and supports the technology change when that happens.  
  
2. The data stored and transported using XML can be changed at any point in time without affecting the data presentation.  
  
3. XML allows validation using DTD and Schema. This validation ensures that the XML document is free from any syntax error.  
  
4. XML simplifies data sharing between various systems because of its platform-independent nature. XML data doesn’t require any conversion when transferred between different systems.  
  
**Syntax**  
  
Every XML document mostly starts with what is known as XML Prolog.  
  
`<?xml version="1.0" encoding="UTF-8"?>`

**Note:** ssh private key is located in home/`<username>`/.ssh/id_rsa

Every XML document must contain a `ROOT` element. For example:  

`<?xml version="1.0" encoding="UTF-8"?>   <mail>      <to>falcon</to>      <from>feast</from>      <subject>About XXE</subject>      <text>Teach about XXE</text>   </mail>`

In the above example the `<mail>` is the ROOT element of that document and `<to>`, `<from>`, `<subject>`, `<text>` are the children elements. If the XML document doesn't have any root element then it would be considered`wrong` or `invalid` XML doc.  
  
Another thing to remember is that XML is a case sensitive language. If a tag starts like `<to>` then it has to end by `</to>` and not by something like `</To>`(notice the capitalization of `T`)  
  
Like HTML we can use attributes in XML too. The syntax for having attributes is also very similar to HTML. For example:  
`<text category = "message">You need to learn about XXE</text>   `

In the above example `category` is the attribute name and `message` is the attribute value.

An XML External Entity (XXE) attack is a vulnerability that abuses features of XML parsers/data. 
It often allows an attacker to interact with any backend or external systems that the application itself can access and can allow the attacker to read the file on that system. 
They can also cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications. 
XXE may even enable port scanning and lead to remote code execution.


There are two types of XXE attacks: in-band and out-of-band (OOB-XXE).  
1) An in-band XXE attack is the one in which the attacker can receive an immediate response to the XXE payload.

2) out-of-band XXE attacks (also called blind XXE), there is no immediate response from the web application and attacker has to reflect the output of their XXE payload to some other file or their own server.
# XXE payload Examples:

```xml
<!DOCTYPE replace [<!ENTITY name "feast"> ]>  
 <userInfo>  
  <firstName>falcon</firstName>  
  <lastName>&name;</lastName>  
 </userInfo>
```

```xml
<?xml version="1.0"?>  
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>  
<root>&read;</root>
```
