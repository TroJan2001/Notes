
**Level One:**

You're presented with a form asking you to enter your name, and once you've entered your name, it will be presented on a line below, for example:

![](../../Attachments/Pasted%20image%2020231105005831.png)

```js
<script>alert('THM');</script>
```

**Level Two:**

Like the previous level, you're being asked again to enter your name. This time when clicking enter, your name is being reflected in an input tag instead:

![](../../Attachments/Pasted%20image%2020231105005837.png)

```js
"><script>alert('THM');</script>
```

The important part of the payload is the `">` which closes the value parameter and then closes the input tag.

**Level Three:**

You're presented with another form asking for your name, and the same as the previous level, your name gets reflected inside an HTML tag, this time the textarea tag.

![](../../Attachments/Pasted%20image%2020231105005848.png)

```js
</textarea><script>alert('THM');</script>
```

The important part of the above payload is `</textarea>`, which causes the textarea element to close so the script will run.  

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful with a link to the next level.

**Level Four:**

Entering your name into the form, you'll see it reflected on the page. This level looks similar to level one, but upon inspecting the page source, you'll see your name gets reflected in some JavaScript code.

![](../../Attachments/Pasted%20image%2020231105005900.png)

You'll have to escape the existing JavaScript command, so you're able to run your code; you can do this with the following payload `';alert('THM');//`  which you'll see from the below screenshot will execute your code. The `'` closes the field specifying the name, then `;` signifies the end of the current command, and the `//`
at the end makes anything after it a comment rather than executable code.

**Level Five:**

Now, this level looks the same as level one, and your name also gets reflected in the same place. But if you try the `<script>alert('THM');</script>` payload, it won't work. When you view the page source, you'll see why.

![](../../Attachments/Pasted%20image%2020231105005908.png)

The word `script`  gets removed from your payload, that's because there is a filter that strips out any potentially dangerous words.

When a word gets removed from a string, there's a helpful trick that you can try.

![](../../Attachments/Pasted%20image%2020231105005913.png)

Try entering the payload `<sscriptcript>alert('THM');</sscriptcript>` and click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful with a link to the next level.

**Level Six:**

Similar to level two, where we had to escape from the value attribute of an input tag, we can try `"><script>alert('THM');</script>`, but that doesn't seem to work. Let's inspect the page source to see why that doesn't work.

![](../../Attachments/Pasted%20image%2020231105005918.png)

You can see that the < and > characters get filtered out from our payload, preventing us from escaping the IMG tag. To get around the filter, we can take advantage of the additional attributes of the IMG tag, such as the onload event. The onload event executes the code of your choosing once the image specified in the src attribute has loaded onto the web page.  
  
Let's change our payload to reflect this `/images/cat.jpg" onload="alert('THM');` and then viewing the page source, and you'll see how this will work.

![](../../Attachments/Pasted%20image%2020231105005926.png)

Now when you click the enter button, you'll get an alert popup with the string THM.

**Polyglots:**

An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.

```js
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```