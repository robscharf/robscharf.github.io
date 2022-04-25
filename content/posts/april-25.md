+++
title = "Now live on GitHub Pages"
description = ""
type = ["posts","post"]
tags = [
    "blog",
    "golang",
    "hugo",
    "development",
]
date = "2022-04-25"
categories = [
    "Meta",
    "(not the company)",
]
[ author ]
  name = "Rob"
+++

## April 25

Kicking the blog off in earnest.

### Finishing up my intro to the Juice Shop

Today I finished up the (OWASP Juice Shop Room)[https://tryhackme.com/room/owaspjuiceshop] on THM, after leaving the final Cross-site Scripting (XSS) modules unfinished last week. This involved quick introductory examples of three XSS modalities:

| DOM (Special)                                                                                                                                                                                 	| Persistent (Server-side)                                                                                                                                                                                                      	| Reflected (Client-side)                                                                                                                                            	|   	|   	|
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|--------------------------------------------------------------------------------------------------------------------------------------------------------------------	|---	|---	|
| DOM XSS (Document Object Model-based Cross-site Scripting) uses the HTML environment to execute malicious javascript. This type of attack commonly uses the  < script ></ script >  HTML tag. 	| Persistent XSS is javascript that is run when the server loads the page containing it. These can occur when the server does not sanitise the user data when it is uploaded to a page. These are commonly found on blog posts. 	| Reflected XSS is javascript that is run on the client-side end of the web application. These are most commonly found when the server doesn't sanitise search data. 	|   	|   	|
|                                                                                                                                                                                               	|                                                                                                                                                                                                                               	|                                                                                                                                                                    	|   	|   	|
|                                                                                                                                                                                               	|                                                                                                                                                                                                                               	|                                                                                                                                                                    	|   	|   	|


The first example, (Document Object Model-based Cross-site Scripting), involved entering `<iframe src="javascript:alert(`xss`)">` into the Juice Shop's search bar, which uses JavaScript to generate new DOM elements. This causes the server to create an iframe, as a new entity in the site's structure (in this case, containing a modal pop-up containing the 'xss' text entered as an argument). More specifically, this technique is known as "cross-frame scripting."

THe second example, a *persistent* cross-site scripting attack, centers on the interception and manipulation of the [HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers). We use Burp Suite to intercept the site's attempt to capture our computer's ip address while logging out. Instead of providing the server with an updated `True-Client-IP` value, we give the server our favorite xss text iframe: `<iframe src="javascript:alert(`xss`)">`. This attack persists, as it exists as a stored/called value on the server side, and relies on a lack on input sanitization.

Finally, we execute a "reflected" XSS attack, which is executed on the client-side, unlike the previous example. This involves using knowledge about the site's structure and server processes to exploit unsanitized search data. Here, we find that the Juice Shop's Orders & Payment page provides the user with links to track thier purchases in the following format:
`https://juice-sh.op/#/track-result?id=5267-53bf6f08cfb76ee6`

If we replace the `track-result-id` with our favorite iframe JavaScript code, the server will create our JavaScriptified iFrame. This is due to the server not sanitizing tracking information id numbers, as it returns the information from a database.


