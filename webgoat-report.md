
# ZAP Scanning Report

Generated on 月, 22 2 2021 21:22:11


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 3 |
| Low | 9 |
| Informational | 9 |

## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| SQL Injection | High | 1 | 
| Cross-Domain Misconfiguration | Medium | 1 | 
| Parameter Tampering | Medium | 1 | 
| Vulnerable JS Library | Medium | 3 | 
| Absence of Anti-CSRF Tokens | Low | 4 | 
| Cookie No HttpOnly Flag | Low | 2 | 
| Cookie Without SameSite Attribute | Low | 2 | 
| Incomplete or No Cache-control and Pragma HTTP Header Set | Low | 26 | 
| X-Content-Type-Options Header Missing | Low | 20 | 
| Charset Mismatch  | Informational | 1 | 
| Charset Mismatch (Header Versus Meta Content-Type Charset) | Informational | 1 | 
| Information Disclosure - Suspicious Comments | Informational | 42 | 
| Loosely Scoped Cookie | Informational | 3 | 
| Timestamp Disclosure - Unix | Informational | 131 | 

## Alert Detail


  
  
  
  
### SQL Injection
##### High (Medium)
  
  
  
  
#### Description
<p>SQL injection may be possible.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/register.mvc](http://localhost:10080/WebGoat/register.mvc)
  
  
  * Method: `POST`
  
  
  * Parameter: `agree`
  
  
  * Attack: `agree AND 1=1 -- `
  
  
  
  
Instances: 1
  
### Solution
<p>Do not trust client side input, even if there is client side validation in place.  </p><p>In general, type check all data on the server side.</p><p>If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'</p><p>If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.</p><p>If database Stored Procedures can be used, use them.</p><p>Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!</p><p>Do not create dynamic SQL queries using simple string concatenation.</p><p>Escape all data received from the client.</p><p>Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.</p><p>Apply the principle of least privilege by using the least privileged database user possible.</p><p>In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.</p><p>Grant the minimum database access that is necessary for the application.</p>
  
### Other information
<p>The page results were successfully manipulated using the boolean conditions [agree AND 1=1 -- ] and [agree AND 1=2 -- ]</p><p>The parameter value being modified was NOT stripped from the HTML output for the purposes of the comparison</p><p>Data was returned for the original parameter.</p><p>The vulnerability was detected by successfully restricting the data originally returned, by manipulating the parameter</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

  
#### CWE Id : 89
  
#### WASC Id : 19
  
#### Source ID : 1

  
  
  
  
### Cross-Domain Misconfiguration
##### Medium (Medium)
  
  
  
  
#### Description
<p>Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server</p>
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records)
  
  
  * Method: `GET`
  
  
  * Evidence: `Access-Control-Allow-Origin: *`
  
  
  
  
Instances: 1
  
### Solution
<p>Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).</p><p>Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.</p>
  
### Other information
<p>The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.</p>
  
### Reference
* http://www.hpenterprisesecurity.com/vulncat/en/vulncat/vb/html5_overly_permissive_cors_policy.html

  
#### CWE Id : 264
  
#### WASC Id : 14
  
#### Source ID : 3

  
  
  
  
### Parameter Tampering
##### Medium (Medium)
  
  
  
  
#### Description
<p>Parameter manipulation caused an error page or Java stack trace to be displayed.  This indicated lack of exception handling and potential areas for further exploit.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/register.mvc](http://localhost:10080/WebGoat/register.mvc)
  
  
  * Method: `POST`
  
  
  * Parameter: `matchingPassword`
  
  
  * Evidence: `javax.servlet.http.HttpServlet.service(HttpServlet.java:523)\n\tat`
  
  
  
  
Instances: 1
  
### Solution
<p>Identify the cause of the error and fix it.  Do not trust client side input and enforce a tight check in the server side.  Besides, catch the exception properly.  Use a generic 500 error page for internal server error.</p>
  
### Reference
* 

  
#### CWE Id : 472
  
#### WASC Id : 20
  
#### Source ID : 1

  
  
  
  
### Vulnerable JS Library
##### Medium (Medium)
  
  
  
  
#### Description
<p>The identified library jquery, version 3.4.1 is vulnerable.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery.min.js](http://localhost:10080/WebGoat/js/libs/jquery.min.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `/*! jQuery v3.4.1`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `/*! jQuery UI - v1.10.3 - 2013-05-03
* http://jqueryui.com
* Includes: jquery.ui.core.js, jquery.ui.widget.js, jquery.ui.mouse.js, jquery.ui.draggable.js, jquery.ui.droppable.js, jquery.ui.resizable.js, jquery.ui.selectable.js, jquery.ui.sortable.js, jquery.ui.effect.js, jquery.ui.accordion.js, jquery.ui.autocomplete.js, jquery.ui.button.js, jquery.ui.datepicker.js, jquery.ui.dialog.js`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-2.1.4.min.js](http://localhost:10080/WebGoat/js/libs/jquery-2.1.4.min.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `jquery-2.1.4.min.js`
  
  
  
  
Instances: 3
  
### Solution
<p>Please upgrade to the latest version of jquery.</p>
  
### Other information
<p>CVE-2020-11023</p><p>CVE-2020-11022</p><p></p>
  
### Reference
* https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
* 

  
#### CWE Id : 829
  
#### Source ID : 3

  
  
  
  
### Absence of Anti-CSRF Tokens
##### Low (Medium)
  
  
  
  
#### Description
<p>No Anti-CSRF tokens were found in a HTML submission form.</p><p>A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.</p><p></p><p>CSRF attacks are effective in a number of situations, including:</p><p>    * The victim has an active session on the target site.</p><p>    * The victim is authenticated via HTTP auth on the target site.</p><p>    * The victim is on the same local network as the target site.</p><p></p><p>CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/login?error](http://localhost:10080/WebGoat/login?error)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/WebGoat/login" method='POST' style="width: 200px;">`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/login](http://localhost:10080/WebGoat/login)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form action="/WebGoat/login" method='POST' style="width: 200px;">`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/registration](http://localhost:10080/WebGoat/registration)
  
  
  * Method: `GET`
  
  
  * Evidence: `<form class="form-horizontal" action="/WebGoat/register.mvc" method='POST'>`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/register.mvc](http://localhost:10080/WebGoat/register.mvc)
  
  
  * Method: `POST`
  
  
  * Evidence: `<form class="form-horizontal" action="/WebGoat/register.mvc" method='POST'>`
  
  
  
  
Instances: 4
  
### Solution
<p>フェーズ： アーキテクチャと設計</p><p>同脆弱性を引き起こさせない、あるいは容易に回避可能な精査されたライブラリ、あるいはフレームワークを使用してください。</p><p>たとえば、OWASP CSRFGuard などのアンチCSRFパッケージを使用します。</p><p></p><p>Phase: Implementation</p><p>Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.</p><p></p><p>Phase: Architecture and Design</p><p>Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.</p><p>Note that this can be bypassed using XSS.</p><p></p><p>Use the ESAPI Session Management control.</p><p>This control includes a component for CSRF.</p><p></p><p>Do not use the GET method for any request that triggers a state change.</p><p></p><p>Phase: Implementation</p><p>Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.</p>
  
### Other information
<p>No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF] was found in the following HTML form: [Form 1: "exampleInputEmail1" "exampleInputPassword1" ].</p>
  
### Reference
* http://projects.webappsec.org/Cross-Site-Request-Forgery
* http://cwe.mitre.org/data/definitions/352.html

  
#### CWE Id : 352
  
#### WASC Id : 9
  
#### Source ID : 3

  
  
  
  
### Cookie No HttpOnly Flag
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/](http://localhost:10080/WebGoat/)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/login](http://localhost:10080/WebGoat/login)
  
  
  * Method: `POST`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that the HttpOnly flag is set for all cookies.</p>
  
### Reference
* https://owasp.org/www-community/HttpOnly

  
#### CWE Id : 16
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Cookie Without SameSite Attribute
##### Low (Medium)
  
  
  
  
#### Description
<p>A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/login](http://localhost:10080/WebGoat/login)
  
  
  * Method: `POST`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/](http://localhost:10080/WebGoat/)
  
  
  * Method: `GET`
  
  
  * Parameter: `JSESSIONID`
  
  
  * Evidence: `Set-Cookie: JSESSIONID`
  
  
  
  
Instances: 2
  
### Solution
<p>Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.</p>
  
### Reference
* https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site

  
#### CWE Id : 16
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Incomplete or No Cache-control and Pragma HTTP Header Set
##### Low (Medium)
  
  
  
  
#### Description
<p>The cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content.</p>
  
  
  
* URL: [https://aus5.mozilla.org/update/3/SystemAddons/85.0.2/20210208133944/WINNT_x86_64-msvc-x64/ja/release/Windows_NT%2010.0.0.0.19042.804%20(x64)/default/default/update.xml](https://aus5.mozilla.org/update/3/SystemAddons/85.0.2/20210208133944/WINNT_x86_64-msvc-x64/ja/release/Windows_NT%2010.0.0.0.19042.804%20(x64)/default/default/update.xml)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `public, max-age=90`
  
  
  
  
Instances: 1
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Incomplete or No Cache-control and Pragma HTTP Header Set
##### Low (Medium)
  
  
  
  
#### Description
<p>The cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content.</p>
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/plugins?_expected=1603126502200](https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/plugins?_expected=1603126502200)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/search-default-override-allowlist?_expected=1595254618540](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/search-default-override-allowlist?_expected=1595254618540)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/top-sites?_expected=1611838808382](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/top-sites?_expected=1611838808382)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/password-recipes?_expected=1600889167888](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/password-recipes?_expected=1600889167888)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/anti-tracking-url-decoration?_expected=1564511755134](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/anti-tracking-url-decoration?_expected=1564511755134)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/search-telemetry/changeset?_expected=1613587794383&_since=%221602016373960%22](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/search-telemetry/changeset?_expected=1613587794383&_since=%221602016373960%22)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/language-dictionaries?_expected=1569410800356](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/language-dictionaries?_expected=1569410800356)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=message-groups&bucket=main](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=message-groups&bucket=main)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=60`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=cfr&bucket=main](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=cfr&bucket=main)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=60`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/pioneer-study-addons-v1/changeset?_expected=1607042143590](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/pioneer-study-addons-v1/changeset?_expected=1607042143590)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=partitioning-exempt-urls&bucket=main](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=partitioning-exempt-urls&bucket=main)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=60`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/partitioning-exempt-urls/changeset?_expected=1592906663254](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/partitioning-exempt-urls/changeset?_expected=1592906663254)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/gfx?_expected=1606146402211](https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/gfx?_expected=1606146402211)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset?_expected=1613759892664&_since=%221612658267016%22](https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset?_expected=1613759892664&_since=%221612658267016%22)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/message-groups/changeset?_expected=1595616291726](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/message-groups/changeset?_expected=1595616291726)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=60`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=fxmonitor-breaches&bucket=main](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=fxmonitor-breaches&bucket=main)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=60`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/hijack-blocklists?_expected=1605801189258](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/hijack-blocklists?_expected=1605801189258)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `no-cache, no-store`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=cfr-fxa&bucket=main](https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/records?collection=cfr-fxa&bucket=main)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  * Evidence: `max-age=60`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/search-config/changeset?_expected=1613587855073&_since=%221610163579843%22](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/search-config/changeset?_expected=1613587855073&_since=%221610163579843%22)
  
  
  * Method: `GET`
  
  
  * Parameter: `Cache-Control`
  
  
  
  
Instances: 25
  
### Solution
<p>Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.</p>
  
### Reference
* https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching

  
#### CWE Id : 525
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://ftp.mozilla.org/pub/system-addons/reset-search-defaults/reset-search-defaults@mozilla.com-1.0.3-signed.xpi](https://ftp.mozilla.org/pub/system-addons/reset-search-defaults/reset-search-defaults@mozilla.com-1.0.3-signed.xpi)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 1
  
### Solution
<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>
  
### Other information
<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.</p><p>At "High" threshold this scan rule will not alert on client or server error responses.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
* https://owasp.org/www-community/Security_Headers

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://content-signature-2.cdn.mozilla.net/chains/remote-settings.content-signature.mozilla.org-2021-04-12-15-03-53.chain](https://content-signature-2.cdn.mozilla.net/chains/remote-settings.content-signature.mozilla.org-2021-04-12-15-03-53.chain)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 1
  
### Solution
<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>
  
### Other information
<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.</p><p>At "High" threshold this scan rule will not alert on client or server error responses.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
* https://owasp.org/www-community/Security_Headers

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-tracking-protection-facebook-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/social-tracking-protection-facebook-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/block-flash-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/block-flash-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/content-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/content-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/analytics-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/analytics-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/except-flashallow-digest256/1490633678](https://tracking-protection.cdn.mozilla.net/except-flashallow-digest256/1490633678)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/except-flashsubdoc-digest256/1517935265](https://tracking-protection.cdn.mozilla.net/except-flashsubdoc-digest256/1517935265)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/ads-track-digest256/1611614019](https://tracking-protection.cdn.mozilla.net/ads-track-digest256/1611614019)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/google-trackwhite-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/google-trackwhite-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-tracking-protection-twitter-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/social-tracking-protection-twitter-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/block-flashsubdoc-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/block-flashsubdoc-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-tracking-protection-linkedin-digest256/1564526481](https://tracking-protection.cdn.mozilla.net/social-tracking-protection-linkedin-digest256/1564526481)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/mozstd-trackwhite-digest256/1611614019](https://tracking-protection.cdn.mozilla.net/mozstd-trackwhite-digest256/1611614019)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/base-cryptomining-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/base-cryptomining-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/social-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/except-flash-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/except-flash-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/base-fingerprinting-track-digest256/1608186823](https://tracking-protection.cdn.mozilla.net/base-fingerprinting-track-digest256/1608186823)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/allow-flashallow-digest256/1490633678](https://tracking-protection.cdn.mozilla.net/allow-flashallow-digest256/1490633678)
  
  
  * Method: `GET`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 17
  
### Solution
<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>
  
### Other information
<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.</p><p>At "High" threshold this scan rule will not alert on client or server error responses.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
* https://owasp.org/www-community/Security_Headers

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### X-Content-Type-Options Header Missing
##### Low (Medium)
  
  
  
  
#### Description
<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.</p>
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Parameter: `X-Content-Type-Options`
  
  
  
  
Instances: 1
  
### Solution
<p>Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.</p>
  
### Other information
<p>This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.</p><p>At "High" threshold this scan rule will not alert on client or server error responses.</p>
  
### Reference
* http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
* https://owasp.org/www-community/Security_Headers

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Charset Mismatch 
##### Informational (Low)
  
  
  
  
#### Description
<p>This check identifies responses where the HTTP Content-Type header declares a charset different from the charset defined by the body of the HTML or XML. When there's a charset mismatch between the HTTP header and content body Web browsers can be forced into an undesirable content-sniffing mode to determine the content's correct character set.</p><p></p><p>An attacker could manipulate content on the page to be interpreted in an encoding of their choice. For example, if an attacker can control content at the beginning of the page, they could inject script using UTF-7 encoded text and manipulate some browsers into interpreting that text.</p>
  
  
  
* URL: [https://aus5.mozilla.org/update/3/SystemAddons/85.0.2/20210208133944/WINNT_x86_64-msvc-x64/ja/release/Windows_NT%2010.0.0.0.19042.804%20(x64)/default/default/update.xml](https://aus5.mozilla.org/update/3/SystemAddons/85.0.2/20210208133944/WINNT_x86_64-msvc-x64/ja/release/Windows_NT%2010.0.0.0.19042.804%20(x64)/default/default/update.xml)
  
  
  * Method: `GET`
  
  
  
  
Instances: 1
  
### Solution
<p>Force UTF-8 for all text content in both the HTTP header and meta tags in HTML or encoding declarations in XML.</p>
  
### Other information
<p>There was a charset mismatch between the HTTP Header and the XML encoding declaration: [utf-8] and [null] do not match.</p>
  
### Reference
* http://code.google.com/p/browsersec/wiki/Part2#Character_set_handling_and_detection

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Charset Mismatch (Header Versus Meta Content-Type Charset)
##### Informational (Low)
  
  
  
  
#### Description
<p>This check identifies responses where the HTTP Content-Type header declares a charset different from the charset defined by the body of the HTML or XML. When there's a charset mismatch between the HTTP header and content body Web browsers can be forced into an undesirable content-sniffing mode to determine the content's correct character set.</p><p></p><p>An attacker could manipulate content on the page to be interpreted in an encoding of their choice. For example, if an attacker can control content at the beginning of the page, they could inject script using UTF-7 encoded text and manipulate some browsers into interpreting that text.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/start.mvc](http://localhost:10080/WebGoat/start.mvc)
  
  
  * Method: `GET`
  
  
  
  
Instances: 1
  
### Solution
<p>Force UTF-8 for all text content in both the HTTP header and meta tags in HTML or encoding declarations in XML.</p>
  
### Other information
<p>There was a charset mismatch between the HTTP Header and the META content-type encoding declarations: [UTF-8] and [ISO-8859-1] do not match.</p>
  
### Reference
* http://code.google.com/p/browsersec/wiki/Part2#Character_set_handling_and_detection

  
#### CWE Id : 16
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Medium)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/start.mvc](http://localhost:10080/WebGoat/start.mvc)
  
  
  * Method: `GET`
  
  
  * Evidence: `user`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/start.mvc](http://localhost:10080/WebGoat/start.mvc)
  
  
  * Method: `GET`
  
  
  * Evidence: `admin`
  
  
  
  
Instances: 2
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bUSER\b and was detected 2 times, the first in the element starting with: "<!--<button type="button" id="user-management" class="btn btn-default right_nav_button"-->", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Information Disclosure - Suspicious Comments
##### Informational (Low)
  
  
  
  
#### Description
<p>The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/view/GoatRouter.js](http://localhost:10080/WebGoat/js/goatApp/view/GoatRouter.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `TODO`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/view/MenuView.js](http://localhost:10080/WebGoat/js/goatApp/view/MenuView.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `TODO`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/view/GoatRouter.js](http://localhost:10080/WebGoat/js/goatApp/view/GoatRouter.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/underscore-min.js](http://localhost:10080/WebGoat/js/libs/underscore-min.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `TODO`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/polyglot.min.js](http://localhost:10080/WebGoat/js/libs/polyglot.min.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-2.1.4.min.js](http://localhost:10080/WebGoat/js/libs/jquery-2.1.4.min.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `db`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/support/GoatUtils.js](http://localhost:10080/WebGoat/js/goatApp/support/GoatUtils.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `TODO`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/view/HintView.js](http://localhost:10080/WebGoat/js/goatApp/view/HintView.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `Select`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `later`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/controller/LessonController.js](http://localhost:10080/WebGoat/js/goatApp/controller/LessonController.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `TODO`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bugs`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/view/LessonContentView.js](http://localhost:10080/WebGoat/js/goatApp/view/LessonContentView.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `TODO`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/text.js](http://localhost:10080/WebGoat/js/libs/text.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `bug`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery.form.js](http://localhost:10080/WebGoat/js/libs/jquery.form.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `query`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery.form.js](http://localhost:10080/WebGoat/js/libs/jquery.form.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `select`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/main.js](http://localhost:10080/WebGoat/js/main.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/goatApp/view/LessonContentView.js](http://localhost:10080/WebGoat/js/goatApp/view/LessonContentView.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `from`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery.form.js](http://localhost:10080/WebGoat/js/libs/jquery.form.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `later`
  
  
  
  
Instances: 40
  
### Solution
<p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>
  
### Other information
<p>The following pattern was used: \bTODO\b and was detected in the element starting with: "        //TODO this works for now because we only have one page we should rewrite this a bit", see evidence field for the suspicious comment/snippet.</p>
  
### Reference
* 

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Loosely Scoped Cookie
##### Informational (Low)
  
  
  
  
#### Description
<p>Cookies can be scoped by domain or path. This check is only concerned with domain scope.The domain scope applied to a cookie determines which domains can access it. For example, a cookie can be scoped strictly to a subdomain e.g. www.nottrusted.com, or loosely scoped to a parent domain e.g. nottrusted.com. In the latter case, any subdomain of nottrusted.com can access the cookie. Loosely scoped cookies are common in mega-applications like google.com and live.com. Cookies set from a subdomain like app.foo.bar are transmitted only to that domain by the browser. However, cookies scoped to a parent-level domain may be transmitted to the parent, or any subdomain of the parent.</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/login](http://localhost:10080/WebGoat/login)
  
  
  * Method: `POST`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/](http://localhost:10080/WebGoat/)
  
  
  * Method: `GET`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/](http://localhost:10080/WebGoat/)
  
  
  * Method: `GET`
  
  
  
  
Instances: 3
  
### Solution
<p>Always scope cookies to a FQDN (Fully Qualified Domain Name).</p>
  
### Other information
<p>The origin domain used for comparison was: </p><p>localhost</p><p>JSESSIONID=XbICyU4z9cfw2RaXC3EL6Se3kCSbVX4T-vcpsFnK</p><p></p>
  
### Reference
* https://tools.ietf.org/html/rfc6265#section-4.1
* https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html
* http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies

  
#### CWE Id : 565
  
#### WASC Id : 15
  
#### Source ID : 3

  
  
  
  
### Timestamp Disclosure - Unix
##### Informational (Low)
  
  
  
  
#### Description
<p>A timestamp was disclosed by the application/web server - Unix</p>
  
  
  
* URL: [http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css](http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `00000000`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `86400000`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui.min.js](http://localhost:10080/WebGoat/js/libs/jquery-ui.min.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `0123456789`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `10000000`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css](http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `80000000`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css](http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `42857143`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css](http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `33333333`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js](http://localhost:10080/WebGoat/js/libs/jquery-ui-1.10.4.js)
  
  
  * Method: `GET`
  
  
  * Evidence: `0123456789`
  
  
  
  
* URL: [http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css](http://localhost:10080/WebGoat/plugins/bootstrap/css/bootstrap.min.css)
  
  
  * Method: `GET`
  
  
  * Evidence: `66666667`
  
  
  
  
Instances: 9
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>00000000, which evaluates to: 1970-01-01 09:00:00</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Timestamp Disclosure - Unix
##### Informational (Low)
  
  
  
  
#### Description
<p>A timestamp was disclosed by the application/web server - Unix</p>
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/block-flashsubdoc-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/block-flashsubdoc-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/except-flashsubdoc-digest256/1517935265](https://tracking-protection.cdn.mozilla.net/except-flashsubdoc-digest256/1517935265)
  
  
  * Method: `GET`
  
  
  * Evidence: `1517935265`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/except-flashallow-digest256/1490633678](https://tracking-protection.cdn.mozilla.net/except-flashallow-digest256/1490633678)
  
  
  * Method: `GET`
  
  
  * Evidence: `1490633678`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-tracking-protection-linkedin-digest256/1564526481](https://tracking-protection.cdn.mozilla.net/social-tracking-protection-linkedin-digest256/1564526481)
  
  
  * Method: `GET`
  
  
  * Evidence: `1564526481`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/analytics-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/analytics-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/except-flash-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/except-flash-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/allow-flashallow-digest256/1490633678](https://tracking-protection.cdn.mozilla.net/allow-flashallow-digest256/1490633678)
  
  
  * Method: `GET`
  
  
  * Evidence: `1490633678`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/base-cryptomining-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/base-cryptomining-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-tracking-protection-facebook-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/social-tracking-protection-facebook-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/base-fingerprinting-track-digest256/1608186823](https://tracking-protection.cdn.mozilla.net/base-fingerprinting-track-digest256/1608186823)
  
  
  * Method: `GET`
  
  
  * Evidence: `1608186823`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/ads-track-digest256/1611614019](https://tracking-protection.cdn.mozilla.net/ads-track-digest256/1611614019)
  
  
  * Method: `GET`
  
  
  * Evidence: `1611614019`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-tracking-protection-twitter-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/social-tracking-protection-twitter-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/block-flash-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/block-flash-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/mozstd-trackwhite-digest256/1611614019](https://tracking-protection.cdn.mozilla.net/mozstd-trackwhite-digest256/1611614019)
  
  
  * Method: `GET`
  
  
  * Evidence: `1611614019`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/social-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/social-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/content-track-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/content-track-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://tracking-protection.cdn.mozilla.net/google-trackwhite-digest256/1604686195](https://tracking-protection.cdn.mozilla.net/google-trackwhite-digest256/1604686195)
  
  
  * Method: `GET`
  
  
  * Evidence: `1604686195`
  
  
  
  
Instances: 17
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>1604686195, which evaluates to: 2020-11-07 03:09:55</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Timestamp Disclosure - Unix
##### Informational (Low)
  
  
  
  
#### Description
<p>A timestamp was disclosed by the application/web server - Unix</p>
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Evidence: `1604686195`
  
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Evidence: `1490633678`
  
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Evidence: `1611614019`
  
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Evidence: `1517935265`
  
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Evidence: `1564526481`
  
  
  
  
* URL: [https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2](https://shavar.services.mozilla.com/downloads?client=navclient-auto-ffox&appver=85.0&pver=2.2)
  
  
  * Method: `POST`
  
  
  * Evidence: `1608186823`
  
  
  
  
Instances: 6
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>1604686195, which evaluates to: 2020-11-07 03:09:55</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3

  
  
  
  
### Timestamp Disclosure - Unix
##### Informational (Low)
  
  
  
  
#### Description
<p>A timestamp was disclosed by the application/web server - Unix</p>
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `20727771`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `23165793`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `91436280`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `39721127`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `91991358`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `152445165`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/cfr/changeset?_expected=1613571698371](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/cfr/changeset?_expected=1613571698371)
  
  
  * Method: `GET`
  
  
  * Evidence: `86400000`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `18241518`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset?_expected=1613759892664&_since=%221612658267016%22](https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset?_expected=1613759892664&_since=%221612658267016%22)
  
  
  * Method: `GET`
  
  
  * Evidence: `07120033`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `31939607`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `35846544`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `25692862`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `161749950`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `23205290`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `06781637`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `10981207`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `763117241`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `14936670`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/fxmonitor-breaches/changeset?_expected=1612303475647)
  
  
  * Method: `GET`
  
  
  * Evidence: `12115583`
  
  
  
  
* URL: [https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/message-groups/changeset?_expected=1595616291726](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/message-groups/changeset?_expected=1595616291726)
  
  
  * Method: `GET`
  
  
  * Evidence: `86400000`
  
  
  
  
Instances: 99
  
### Solution
<p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>
  
### Other information
<p>20727771, which evaluates to: 1970-08-29 06:42:51</p>
  
### Reference
* http://projects.webappsec.org/w/page/13246936/Information%20Leakage

  
#### CWE Id : 200
  
#### WASC Id : 13
  
#### Source ID : 3
