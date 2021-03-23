## Classes

<dl>
<dt><a href="#OIDC">OIDC</a></dt>
<dd><p>Setup OIDC with express</p>
</dd>
</dl>

## Members

<dl>
<dt><a href="#constructor">constructor</a></dt>
<dd></dd>
</dl>

## Functions

<dl>
<dt><a href="#login">login(req, res, next)</a> ⇒ <code>Promise.&lt;Middleware&gt;</code></dt>
<dd></dd>
<dt><a href="#silentLogin">silentLogin(req, res, next)</a> ⇒ <code>Promise.&lt;Middleware&gt;</code></dt>
<dd></dd>
<dt><a href="#loginStrategy">loginStrategy()</a> ⇒ <code>Promise.&lt;Strategy&gt;</code></dt>
<dd></dd>
<dt><a href="#loginSilentStrategy">loginSilentStrategy()</a> ⇒ <code>Promise.&lt;Strategy&gt;</code></dt>
<dd></dd>
<dt><a href="#requireRole">requireRole(roles)</a> ⇒ <code>Promise.&lt;Middleware&gt;</code></dt>
<dd></dd>
</dl>

<a name="OIDC"></a>

## OIDC
Setup OIDC with express

**Kind**: global class  
<a name="constructor"></a>

## constructor
**Kind**: global variable  
**Api**: public  
**Todo**

- [ ] Secure cookie?


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| expressApp | <code>Object</code> |  | The express app instance |
| config | <code>Object</code> |  |  |
| config.configurationUrl | <code>String</code> |  |  |
| config.clientId | <code>String</code> |  |  |
| config.clientSecret | <code>String</code> |  |  |
| config.callbackUrl | <code>String</code> |  |  |
| config.appCallbackUrl | <code>String</code> |  | The callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/callback |
| config.callbackSilentUrl | <code>String</code> |  |  |
| config.appCallbackSilentUrl | <code>String</code> |  | The silent callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/silent/callback |
| config.logoutUrl | <code>String</code> |  |  |
| config.defaultRedirect | <code>String</code> |  | Fallback if no next url is supplied to login |
| config.failureRedirect | <code>String</code> |  | In case of error |
| [config.anonymousCookieMaxAge] | <code>String</code> | <code>600000</code> | If a client, on a silent login, is considered anonymous, this cookie lives this long (in milliseconds). |
| config.extendUser | <code>function</code> |  | Function which gives you the possibility to add custom properties to the user object. Example: (user, claims) => {} |

<a name="login"></a>

## login(req, res, next) ⇒ <code>Promise.&lt;Middleware&gt;</code>
**Kind**: global function  
**Summary**: Check if the user it authenticated or else redirect to OpenID Connect server
for authentication  
**Returns**: <code>Promise.&lt;Middleware&gt;</code> - A promise which resolves to a middleware which ensures a logged in user  

| Param | Type | Description |
| --- | --- | --- |
| req | <code>Object</code> | Express request object |
| res | <code>Object</code> | Express response object |
| next | <code>function</code> | Express next middleware function |

**Example**  
```js
oidc.login
```
<a name="silentLogin"></a>

## silentLogin(req, res, next) ⇒ <code>Promise.&lt;Middleware&gt;</code>
**Kind**: global function  
**Summary**: Check if the user is anonymous or authenticated, known as a "silent login"
for authentication  
**Returns**: <code>Promise.&lt;Middleware&gt;</code> - A promise which resolves to a middleware which ensures a silent authenticated user  

| Param | Type | Description |
| --- | --- | --- |
| req | <code>Object</code> | Express request object |
| res | <code>Object</code> | Express response object |
| next | <code>function</code> | Express next middleware function |

**Example**  
```js
oidc.silentLogin
```
<a name="loginStrategy"></a>

## loginStrategy() ⇒ <code>Promise.&lt;Strategy&gt;</code>
**Kind**: global function  
**Summary**: Creates a openid-client Strategy  
**Returns**: <code>Promise.&lt;Strategy&gt;</code> - A promise which resolves to a openid-client configured strategy  
<a name="loginSilentStrategy"></a>

## loginSilentStrategy() ⇒ <code>Promise.&lt;Strategy&gt;</code>
**Kind**: global function  
**Summary**: Creates a openid-client Strategy configured for silent authentication  
**Returns**: <code>Promise.&lt;Strategy&gt;</code> - A promise which resolves to a openid-client configured strategy for silent authentication  
<a name="requireRole"></a>

## requireRole(roles) ⇒ <code>Promise.&lt;Middleware&gt;</code>
**Kind**: global function  
**Summary**: Express Middleware that checks if the req.user has this/these roles.  
**Returns**: <code>Promise.&lt;Middleware&gt;</code> - Promise which resolves to a Express middleware

A role is a property found on the user object and has most
likely been added through the internal createUser function.  
**Api**: public  

| Param | Type | Description |
| --- | --- | --- |
| roles | <code>Array.&lt;string&gt;</code> | Array of roles to be compared with the ones on the req.user object |

**Example**  
```js
requireRole('isAdmin', 'isEditor')
```
