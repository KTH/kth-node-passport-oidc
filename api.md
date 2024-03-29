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
<dt><a href="#logout">logout(req, res)</a> ⇒ <code>Promise.&lt;Middleware&gt;</code></dt>
<dd></dd>
<dt><a href="#requireRole">requireRole(roles)</a> ⇒ <code>Middleware</code></dt>
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

| Param                             | Type                  | Description                                                                                                                                                                                                                               |
| --------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| expressApp                        | <code>Object</code>   | The express app instance                                                                                                                                                                                                                  |
| passport                          | <code>Object</code>   | The passport instance                                                                                                                                                                                                                     |
| config                            | <code>Object</code>   | Configuration object                                                                                                                                                                                                                      |
| config.configurationUrl           | <code>string</code>   | Url to OpenID Connect server Example: https://myOpenIDServer.com/adfs/.well-known/openid-configuration                                                                                                                                    |
| config.clientId                   | <code>string</code>   | This apps clientID                                                                                                                                                                                                                        |
| config.clientSecret               | <code>string</code>   | This apps client secret                                                                                                                                                                                                                   |
| config.tokenSecret                | <code>string</code>   | This apps token secret, used for encrypting token for session storage                                                                                                                                                                     |
| config.callbackLoginUrl           | <code>string</code>   | This apps full URL to callback function for standard login. Example: http://localhost:3000/node/auth/login/callback                                                                                                                       |
| config.callbackLoginRoute         | <code>string</code>   | The callback route used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/login/callback                                                                                                     |
| [config.callbackSilentLoginUrl]   | <code>string</code>   | Optional This apps full URL to callback function for silent login. Example: http://localhost:3000/node/auth/silent/callback                                                                                                               |
| [config.callbackSilentLoginRoute] | <code>string</code>   | Optional The silent callback route used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/silent/callback                                                                                    |
| [config.callbackLogoutUrl]        | <code>string</code>   | Optional This apps full URL to callback function for logout. Example: http://localhost:3000/node/auth/logout/callback                                                                                                                     |
| [config.callbackLogoutRoute]      | <code>string</code>   | Optional The logout callback route used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/logout/callback                                                                                    |
| config.defaultRedirect            | <code>string</code>   | Fallback if no next url is supplied to login or on logout                                                                                                                                                                                 |
| [config.extendUser]               | <code>function</code> | Optional Function which gives you the possibility to add custom properties to the user object. The supplied function can be a async. Example: (user, claims) => { user.isAwesome = true } or async (user, claims) => { // do a api call } |
| [config.log]                      | <code>Object</code>   | Optional Logger object which should have logging functions. Used for logging in this module. Example: logger.error('Error message')                                                                                                       |
| [config.setIsOwner]               | <code>boolean</code>  | Optional flag with false as default. When used with requireRole, user objects includes an isOwner attribute which is set to true only if req.parameter contains the same username as the logged in username.                              |

<a name="login"></a>

## login(req, res, next) ⇒ <code>Promise.&lt;Middleware&gt;</code>

**Kind**: global function  
**Summary**: Check if the user it authenticated or else redirect to OpenID Connect server
for authentication  
**Returns**: <code>Promise.&lt;Middleware&gt;</code> - A promise which resolves to a middleware which ensures a logged in user

| Param | Type                  | Description                      |
| ----- | --------------------- | -------------------------------- |
| req   | <code>Object</code>   | Express request object           |
| res   | <code>Object</code>   | Express response object          |
| next  | <code>function</code> | Express next middleware function |

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

| Param | Type                  | Description                      |
| ----- | --------------------- | -------------------------------- |
| req   | <code>Object</code>   | Express request object           |
| res   | <code>Object</code>   | Express response object          |
| next  | <code>function</code> | Express next middleware function |

**Example**

```js
oidc.silentLogin
```

<a name="logout"></a>

## logout(req, res) ⇒ <code>Promise.&lt;Middleware&gt;</code>

**Kind**: global function  
**Summary**: Express Middleware that logs out the user from both the OpenID Connect server and this app. Note: The user is redirected to the config.defaultRedirect after a successful logout.  
**Returns**: <code>Promise.&lt;Middleware&gt;</code> - A promise which resolves to a middleware which logs out the current user

| Param | Type                | Description             |
| ----- | ------------------- | ----------------------- |
| req   | <code>Object</code> | Express request object  |
| res   | <code>Object</code> | Express response object |

**Example**

```js
oidc.logout
```

<a name="requireRole"></a>

## requireRole(roles) ⇒ <code>Middleware</code>

**Kind**: global function  
**Summary**: Express Middleware that checks if the req.user has this/these roles.  
**Returns**: <code>Middleware</code> - A Express middleware

A role is a property found on the user object and has most
likely been added through the optional extendUser function parameter. @see {config.extendUser}

If config.setIsOwner is set, the user object gets additional property (isOwner) which is set only if the req.parameter has the same username  
**Api**: public

| Param | Type                              | Description                                                        |
| ----- | --------------------------------- | ------------------------------------------------------------------ |
| roles | <code>Array.&lt;string&gt;</code> | Array of roles to be compared with the ones on the req.user object |

**Example**

```js
oidc.requireRole('isAdmin', 'isEditor')
```
