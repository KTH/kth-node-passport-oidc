# KTH Node Passport OpenID Connect

NPM: https://www.npmjs.com/package/@kth/kth-node-passport-oidc

Simple and configurable package for OpenID Connect authentication. Based on [node-openid-client](https://github.com/panva/node-openid-client) and gives you Express middleware based on Passport.

Supports login and Silent login.

## Quick start

### Used with node-web template

```js
const { OpenIDConnect, hasGroup } = require("@kth/kth-node-passport-oidc");

const oidc = new OpenIDConnect(server, passport, {
  ...config.oidc,
  appCallbackLoginUrl: _addProxy("/auth/login/callback"),
  appCallbackLogoutUrl: _addProxy("/auth/logout/callback"),
  appCallbackSilentLoginUrl: _addProxy("/auth/silent/callback"),
  defaultRedirect: _addProxy(""),
  failureRedirect: _addProxy(""),
  extendUser: (user) => {
    user.isAdmin = hasGroup(config.auth.adminGroup, user);
  },
});

// And use the middleware with your routes
appRoute.get(
  "node.page",
  _addProxy("/silent"),
  oidc.silentLogin,
  Sample.getIndex
);
appRoute.get("node.index", _addProxy("/"), oidc.login, Sample.getIndex);
```

### Parameters

| Param                              | Type                  | Default             | Description                                                                                                                                          |
| ---------------------------------- | --------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| expressApp                         | <code>Object</code>   |                     | The express app instance                                                                                                                             |
| passport                           | <code>Object</code>   |                     | The passport instance                                                                                                                                |
| config                             | <code>Object</code>   |                     | Configuration object                                                                                                                                 |
| config.configurationUrl            | <code>string</code>   |                     | Url to OpenID Connect server Example: https://myOpenIDServer.com/adfs/.well-known/openid-configuration                                               |
| config.clientId                    | <code>string</code>   |                     | This apps clientID                                                                                                                                   |
| config.clientSecret                | <code>string</code>   |                     | This apps client secret                                                                                                                              |
| config.callbackLoginUrl            | <code>string</code>   |                     | This apps full URL to callback function for standard login. Example: http://localhost:3000/node/auth/login/callback                                  |
| config.appCallbackLoginUrl         | <code>string</code>   |                     | The callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/login/callback                  |
| [config.callbackSilentLoginUrl]    | <code>string</code>   |                     | This apps full URL to callback function for silent login. Example: http://localhost:3000/node/auth/silent/callback                                   |
| [config.appCallbackSilentLoginUrl] | <code>string</code>   |                     | Optional The silent callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/silent/callback |
| [config.callbackLogoutUrl]         | <code>string</code>   |                     | Optional This apps full URL to callback function for logout. Example: http://localhost:3000/node/auth/silent/callback                                |
| [config.appCallbackLogoutUrl]      | <code>string</code>   |                     | Optional The silent callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/logout/callback |
| config.defaultRedirect             | <code>string</code>   |                     | Fallback if no next url is supplied to login                                                                                                         |
| config.failureRedirect             | <code>string</code>   |                     | In case of error                                                                                                                                     |
| [config.anonymousCookieMaxAge]     | <code>string</code>   | <code>600000</code> | Optional If a client, on a silent login, is considered anonymous, this cookie lives this long (in milliseconds).                                     |
| [config.extendUser]                | <code>function</code> |                     | Optional Function which gives you the possibility to add custom properties to the user object. Example: (user, claims) => { user.isAwesome = true }  |

### Properties on the created OIDC

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
oidc.login;
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
oidc.silentLogin;
```

<a name="logout"></a>

## logout(req, res)

**Kind**: global function  
**Summary**: Check if the user it authenticated or else redirect to OpenID Connect server
for authentication

| Param | Type                | Description             |
| ----- | ------------------- | ----------------------- |
| req   | <code>Object</code> | Express request object  |
| res   | <code>Object</code> | Express response object |

**Example**

```js
oidc.login;
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
likely been added through the internal createUser function. @see {constructor}  
**Api**: public

| Param | Type                              | Description                                                        |
| ----- | --------------------------------- | ------------------------------------------------------------------ |
| roles | <code>Array.&lt;string&gt;</code> | Array of roles to be compared with the ones on the req.user object |

**Example**

```js
requireRole("isAdmin", "isEditor");
```

## Run tests

```bash
npm build ## Does npm install and npm test.
```
