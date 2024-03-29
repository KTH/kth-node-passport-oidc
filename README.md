# KTH Node Passport OpenID Connect

Simple and configurable package for OpenID Connect authentication. Based on [node-openid-client](https://github.com/panva/node-openid-client) and gives you Express middleware based on Passport.

## Quick start

```bash
$ npm install @kth/kth-node-passport-oidc
```

```js
const { OpenIDConnect, hasGroup } = require('@kth/kth-node-passport-oidc')

const oidc = new OpenIDConnect(server, passport, {
  ...config.oidc,
  appCallbackLoginUrl: _addProxy('/auth/login/callback'),
  appCallbackLogoutUrl: _addProxy('/auth/logout/callback'),
  appCallbackSilentLoginUrl: _addProxy('/auth/silent/callback'),
  defaultRedirect: _addProxy(''),
  extendUser: (user, claims) => {
    user.isAdmin = hasGroup(config.auth.adminGroup, user)
  },
  log,
})

// And use the middleware with your routes
appRoute.get('node.page', _addProxy('/silent'), oidc.silentLogin, Sample.getIndex)
appRoute.get('node.index', _addProxy('/'), oidc.login, Sample.getIndex)
```

## The basics

There are three basic OIDC functions

### **login**

A normal login. Use this middleware to force the user to login into the OpenID Connect server.

After a successful login a user object can be found in req.user.

If not, the user may not visit the route

### **silentLogin**

A silent login. Basically the user is allowed to be anonymous.

Use this middleware to check if the user is logged into the OpenID Connect server.

If the user is logged in a user object can be found in req.user.

If not, the user is anonymous and the req.user will be undefined. The silent login will occur again after `anonymousCookieMaxAge` expires.

### **logout**

Logs out the user from both the OpenID Connect server and this app.

## Configuration

Configuration for each OIDC function comes in pairs. A pair consist of the same URL in two different formats.

One that is configured directly into the OpenID Connect client and the other is used to set up the URL in our app through a Express route.

These URLs are used by the OpenID Connect server to communicate with our app during authentication.

> Note: Only the login configuration is required but you will most likely want at least also the logout

## req.user

On a successful login passport will add a user object on the request object. By default this object will have the following properties:

| Property    | Type   | Example                               | Description                                                            |
| ----------- | ------ | ------------------------------------- | ---------------------------------------------------------------------- |
| username    | string | johnd                                 | KTH Username                                                           |
| displayName | string | John Doe                              | Users full name                                                        |
| email       | string |                                       | KTH email address. This requires higher security clearance             |
| memberOf    | array  | ['app.myApp.user', 'app.myApp.admin'] | Groups connected to this user. This requires higher security clearance |

If you would like to add properties to the user object you can do this by adding a function called `extendUser` when instantiating OpenIDConnect. The function can also be async.

The function makes changes directly to the user object and must have this signature:

```js
;(user, claims) => {
  user.isAwesome = true
}
```

> The claims argument is the full response from the OpenID Connect server

### Parameters

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
| [config.setIsOwner]               | <code>boolean</code>  | Optional flag with false as default. When used with requireRole, user object includes the property isOwner which is set to true only if req.parameter contains the same username as the logged in username.                               |
|                                   |

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
**Api**: public

| Param | Type                              | Description                                                        |
| ----- | --------------------------------- | ------------------------------------------------------------------ |
| roles | <code>Array.&lt;string&gt;</code> | Array of roles to be compared with the ones on the req.user object |

**Example**

```js
oidc.requireRole('isAdmin', 'isEditor')
```

## Versions and Migrating

### v4

**Important**: SilentLogin now uses the toolbar cookie KTH_SSO_START for deciding if the user should be silently logged in.

Basically: if the cookie exists we will try to silently login in the user.

This eliminates a strange behavior for our users.
Most users considers the Social toolbar as the main place to log in into KTH. But if they used one app before they logged into the toolbar, a session was already created in that app which was anonymous.

By letting the app know, through the KTH_SSO_START cookie, that it should try again to log in the user, we get a better flow for the user.

### v3

Changes how the data in the session is stored during login.

### v2

Changes how the data in the session is stored during login. Also adds the possibility to configure a logger which can be used to debug.

### v1

The original :-)

## Troubleshooting

### I get a 403 Unauthorized when trying to login

If you get this message after you logged into the ADFS server it might be that your applications local time differs from the one on the ADFS server.

After you logged in, the client (browser) is trying to call the callback-route in your application.

The reason for this is that the JWT information contains a timestamp. If the timestamp differs to much the JWT will be refused and you get a 403.

Check your time settings. Are you synching with a time server? Try to change this to `ntp.kth.se`

### Handling multiple simultaneous requests

If your app gets multiple simultaneous requests it will break. This is mainly because our session store does not work well with multiple app instances. It can overwrite session data if requests reach the two app instances at the same time.

And since we store ongoing auth information in the session, it will break most of the time. The last request will most likely succeed.

One way to handle this is to ensure that a login has been made before all the requests are made.

#### Example

This solution is currently used in directory-web and files-web.

In Directory-web, the app that makes multiple calls for avatar images, use this middleware on its public routes. It bounces the incoming page requests, if needed, against files-web.

> Note: Working locally, localhost:3000 and so on, can be problematic. The KTH_SSO_START cookie has a domain set which will not work with localhost. One way is to simply create a "fake cookie" with the same name.

```javascript
const bounceOnFiles = (req, res, next) => {
  const cookies = Object.keys(req.cookies)
  const filesAuthHandling = `${cookies.includes('files-web.sid')}${cookies.includes('KTH_SSO_START')}`

  // By adding the existence of the two cookies above we create a state. The state
  // shows if a files-cookie exists and if a KTH_SSO_START cookie exists. If the
  // state changes during calls we bounce against files-web again to get a correct state

  if (req.session.filesAuthHandling === filesAuthHandling) {
    return next()
  }

  req.session.filesAuthHandling = filesAuthHandling
  const nextUrl = encodeURIComponent(req.protocol + '://' + req.get('host') + req.originalUrl)
  // config.files.url = https://www-r.referens.sys.kth.se/files
  return res.redirect(`${config.files.url}/auth/silent/bounce?nextUrl=${nextUrl}`)
}
```

**serverSettings.js**

```javascript
files: {
  url: getEnv('FILES_URL', devDefaults('http://localhost:3003/files')),
}
```

In Files-web, the app that serves avatar images has this routes which handles the bounce request. As you may notice there is a simple whitelisting of the accepted urls to be redirected.

```javascript
const urlWhitelist = ['localhost', '.kth.se']

server.get(_addProxy('/auth/silent/bounce'), oidc.silentLogin, async (req, res, next) => {
  const nextUrl = req.query.nextUrl

  if (!nextUrl) {
    return res.status(400).send('Missing nextUrl param')
  }

  if (!urlWhitelist.find(whitelisted => nextUrl.includes(whitelisted))) {
    return res.status(400).send('Not an accepted url')
  }

  return res.redirect(nextUrl)
})
```

## Development

1. Clone the repo
   ```bash
   $ npm clone git@github.com:KTH/kth-node-passport-oidc.git
   ```
2. Install dependencies
   ```bash
   $ npm install
   ```

### Generate API documentation

This project includes a simple generation of Markdown documentation from the JS-doc in our code.

To run this:

```bash
$ npm run buildApiDocs
```

Now you have a `api.md` file in the root of the project. Use this to update the main `README.md`
