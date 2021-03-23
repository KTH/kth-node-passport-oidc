# KTH Node Passport OpenID Connect

NPM: https://www.npmjs.com/package/@kth/kth-node-passport-oidc

Simple and configurable package for OpenID Connect authentication. Based on [node-openid-client](https://github.com/panva/node-openid-client) and gives you Express middleware based on Passport.

Supports login and Silent login.

## Quick start

### Used with node-web template

```js
const { OpenIDConnect, hasGroup } = require("@kth/kth-node-passport-oidc");

const oidc = new OpenIDConnect(server, {
  ...config.oidc,
  appCallbackUrl: _addProxy("/auth/callback"),
  appCallbackSilentUrl: _addProxy("/auth/silent/callback"),
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
appRoute.get("node.page", _addProxy("/:page"), oidc.login, Sample.getIndex);
```

# API Documentation

## Oidc

## Run tests

```bash
npm build ## Does npm install and npm test.
```

You can also view the tests at https://travis-ci.org/KTH/npm-template

### Output from tests

```text

Type of tests header
   ✓ When running tests, expect it to always return 'true'.

```
