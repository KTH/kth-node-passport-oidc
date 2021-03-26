require("dotenv").config();
const express = require("express");
const passport = require("passport");
const server = express();

serverSetup();

const { OpenIDConnect, hasGroup } = require("../lib/index");

const oidcConfig = {
  configurationUrl: getEnv("OIDC_CONFIGURATION_URL"),
  clientId: getEnv("OIDC_APPLICATION_ID"),
  clientSecret: getEnv("OIDC_CLIENT_SECRET"),
  callbackLoginUrl: "http://localhost:3000/node/auth/login/callback",
  callbackSilentLoginUrl: "http://localhost:3000/node/auth/silent/callback",
  callbackLogoutUrl: "http://localhost:3000/node/auth/logout/callback",
};

const oidc = new OpenIDConnect(server, passport, {
  ...oidcConfig,
  appCallbackLoginUrl: "/node/auth/login/callback",
  appCallbackLogoutUrl: "/node/auth/logout/callback",
  appCallbackSilentLoginUrl: "/node/auth/silent/callback",
  defaultRedirect: "/",
  failureRedirect: "/",
  // eslint-disable-next-line no-unused-vars
  extendUser: (user, claims) => {
    // eslint-disable-next-line no-param-reassign
    user.isAdmin = true;
  },
});

server.get("/", (req, res) => {
  res.send("Hello World!");
});

server.get("/login", oidc.login, (req, res) => {
  res.send("Logged In Hello World!");
});

const port = 3000;

server.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

function serverSetup() {
  var session = require("express-session");
  server.use(
    session({
      secret: "thereIsNoSpoon",
    })
  );

  server.use(passport.initialize());
  server.use(passport.session());

  passport.serializeUser((user, done) => {
    if (user) {
      done(null, user);
    } else {
      done();
    }
  });

  passport.deserializeUser((user, done) => {
    if (user) {
      done(null, user);
    } else {
      done();
    }
  });
}

function getEnv(name) {
  const outp = process.env[name];
  if (outp === undefined) {
    console.warn(
      'You have not configured any value for "' +
        name +
        '" and there was no default value. This could cause strange errors, check your environment variable configurations!'
    );
  }
  return outp;
}
