const { Issuer, Strategy } = require("openid-client");

const {
  generators: { state },
} = require("openid-client");

/**
 * @class
 * @classdesc Setup OIDC with express
 */
class OIDC {
  // ***************************
  // Internal functions
  // ***************************

  extractDisplayName(uniqueName) {
    if (Array.isArray(uniqueName)) {
      return uniqueName[0];
    }

    return uniqueName;
  }

  createUserFromClaims(claims, extendUser = () => {}) {
    let user = {
      username: claims.ugUsername,
      displayName: this.extractDisplayName(claims.unique_name), // An array. What to do .....
      email: claims.email, // Was this a high security value?
      memberOf: claims.memberOf,
    };

    extendUser(user, claims);

    return user;
  }

  isCallbackConfigured(type, callback, appCallback) {
    if (callback && appCallback) {
      return true;
    }

    if (!callback && !appCallback) {
      return false;
    }

    if (!callback) {
      throw new Error(
        `A route (appCallback) for ${type} was found but no callback URL for the strategy. Bad configuration?`
      );
    }

    if (!appCallback) {
      throw new Error(
        `A callback (for the strategy) for ${type} was found but no route (appCallback) URL. Bad configuration?`
      );
    }
  }

  /**
   * @name constructor
   * @api public
   *
   *
   * @todo Checks of params
   * @todo Secure cookie?
   *
   * @param {Object} expressApp The express app instance
   * @param {Object} passport The passport instance
   * @param {Object} config Configuration object
   * @param {String} config.configurationUrl Url to OpenID Connect server Example: https://myOpenIDServer.com/adfs/.well-known/openid-configuration
   * @param {String} config.clientId This apps clientID
   * @param {String} config.clientSecret This apps client secret
   * @param {String} config.callbackLoginUrl This apps full URL to callback function for standard login. Example: http://localhost:3000/node/auth/login/callback
   * @param {String} config.appCallbackLoginUrl The callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/login/callback
   * @param {String} config.callbackSilentLoginUrl This apps full URL to callback function for silent login. Example: http://localhost:3000/node/auth/silent/callback
   * @param {String} config.appCallbackSilentLoginUrl The silent callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/silent/callback
   * @param {String} config.callbackLogoutUrl This apps full URL to callback function for logout. Example: http://localhost:3000/node/auth/silent/callback
   * @param {String} config.appCallbackLogoutUrl The silent callback URL used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/logout/callback
   * @param {String} config.defaultRedirect Fallback if no next url is supplied to login
   * @param {String} config.failureRedirect In case of error
   * @param {String} [config.anonymousCookieMaxAge=600000] If a client, on a silent login, is considered anonymous, this cookie lives this long (in milliseconds).
   * @param {function} config.extendUser Function which gives you the possibility to add custom properties to the user object. Example: (user, claims) => { user.isAwesome = true }
   */

  constructor(
    expressApp,
    passport,
    {
      configurationUrl,
      clientId,
      clientSecret,
      callbackLoginUrl,
      appCallbackLoginUrl,
      callbackSilentLoginUrl,
      appCallbackSilentLoginUrl,
      callbackLogoutUrl,
      appCallbackLogoutUrl,
      defaultRedirect,
      failureRedirect,
      anonymousCookieMaxAge = 600000,
      extendUser,
    }
  ) {
    OIDC.prototype.login = () => Promise.reject(new Error("Not configured"));
    OIDC.prototype.loginSilent = () =>
      Promise.reject(new Error("Not configured"));
    OIDC.prototype.logout = () => Promise.reject(new Error("Not configured"));

    const oidcClient = Issuer.discover(configurationUrl).then(
      (provider) =>
        new provider.Client({
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uris: [callbackLoginUrl], // The redirect url must be registered with ADFS!
          post_logout_redirect_uris: [callbackLogoutUrl], // The logout url must be registered with ADFS!
          usePKCE: "S256",
          // response_types: ['code'], (default "code")
          // id_token_signed_response_alg (default "RS256")
          // token_endpoint_auth_method (default "client_secret_basic")
          token_endpoint_auth_method: "client_secret_post",
        })
    );

    // ***************************
    // Login setup
    // ***************************

    if (
      this.isCallbackConfigured("login", callbackLoginUrl, appCallbackLoginUrl)
    ) {
      /**
       * @method
       * @name loginStrategy
       *
       * @summary Creates a openid-client Strategy
       *
       * @returns {Promise<Strategy>} A promise which resolves to a openid-client configured strategy
       */
      const loginStrategy = async () => {
        const client = await oidcClient;
        const loginStrategy = new Strategy(
          { client, passReqToCallback: true, usePKCE: "S256" },
          (req, tokenSet, done) => {
            req.session["_id_token"] = tokenSet.id_token; // store id_token for logout
            return done(
              null,
              this.createUserFromClaims(tokenSet.claims(), extendUser)
            );
          }
        );
        passport.use("oidc", loginStrategy);
        return loginStrategy;
      };

      /**
       * @method
       * @name login
       *
       * @param {Object} req - Express request object
       * @param {Object} res - Express response object
       * @param {Function} next - Express next middleware function
       *
       * @summary Check if the user it authenticated or else redirect to OpenID Connect server
       * for authentication
       *
       * @example oidc.login
       *
       * @returns {Promise<Middleware>} A promise which resolves to a middleware which ensures a logged in user
       */
      /* On a redirect this function generates a state. This is automatically done inside the openid-client
       * but can also be injected into the authentication function, which is what happens here.
       *
       * The state is a unique random string which we send to the OpenID Connect server
       * and then used to verify the callback from the server. This to prevent request forgery.
       * Read more: https://developers.google.com/identity/protocols/oauth2/openid-connect#createxsrftoken
       *
       * The state is generated the same way as it is done inside the openid-client but in this way we
       * can store the originally requested URL in the session with a unique id. This id, the state, is
       * also sent to our callback function from the OpenID Connect server, where we can extract the originalUrl
       * from the session with the state.
       *
       */
      OIDC.prototype.login = async function (req, res, next) {
        // eslint-disable-next-line no-unused-vars
        const strategyIsReady = await loginStrategy();
        // eslint-disable-next-line no-shadow
        return ((req, res, next) => {
          if (
            typeof req.isAuthenticated === "function" &&
            req.isAuthenticated()
          ) {
            return next();
          }

          const newState = state();

          req.session.redirects = req.session.redirects || {};

          req.session.redirects[newState] = req.originalUrl || req.url;

          return passport.authenticate("oidc", { state: newState })(
            req,
            res,
            next
          );
        })(req, res, next);
      };

      /**
       * Setup of express route. Callback route to be used by OpenID Connect server
       * for authentication
       *
       * On a successful authentication the user is redirected to the original url
       */
      expressApp.get(appCallbackLoginUrl, (req, res, next) => {
        const nextUrl =
          req.session.redirects[req.query.state] || defaultRedirect;
        delete req.session.redirects[req.query.state];
        passport.authenticate("oidc", {
          successRedirect: nextUrl,
          failureRedirect,
        })(req, res, next);
      });
    }

    // ***************************
    // Silent authentication setup
    // ***************************
    if (
      this.isCallbackConfigured(
        "silent",
        callbackSilentLoginUrl,
        appCallbackSilentLoginUrl
      )
    ) {
      /**
       * @method
       * @name loginSilentStrategy
       *
       * @summary Creates a openid-client Strategy configured for silent authentication
       *
       * @returns {Promise<Strategy>} A promise which resolves to a openid-client configured strategy for silent authentication
       */
      const loginSilentStrategy = async () => {
        const client = await oidcClient;
        const loginSilentStrategy = new Strategy(
          {
            client,
            params: { prompt: "none", redirect_uri: callbackSilentLoginUrl },
            passReqToCallback: true,
            usePKCE: "S256",
          },
          (req, tokenSet, done) => {
            req.session["_id_token"] = tokenSet.id_token; // store id_token for logout
            return done(
              null,
              this.createUserFromClaims(tokenSet.claims(), extendUser)
            );
          }
        );
        passport.use("oidcSilent", loginSilentStrategy);
        return loginSilentStrategy;
      };

      /**
       * @method
       * @name silentLogin
       *
       * @param {Object} req - Express request object
       * @param {Object} res - Express response object
       * @param {Function} next - Express next middleware function
       *
       * @summary Check if the user is anonymous or authenticated, known as a "silent login"
       * for authentication
       *
       * @example oidc.silentLogin
       *
       * @returns {Promise<Middleware>}  A promise which resolves to a middleware which ensures a silent authenticated user
       */
      /*
       * Read More: https://auth0.com/docs/authorization/configure-silent-authentication
       *
       * @see {@login} for more of the redirect functionality
       *
       */
      OIDC.prototype.silentLogin = async function (req, res, next) {
        // eslint-disable-next-line no-unused-vars
        const silentStrategyIsReady = await loginSilentStrategy();
        return ((req, res, next) => {
          if (
            req.session.anonymous ||
            (typeof req.isAuthenticated === "function" && req.isAuthenticated())
          ) {
            return next();
          }

          const newState = state();

          req.session.redirects = req.session.redirects || {};

          req.session.redirects[newState] = req.originalUrl || req.url;

          return passport.authenticate("oidcSilent", { state: newState })(
            req,
            res,
            next
          );
        })(req, res, next);
      };

      /**
       * Setup of express route. Callback route to be used by OpenID Connect server
       * for silent authentication
       *
       * Handles error codes from OpenID Connect server if the user isn't logged in.
       * Possible error codes
       * - login_required
       * - consent_required
       * - interaction_required
       *
       * Read More: https://auth0.com/docs/authorization/configure-silent-authentication
       *
       * On a successful authentication the user is redirected to the original url
       */
      expressApp.get(appCallbackSilentLoginUrl, (req, res, next) => {
        const nextUrl =
          req.session.redirects[req.query.state] || defaultRedirect;
        delete req.session.redirects[req.query.state];

        if (req.query.error) {
          if (
            req.query.error === "login_required" ||
            req.query.error === "consent_required" ||
            req.query.error === "interaction_required"
          ) {
            req.session.anonymous = true;
            // Setting a 'short' cookie max age so we re-authenticate soon
            req.session.cookie.maxAge = anonymousCookieMaxAge;
            return res.redirect(nextUrl);
            // eslint-disable-next-line no-else-return
          } else {
            // TODO show error_description on error page?
          }
        }

        passport.authenticate("oidcSilent", {
          successRedirect: nextUrl,
          failureRedirect,
        })(req, res, next);
      });
    }

    // ***************************
    // Logout setup
    // ***************************

    if (
      this.isCallbackConfigured(
        "logout",
        callbackLogoutUrl,
        appCallbackLogoutUrl
      )
    ) {
      /**
       * @method
       * @name logout
       *
       * @param {Object} req - Express request object
       * @param {Object} res - Express response object
       *
       * @summary Check if the user it authenticated or else redirect to OpenID Connect server
       * for authentication
       *
       * @example oidc.login
       */
      OIDC.prototype.logout = async (req, res) => {
        const id_token_hint = req.session["_id_token"];
        const client = await oidcClient;
        res.redirect(client.endSessionUrl({ id_token_hint }));
      };

      expressApp.get(appCallbackLogoutUrl, async (req, res, next) => {
        // clears the id token from the local storage
        delete req.session._id_token;
        // clears the persisted user from the local storage
        req.logout();
        res.redirect(defaultRedirect);
      });
    }

    // ***************************
    // Utils functions
    // ***************************

    /**
     * @method
     * @name requireRole
     * @api public
     *
     * @param {Array.<string>} roles - Array of roles to be compared with the ones on the req.user object
     *
     * @summary Express Middleware that checks if the req.user has this/these roles.
     *
     * @returns {Promise.<Middleware>} Promise which resolves to a Express middleware
     *
     * A role is a property found on the user object and has most
     * likely been added through the internal createUser function. @see {constructor}
     *
     * @example
     * requireRole('isAdmin', 'isEditor')
     */

    OIDC.prototype.requireRole = (...roles) => (req, res, next) => {
      const user = req.user || {};

      // Check if we have any of the roles passed
      const hasAuthorizedRole = roles.reduce(
        (prev, curr) => prev || user[curr],
        false
      );
      // If we don't have one of these then access is forbidden
      if (!hasAuthorizedRole) {
        const error = new Error("Forbidden");
        error.status = 403;
        return next(error);
      }
      return next();
    };
  }
}

module.exports = OIDC;
