const { Issuer, Strategy } = require('openid-client')
const { encrypt, decrypt } = require('./utils/crypto')

const {
  generators: { state },
} = require('openid-client')
const { config } = require('dotenv')

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
      return uniqueName[0]
    }

    return uniqueName
  }

  async createUserFromClaims(claims, extendUser = async () => {}) {
    const emailObject = claims.email ? { email: claims.email } : {}

    const memberOf = claims.memberOf ? [...claims.memberOf] : []

    const user = {
      username: claims.username,
      displayName: this.extractDisplayName(claims.unique_name), // An array. What to do .....
      ...emailObject, // This requires higher security clearance
      memberOf, // This requires higher security clearance
    }

    await Promise.resolve(extendUser(user, claims))

    return user
  }

  isCallbackConfigured(type, callback, appCallback) {
    if (callback && appCallback) {
      return true
    }

    if (!callback && !appCallback) {
      return false
    }

    if (!callback) {
      throw new Error(
        `A route (appCallback) for ${type} was found but no callback URL for the strategy. Bad configuration?`
      )
    }

    if (!appCallback) {
      throw new Error(
        `A callback (for the strategy) for ${type} was found but no route (appCallback) URL. Bad configuration?`
      )
    }
  }

  verifyBasicConfiguration(basicConfig) {
    const keys = Object.keys(basicConfig)

    keys.forEach(key => {
      if (!basicConfig[key]) {
        throw new Error(`OpenID Connect setup: Missing configuration for ${key}`)
      }
    })
  }

  foundToolbarCookie(req) {
    return req.cookies && Object.keys(req.cookies).includes('KTH_SSO_START')
  }

  commonLogInfo(req) {
    try {
      return `sessionID: ${req.sessionID && req.sessionID.substring(0, req.sessionID.length - 5)} User-agent: ${
        req.headers['user-agent']
      } Referer: ${req.get('Referrer')}`
    } catch (error) {
      // Let it go...
    }
  }

  /**
   * @name constructor
   * @api public
   *
   * @param {Object} expressApp The express app instance
   * @param {Object} passport The passport instance
   * @param {Object} config Configuration object
   * @param {string} config.configurationUrl Url to OpenID Connect server Example: https://myOpenIDServer.com/adfs/.well-known/openid-configuration
   * @param {string} config.clientId This apps clientID
   * @param {string} config.clientSecret This apps client secret
   * @param {string} config.tokenSecret This apps token secret, used for encrypting token for session storage
   * @param {string} config.callbackLoginUrl This apps full URL to callback function for standard login. Example: http://localhost:3000/node/auth/login/callback
   * @param {string} config.callbackLoginRoute The callback route used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/login/callback
   * @param {string} [config.callbackSilentLoginUrl] Optional This apps full URL to callback function for silent login. Example: http://localhost:3000/node/auth/silent/callback
   * @param {string} [config.callbackSilentLoginRoute] Optional The silent callback route used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/silent/callback
   * @param {string} [config.callbackLogoutUrl] Optional This apps full URL to callback function for logout. Example: http://localhost:3000/node/auth/logout/callback
   * @param {string} [config.callbackLogoutRoute] Optional The logout callback route used for setting up the express route. Same as config.callbackUrl without host. Example: /node/auth/logout/callback
   * @param {string} config.defaultRedirect Fallback if no next url is supplied to login or on logout
   * @param {function} [config.extendUser] Optional Function which gives you the possibility to add custom properties to the user object. The supplied function can be a async. Example: (user, claims) => { user.isAwesome = true } or async (user, claims) => { // do a api call }
   * @param {Object} [config.log] Optional Logger object which should have logging functions. Used for logging in this module. Example: logger.error('Error message')
   */

  constructor(
    expressApp,
    passport,
    {
      configurationUrl,
      clientId,
      clientSecret,
      tokenSecret,
      callbackLoginUrl,
      callbackLoginRoute,
      callbackSilentLoginUrl,
      callbackSilentLoginRoute,
      callbackLogoutUrl,
      callbackLogoutRoute,
      defaultRedirect,
      extendUser,
      log,
    }
  ) {
    this.verifyBasicConfiguration({
      configurationUrl,
      clientId,
      clientSecret,
      tokenSecret,
      defaultRedirect,
    })

    const thiz = this

    OIDC.prototype.logCall = (action, log, req, state, nextUrl) => {
      try {
        log.debug(
          `${action} ${this.commonLogInfo(req)} nextUrl: ${nextUrl} state: ${state} user: ${
            req.user && req.user.username
          }`
        )
      } catch (error) {
        // Let it go...
      }
    }

    OIDC.prototype.logEvent = (req, info) => {
      try {
        log.debug(`${info} ${this.commonLogInfo(req)}`)
      } catch (error) {
        // Let it go...
      }
    }

    OIDC.prototype.throwError = (req, info) => {
      throw new Error(`${info} ${this.commonLogInfo(req)}`)
    }

    const oidcClient = Issuer.discover(configurationUrl).then(
      provider =>
        new provider.Client({
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uris: [callbackLoginUrl], // The redirect url must be registered with ADFS!
          post_logout_redirect_uris: [callbackLogoutUrl], // The logout url must be registered with ADFS!
          usePKCE: 'S256',
          // response_types: ['code'], (default "code")
          // id_token_signed_response_alg (default "RS256")
          // token_endpoint_auth_method (default "client_secret_basic")
          token_endpoint_auth_method: 'client_secret_post',
        })
    )

    const redirectPropertyName = state => `${state}_redirect`

    // ***************************
    // Login setup
    // ***************************

    const loginIsConfigured = this.isCallbackConfigured('login', callbackLoginUrl, callbackLoginRoute)

    if (!loginIsConfigured) {
      throw new Error('Mandatory OIDC configuration for login. Bad configuration?')
    }

    /**
     * @summary Creates a openid-client Strategy
     * @returns {Promise<Strategy>} A promise which resolves to a openid-client configured strategy
     */
    const loginStrategy = new Promise(async (resolve, reject) => {
      const client = await oidcClient
      const loginStrategy = new Strategy(
        { client, passReqToCallback: true, usePKCE: 'S256' },
        (req, tokenSet, done) => {
          req.session['_id_token'] = encrypt(tokenSet.id_token, tokenSecret) // store id_token for logout
          this.createUserFromClaims(tokenSet.claims(), extendUser).then(user => {
            return done(null, user)
          })
        }
      )
      passport.use('oidc', loginStrategy)
      resolve(loginStrategy)
    })

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
      const strategyIsReady = await loginStrategy
      // eslint-disable-next-line no-shadow
      return ((req, res, next) => {
        if (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
          thiz.logEvent(req, 'User was already logged in when arriving at Silent Login. Forwarding with next()')
          return next()
        }

        if (req.method === 'HEAD') {
          thiz.logEvent(req, 'Login does not support method HEAD')
          return res.status(400).send('Login does not support method HEAD')
        }

        const newState = state()

        req.session[redirectPropertyName(newState)] = req.url

        thiz.logCall('Login', log, req, newState, req.url)

        return passport.authenticate('oidc', { state: newState })(req, res, next)
      })(req, res, next)
    }

    /**
     * Setup of express route. Callback route to be used by OpenID Connect server
     * for authentication
     *
     * On a successful authentication the user is redirected to the original url
     */
    expressApp.get(callbackLoginRoute, (req, res, next) => {
      const state = req.query.state
      const nextUrl = req.session[redirectPropertyName(state)]

      if (req.method === 'HEAD') {
        thiz.logEvent(req, 'Login callback: Login does not support method HEAD')
        return res.status(400).send('Login does not support method HEAD')
      }

      thiz.logCall('Login callback', log, req, state, nextUrl)

      if (!state) {
        thiz.throwError(req, 'Login callback: Missing required parameter: state')
      }

      if (!nextUrl) {
        thiz.logEvent(
          req,
          `Missing nextUrl. Current session is not the one that started the login. state: ${state} method: ${req.method}`
        )
        return res.status(400).send('Missing nextUrl. Current session is not the one that started the login.')
      }

      // This happens if the user presses "back" in the browser. Returns the user to the url it came from
      if (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
        return res.redirect(nextUrl)
      }

      passport.authenticate('oidc', {
        successRedirect: nextUrl,
      })(req, res, next)
    })

    // ***************************
    // Silent authentication setup
    // ***************************
    if (this.isCallbackConfigured('silent', callbackSilentLoginUrl, callbackSilentLoginRoute)) {
      const createSilentLoginStrategy = (client, callbackSilentLoginUrl, state) => {
        return new Strategy(
          {
            client,
            params: { prompt: 'none', redirect_uri: callbackSilentLoginUrl },
            passReqToCallback: true,
            usePKCE: 'S256',
            sessionKey: state,
          },
          (req, tokenSet, done) => {
            req.session['_id_token'] = encrypt(tokenSet.id_token, tokenSecret) // store id_token for logout

            this.createUserFromClaims(tokenSet.claims(), extendUser).then(user => {
              return done(null, user)
            })
          }
        )
      }

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
        const client = await oidcClient
        return ((req, res, next) => {
          if (req.method === 'HEAD') {
            thiz.logEvent(req, 'SilentLogin: Login does not support method HEAD')
            return res.status(400).send('Silent login does not support method HEAD')
          }

          if (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
            thiz.logEvent(req, 'SilentLogin: User was logged in when arriving at Silent Login. Forwarding with next()')
            return next()
          }

          const toolbarCookieFound = thiz.foundToolbarCookie(req)

          const numberOfTries = req.session.triedLogin ? req.session.triedLogin : 0

          thiz.logEvent(
            req,
            `SilentLogin: toolbarCookieFound: ${toolbarCookieFound} and numberOfTries: ${numberOfTries}`
          )

          if (!toolbarCookieFound) {
            thiz.logEvent(
              req,
              `SilentLogin: no toolbarCookieFound, but found these cookies: ${JSON.stringify(req.cookies)}`
            )
          }

          if (toolbarCookieFound && numberOfTries < 3) {
            const newState = state()

            req.session[redirectPropertyName(newState)] = req.url

            thiz.logCall('SilentLogin', log, req, newState, req.url)

            req.session.save(err => {
              if (err) {
                return next(err)
              }

              return passport.authenticate(createSilentLoginStrategy(client, callbackSilentLoginUrl, newState), {
                state: newState,
              })(req, res, next)
            })
          } else {
            return next()
          }
        })(req, res, next)
      }

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
      expressApp.get(callbackSilentLoginRoute, async (req, res, next) => {
        const client = await oidcClient

        if (req.method === 'HEAD') {
          thiz.logEvent(req, 'SilentLogin callback: Login does not support method HEAD')
          return res.status(400).send('Silent login callback does not support method HEAD')
        }

        const state = req.query.state

        if (!state) {
          thiz.throwError(req, 'SilentLogin callback: Missing required parameter: state')
        }

        const nextUrl = req.session[redirectPropertyName(state)]

        // On multiple simultaneous calls an earlier call could already have authenticated the user. Then there
        // is no need to authenticate again. It may even break the call due to how the openid-client library stores it validation in the session.
        // This could also happen if the user presses "back" in the browser. Returns the user to the url it came from, the nextUrl from the previous call
        if (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
          thiz.logCall('SilentLogin callback. Was already authenticated', log, req, state, nextUrl)
          return res.redirect(nextUrl)
        }

        if (req.query.error) {
          if (
            req.query.error === 'login_required' ||
            req.query.error === 'consent_required' ||
            req.query.error === 'interaction_required'
          ) {
            // State so we know how many times we tried, but failed
            req.session.triedLogin
              ? (req.session.triedLogin = req.session.triedLogin + 1)
              : (req.session.triedLogin = 1)
            thiz.logCall('SilentLogin callback. Is anonymous', log, req, state, nextUrl)
            return res.redirect(nextUrl)
          } else {
            return next(new Error(req.query.error))
          }
        }

        thiz.logCall('SilentLogin callback', log, req, state, nextUrl)

        // Check if session contains the req details
        if (req & req.session && req.session[state]) {
          return passport.authenticate(createSilentLoginStrategy(client, callbackSilentLoginUrl, state), {
            state,
            successRedirect: nextUrl,
          })(req, res, next)
        }
        thiz.logCall('Silent login error', err)
        thiz.logCall(
          'Expected authorization request details in session is missing',
          log,
          req,
          state,
          nextUrl,
          req.session[state],
          req.session[redirectPropertyName(state)]
        )
        return next()
      })
    } else {
      OIDC.prototype.silentLogin = () => Promise.reject(new Error('Not configured'))
    }

    // ***************************
    // Logout setup
    // ***************************

    if (this.isCallbackConfigured('logout', callbackLogoutUrl, callbackLogoutRoute)) {
      /**
       * @method
       * @name logout
       *
       * @param {Object} req - Express request object
       * @param {Object} res - Express response object
       *
       * @summary Express Middleware that logs out the user from both the OpenID Connect server and this app. Note: The user is redirected to the config.defaultRedirect after a successful logout.
       *
       * @returns {Promise<Middleware>} A promise which resolves to a middleware which logs out the current user
       *
       * @example oidc.logout
       */
      OIDC.prototype.logout = async (req, res) => {
        if (req.session['_id_token']) {
          const id_token_hint = decrypt(req.session['_id_token'], tokenSecret)
          const client = await oidcClient
          return res.redirect(client.endSessionUrl({ id_token_hint }))
        }

        // No OIDC Token stored in session? Lets just logout from this app
        return res.redirect(callbackLogoutRoute)
      }

      expressApp.get(callbackLogoutRoute, async (req, res, next) => {
        // clears the id token from the local storage
        delete req.session._id_token
        // clears the persisted user from the local storage
        req.logout()
        res.redirect(defaultRedirect)
      })
    } else {
      OIDC.prototype.logout = () => Promise.reject(new Error('Not configured'))
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
     * @returns {Middleware} A Express middleware
     *
     * A role is a property found on the user object and has most
     * likely been added through the optional extendUser function parameter. @see {config.extendUser}
     *
     * @example
     * oidc.requireRole('isAdmin', 'isEditor')
     */

    OIDC.prototype.requireRole =
      (...roles) =>
      (req, res, next) => {
        const user = req.user || {}

        // Check if we have any of the roles passed
        const hasAuthorizedRole = roles.reduce((prev, curr) => prev || user[curr], false)
        // If we don't have one of these then access is forbidden
        if (!hasAuthorizedRole) {
          const error = new Error('Forbidden')
          error.status = 403
          return next(error)
        }
        return next()
      }
  }
}

module.exports = OIDC
