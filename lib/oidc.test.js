/**
 * OIDC.prototype.createUserFromClaims
 * OIDC.prototype.isCallbackConfigured
 * OIDC.prototype.verifyBasicConfiguration
 *
 */

const {
  OIDC: OpenIDConnect,
  extractDisplayName,
  verifyBasicConfiguration,
  isCallbackConfigured,
  createUserFromClaims,
  foundToolbarCookie,
} = require('./oidc')

const configOptions = {
  configurationUrl: 'http://login.testserver.nu/adfs',
  clientId: '1234',
  clientSecret: 'abc',
  tokenSecret: 'secret',
  callbackLoginUrl: 'login',
  // callbackLoginRoute,
  // callbackSilentLoginUrl,
  // callbackSilentLoginRoute,
  // callbackLogoutUrl,
  // callbackLogoutRoute,
  defaultRedirect: 'http://localhost/hejsanhoppsan',
  // extendUser,
  // log,
}

describe(`OpenIDConnect class `, () => {
  test('Create OpenIDConnect with empty option should fail', async () => {
    try {
      const oidc = new OpenIDConnect(null, null, { configurationUrl: '' })
    } catch (err) {
      expect(err).toEqual(new Error('OpenID Connect setup: Missing configuration for configurationUrl'))
    }
  })
})

describe(`Helper functions tests`, () => {
  test('verifyBasicConfiguration ', () => {
    expect(() => verifyBasicConfiguration({ test: undefined })).toThrow()
  })

  test('extractDisplayName should return the same value if called with a string or with an array', () => {
    expect(extractDisplayName(['Name'])).toBe('Name')

    expect(extractDisplayName('Name')).toBe('Name')
  })

  test('should return false if no callback and appCallback provided', () => {
    expect(isCallbackConfigured()).toBe(false)
  })

  test('should throw error if no callback provided', () => {
    expect(() => isCallbackConfigured('login', () => {}, null)).toThrow()
  })

  test('should throw error if no callback provided', () => {
    expect(() => isCallbackConfigured('login', null, () => {})).toThrow()
  })

  test('it creates user from claims when user is member of two UG groups', () => {
    const claims = {
      username: 'jonsnow',
      unique_name: ['Jon Snow'],
      email: 'jonsnow@kth.se',
      memberOf: ['utveckling', 'förvaltning'],
    }
    return createUserFromClaims(claims).then(data => {
      expect(data).toEqual({
        displayName: 'Jon Snow',
        email: 'jonsnow@kth.se',
        memberOf: ['utveckling', 'förvaltning'],
        username: 'jonsnow',
      })
    })
  })
  test('it creates user from claims when user is member of one UG groups', () => {
    const claims = { username: 'jonsnow', unique_name: ['Jon Snow'], email: 'jonsnow@kth.se', memberOf: 'utveckling' }
    return createUserFromClaims(claims).then(data => {
      expect(data).toEqual({
        displayName: 'Jon Snow',
        email: 'jonsnow@kth.se',
        memberOf: ['utveckling'],
        username: 'jonsnow',
      })
    })
  })
  test('it creates user from claims without memberOf', () => {
    const claims = { username: 'jonsnow', unique_name: ['Jon Snow'], email: 'jonsnow@kth.se' }
    return createUserFromClaims(claims).then(data => {
      expect(data).toEqual({
        displayName: 'Jon Snow',
        email: 'jonsnow@kth.se',
        memberOf: [],
        username: 'jonsnow',
      })
    })
  })

  test('it can decide from the toolbar cookie if it should try to silently log in the user', () => {
    const req = {
      cookies: {
        cookie1: {},
        cookie2: {},
      },
    }
    const socialToolbarCookieName = 'KTH_SSO_START'
    req.cookies[socialToolbarCookieName] = {}

    expect(foundToolbarCookie(req)).toBe(true)
  })
})
