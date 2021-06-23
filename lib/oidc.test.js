/**
 * OIDC.prototype.createUserFromClaims
 * OIDC.prototype.isCallbackConfigured
 * OIDC.prototype.verifyBasicConfiguration
 *
 */

const OIDC = require('./oidc')
test('should ', () => {
  expect(() => OIDC.prototype.verifyBasicConfiguration({ test: undefined })).toThrow()
})

test('extractDisplayName should return the same value if called with a string or with an array', () => {
  expect(OIDC.prototype.extractDisplayName(['Name'])).toBe('Name')

  expect(OIDC.prototype.extractDisplayName('Name')).toBe('Name')
})

test('should return false if no callback and appCallback provided', () => {
  expect(OIDC.prototype.isCallbackConfigured()).toBe(false)
})

test('should throw error if no callback provided', () => {
  expect(() => OIDC.prototype.isCallbackConfigured('login', () => {}, null)).toThrow()
})

test('should throw error if no callback provided', () => {
  expect(() => OIDC.prototype.isCallbackConfigured('login', null, () => {})).toThrow()
})

test('it creates user from claims', () => {
  const claims = { username: 'jonsnow', unique_name: ['Jon Snow'], email: 'jonsnow@kth.se', memberOf: ['utveckling'] }
  return OIDC.prototype.createUserFromClaims(claims).then(data => {
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
  return OIDC.prototype.createUserFromClaims(claims).then(data => {
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

  expect(OIDC.prototype.foundToolbarCookie(req)).toBeTrue()
})
test('it can decide if the current request was the first request to silent login ', () => {
  const appCookieName = 'appCookieName'
  const cookies = {
    '1-appCookieName': '1',
    '3-appCookieName': '3',
    strangeCookie: 'strange value',
    '2-appCookieName': '1',
  }

  expect(OIDC.prototype.isCurrentRequestTheFirstRequest(1, appCookieName, cookies)).toBeTrue()
})

// test("should fetch users", () => {
//   const openIdClient = require("openid-client");
//   jest.mock("openIdClient");
//   openIdClient.Issuer.mockResolvedValue(new Promise());

//   const expressApp;
//   const passport;

//   const oidcImpl = new OIDC(expressApp, passport, {});
// });
