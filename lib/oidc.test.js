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
  const claims = { username: 'jonsnow', unique_name: ['Jon Snow'], email: 'jonsnow@kth.se', memberOf: 'utveckling' }
  return OIDC.prototype.createUserFromClaims(claims).then(data => {
    expect(data).toEqual({
      displayName: 'Jon Snow',
      email: 'jonsnow@kth.se',
      memberOf: 'utveckling',
      username: 'jonsnow',
    })
  })
})

// test("should fetch users", () => {
//   const openIdClient = require("openid-client");
//   jest.mock("openIdClient");
//   openIdClient.Issuer.mockResolvedValue(new Promise());

//   const expressApp;
//   const passport;

//   const oidcImpl = new OIDC(expressApp, passport, {});
// });
