/**
 * OIDC.prototype.createUserFromClaims
 * OIDC.prototype.isCallbackConfigured
 * OIDC.prototype.verifyBasicConfiguration
 *
 */

const OIDC = require("./oidc");
test("should ", () => {
  expect(() =>
    OIDC.prototype.verifyBasicConfiguration({ test: undefined })
  ).toThrow();
});

// test("should fetch users", () => {
//   const openIdClient = require("openid-client");
//   jest.mock("openIdClient");
//   openIdClient.Issuer.mockResolvedValue(new Promise());

//   const expressApp;
//   const passport;

//   const oidcImpl = new OIDC(expressApp, passport, {});
// });
