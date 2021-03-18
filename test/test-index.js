/* eslint-env mocha */
"use strict";

// Testing libraries
const expect = require("chai").expect;

// Import your module to test against.
const index = require("../index");

// Organize your tests in areas.
describe("Type of tests header", function() {
  // Use your tests as feature specification, that way
  // the test help with documenting the package, and
  // its intent. Giving a good overview when running tests.
  it("When running tests, expect the package to always work.", function() {
    expect(index.isWorking()).to.be.true;
  });
});
