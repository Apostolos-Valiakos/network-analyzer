// Jest config for StrykerJS: the normal one with an absolute rootDir (Stryker
// resolves a relative one against its sandbox) and a testMatch without
// <rootDir>, which does not match inside Stryker's dot-folder sandbox.
const path = require('path')
module.exports = {
  ...require('./jest.config'),
  rootDir: path.resolve(__dirname, '..', '..'),
  testMatch: ['**/tests/frontend/**/*.spec.js'],
}
