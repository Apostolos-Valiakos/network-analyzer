/**
 * Jest configuration for Nuxt 2 / Vue 2 frontend tests.
 *
 * Install test dependencies once (from the project root):
 *
 *   npm install --save-dev jest@27 babel-jest@27 @babel/core @babel/preset-env vue-jest@3 @vue/test-utils@1 vuex@3
 *
 * Run from project root:
 *   npx jest@27 --config tests/frontend/jest.config.js
 *
 * Notes
 * -----
 * - vue-jest@3 is used (not @4) because vue-jest@4 has a peer-dep conflict with babel-jest@27.
 * - jest@27 ships jsdom bundled; no separate jest-environment-jsdom package is required.
 * - Babel config is inlined below so no root-level babel.config.js is needed.
 */

module.exports = {
  rootDir: '../../',
  testMatch: ['<rootDir>/tests/frontend/**/*.spec.js'],
  testEnvironment: 'jsdom',

  transform: {
    '^.+\\.vue$': '<rootDir>/node_modules/vue-jest',
    // Inline babel config — avoids root-level babel.config.js requirement
    '^.+\\.js$': ['babel-jest', {
      presets: [['@babel/preset-env', { targets: { node: 'current' } }]],
    }],
  },

  moduleFileExtensions: ['js', 'json', 'vue'],

  moduleNameMapper: {
    // Nuxt aliases: ~ and @ both resolve to project root
    '^[~@]/(.*)$': '<rootDir>/$1',
    // Stub CSS/image imports
    '\\.(css|scss|png|jpg|svg)$': '<rootDir>/tests/frontend/__mocks__/fileMock.js',
  },

  // Inject process.env values used by components
  setupFiles: ['<rootDir>/tests/frontend/setup.js'],

  // Coverage sources
  collectCoverageFrom: [
    'store/**/*.js',
    'plugins/**/*.js',
    'pages/**/*.vue',
    'components/**/*.vue',
    '!**/node_modules/**',
  ],
}
