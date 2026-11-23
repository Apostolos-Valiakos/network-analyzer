/**
 * Jest configuration for Nuxt 2 / Vue 2 frontend tests.
 *
 * Run from project root:
 *   npx jest --config tests/frontend/jest.config.js
 *
 * Notes
 * -----
 * - @vue/vue2-jest is the official Vue 2 transformer for Jest 27 and uses Babel 7.
 *   (vue-jest 3 compiled with Babel 6, which could not read this project's presets.)
 * - jest@27 ships jsdom bundled; no separate jest-environment-jsdom package is required.
 * - babel-transformer.js holds the Babel setup, so no root-level config is needed.
 */

const path = require('path')

const babelTransformer = path.resolve(__dirname, 'babel-transformer.js')

module.exports = {
  rootDir: '../../',
  testMatch: ['<rootDir>/tests/frontend/**/*.spec.js'],
  testEnvironment: 'jsdom',

  transform: {
    '^.+\\.vue$': '@vue/vue2-jest',
    '^.+\\.js$': babelTransformer,
  },

  moduleFileExtensions: ['js', 'json', 'vue'],

  // <script> blocks inside .vue files go through the same Babel setup
  globals: { 'vue-jest': { transform: { js: babelTransformer } } },

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
    'utils/**/*.js',
    'pages/**/*.vue',
    'components/**/*.vue',
    '!**/node_modules/**',
  ],
}
