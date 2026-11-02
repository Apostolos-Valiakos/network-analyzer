// Babel for the test run only: plain .js files and <script> blocks in .vue files.
const babelJest = require('babel-jest').default

module.exports = babelJest.createTransformer({
  babelrc: false,
  configFile: false,
  presets: [['@babel/preset-env', { targets: { node: 'current' } }]],
})
