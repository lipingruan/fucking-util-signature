'use strict';

const sha256Src = require('./src');

module.exports = sha256;

function sha256(s) {

  return sha256Src(s).toUpperCase();
}