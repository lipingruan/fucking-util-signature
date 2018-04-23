'use strict';

const md5Src = require('./src');

module.exports = md5;

function md5(s) {

  return md5Src(s).toUpperCase();
}