'use strict';

const { Erorr, Extend, Type } = require ( './util' );

const md5 = require('./md5');
const sha256 = require('./sha256');

const signIgnoreArr = ['sign', 'signKey'];

module.exports = Signature;

function Signature() {}

Signature.verify     = verify;
Signature.verifyJSON = verifyJSON;
Signature.sign       = sign;
Signature.signJSON   = signJSON;
Signature.md5        = md5;
Signature.sha256     = sha256;

function signJSON(data, key) {

  let { signType } = data;

  if (signType === 'MD5') {

    return Signature.sign(data, key, md5);
  } else if (signType === 'SHA256') {

    return Signature.sign(data, key, sha256);
  } else {

    throw Erorr(`Not Support Sign Type [${signType}]`, '[Signature signJSON]');
  }
}

function verifyJSON(data, key) {

  let { signType } = data;

  if (signType === 'MD5') {

    return Signature.verify(data, key, md5);
  } else if (signType === 'SHA256') {

    return Signature.verify(data, key, sha256);
  } else  {

    throw Erorr(`Not Support Sign Type [${signType}]`, '[Signature verifyJSON]');
  }
}

function verify(source, skey, method) {

  let signInfo = sign(source, skey, method);

  let sourceStr = '';

  if (Type.object(source)) {

    return signInfo.sign === source.sign;
  } else {

    sourceStr = String(source);
  }

  return sourceStr === signInfo.urlStr;
}

function sign(source, skey, method) {

  if (Type.object(source)) {

    let keyValArr = [];

    keyValArr = objToUrlKeyValArr(source, signIgnoreArr);

    let signStr = '';

    if (skey) {

      signStr = keyValArr.concat(mixKeyVal('signKey', skey)).join('&');
    } else {

      signStr = keyValArr.join('&');
    }

    let signVal = method(signStr);

    let urlStr  = keyValArr.concat(mixKeyVal('sign', signVal)).join('&');

    return {urlStr: urlStr, sign: signVal};
  } else {

    return signString(String(source), skey);
  }
}

function signString(source, skey) {

  /* check urlStr */

  let sourceObj = urlStrToObj(source, signIgnoreArr);

  return sign(sourceObj, skey);
}

function mixKeyVal(key, val) {

  /* [BUG] JSON.stringify => circle refrence */
  let _val = Type.object(val) ? JSON.stringify(val) : String(val);

  return [key, encodeURIComponent(_val)].join('=');

  // return [key, _val].join('=');
}

function splitKeyVal(keyValStr) {

  let keyVal = keyValStr.split('=');

  return [keyVal[0], decodeURIComponent(keyVal[1])];

  // return keyVal;
}

// object to Url 'key=val' Array
function objToUrlKeyValArr(source, ignoreArr) {

  let keyValArr = [];

  let keys = Object.keys(source);

  keys.sort(function(k1, k2) { return k1.localeCompare(k2) });

  for (let key of keys) {

    // ignore [sign & signKey]

    if (!ignoreArr || ignoreArr.indexOf(key) === -1) {

      let keyValStr = mixKeyVal(key, source[key]);

      keyValArr.push(keyValStr);
    }
  }

  return keyValArr;
}

function urlStrToObj(source, ignoreArr) {

  let keyValArr = source.split('&');

  let sourceObj = {};

  for (let keyValStr of keyValArr) {

    let keyVal = splitKeyVal(keyValStr);

    let key = keyVal[0],
        val = keyVal[1];

    if (!ignoreArr || ignoreArr.indexOf(key) === -1) {

      sourceObj[key] = val;
    }
  }

  return sourceObj;
}

function objToUrlStr(source, ignoreArr) {

  let keyValArr = objToUrlKeyValArr(source, ignoreArr);

  return keyValArr.join('&');
}