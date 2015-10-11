// Copyright 2014-2015 runtime.js project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

var lib = require('./resources').libsodium;

// Helper function to convert hex results into Uint8Arrays.
function hexToU8(hexStr) {
  var u8 = new Uint8Array(hexStr.length/2);
  for (var i = 0; i < (hexStr.length/2); i++) {
    u8[i] = parseInt(hexStr.substr(i*2, 2), 16);
  }
  return u8;
}

module.exports = {
  crypto_secretbox_easy: function(data, key) {
    var dataArr = data;

    if (typeof data === 'string') {
      dataArr = new Uint8Array(data.length);
      for (var i = 0; i < data.length; i++) {
        dataArr[i] = data.charCodeAt(i);
      }
    } else {
      throw new Error('crypto_secretbox_easy: data (argument 0) must be a string or Uint8Array.');
    }

    var nonceArr = runtime.random.getRandomValues(lib.crypto_constants().crypto_secretbox_NONCEBYTES);

    var cipher = lib.crypto_secretbox_easy(dataArr, key, nonceArr);
    if (!cipher) {
      throw new Error('crypto_secretbox_easy: error creating box.');
    }
    return {
      ciphertext: hexToU8(cipher),
      nonce: nonceArr
    };
  },
  crypto_secretbox_open_easy: function(cipherArr, key, nonceArr) {
    if (!cipherArr instanceof Uint8Array) {
      throw new Error('crypto_secretbox_open_easy: cipher data (argument 0) must be a Uint8Array.');
    }

    var decipher = lib.crypto_secretbox_open_easy(cipherArr, key, nonceArr);
    if (!decipher) {
      throw new Error('crypto_secretbox_open_easy: error decrypting box.');
    }
    return hexToU8(decipher);
  }
};

var justConvertHex = [
  {
    funcName: 'crypto_generichash',
    errorInfo: 'error calculating hash.'
  },
  {
    funcName: 'crypto_hash_sha256',
    errorInfo: 'error calculating hash.'
  },
  {
    funcName: 'crypto_hash_sha512',
    errorInfo: 'error calculating hash.'
  }
];

for (var i = 0; i < justConvertHex.length; i++) {
  (function(i) {
    module.exports[justConvertHex[i].funcName] = function(data) {
      var result = lib[justConvertHex[i].funcName](data);
      if (!result) {
        throw new Error(justConvertHex[i].funcName + ': ' + justConvertHex[i].errprInfo);
      }
      return hexToU8(result);
    }
  })(i);
}
