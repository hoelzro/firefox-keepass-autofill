/*

 Copyright (c) 2013 SMB Phone Inc.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are those
 of the authors and should not be interpreted as representing official policies,
 either expressed or implied, of the FreeBSD Project.

*/

// modified version of cifre.utils
var EXPORTED_SYMBOLS = ['Utils'];

var Utils = (function () {
  "use strict";

  function hex(val) {
    if (val >>> 0 !== val) { return "  "; }
    if (val < 0x10) { return "0" + val.toString(16); }
    return val.toString(16);
  }

  function ensureArray(buffer) {
    if (buffer instanceof Uint8Array) {
      return buffer;
    }
    if (buffer instanceof ArrayBuffer || Array.isArray(buffer)) {
      return new Uint8Array(buffer);
    }
    if (buffer.buffer instanceof ArrayBuffer) {
      return new Uint8Array(buffer.buffer);
    }
    throw new TypeError("Invalid buffer type " + buffer);
  }

  function fromhex(string) {
    var length = string.length;
    var array = new Uint8Array(length / 2);
    for (var i = 0; i < length; i += 2) {
      array[i / 2] = parseInt(string.substr(i, 2), 16);
    }
    return array;
  }

  function tohex(array) {
    var string = "";
    array = ensureArray(array);
    for (var i = 0, l = array.length; i < l; i++) {
      string += hex(array[i]);
    }
    return string;
  }

  // XXX can we do this with nsIScriptableUnicodeConverter?
  function stringToArray(string) {
    var length = string.length;
    var result = new Array(length);

    for(var i = 0; i < length; i++) {
        result[i] = string.charCodeAt(i);
    }
    return result;
  }

  return {
    dump: dump,
    tohex: tohex,
    fromhex: fromhex,
    stringToArray: stringToArray,
  };
})();
