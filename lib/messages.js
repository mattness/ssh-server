// Copyright (c) Matt Gollob and other ssh-server contributors.
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// RFC 4253, Section 7.1 (Algorithm Negotiation)
var KEXINIT_COOKIE_SIZE = 16;

// RFC 4251, Section 6 (Algorithm and Method Naming)
var MAX_ALGORITHM_NAME_LENGTH = 64;

module.exports = {
  KEXINIT_COOKIE_SIZE: KEXINIT_COOKIE_SIZE,
  createServerIdent: _createServerIdent,
  createKexInit: _createKexInit,
  parseKexInit: _parseKexInit,
  createDisconnect: _createDisconnect,
  createNewKeys: _createNewKeys
};

var util = require('util');

// RFC 4253, Section 7.1 (Algorithm Negotiation)
var KEXINIT_COOKIE_SIZE = 16;

// RFC 4251, Section 6 (Algorithm and Method Naming)
var MAX_ALGORITHM_NAME_LENGTH = 64;

// Message Numbers
var SSH_MSG_DISCONNECT = 1;
var SSH_MSG_KEXINIT = 20;
var SSH_MSG_NEWKEYS = 21;

// constant messages
var disconnectMessage = new Buffer([SSH_MSG_DISCONNECT]);
var newKeysMessage = new Buffer([SSH_MSG_NEWKEYS]);

function _createServerIdent(swVersion, comment) {
  if (!swVersion) throw new Error('swVersion is a required argument');

  var buf = new Buffer(255);

  // Write the string, but save room for the crlf, we enforce the 255 char
  // limit by simply truncating the comment (or swversion if there is no
  // comment)
  var offset = buf.write(
    util.format('SSH-2.0-%s%s', swVersion, comment ? ' ' + comment : ''),
    0, buf.length - 2
  );
  offset += buf.write('\r\n', offset, 2);

  if (offset < buf.length)
    buf = buf.slice(0, offset);

  return buf;
}

function _createKexInit(cookie, opts) {
  if (!cookie) throw new Error('cookie is a required argument');
  if (!(cookie instanceof(Buffer))) throw new Error('cookie must be a Buffer');
  if (cookie.length < KEXINIT_COOKIE_SIZE) {
    throw new Error('cookie must be at least ' + KEXINIT_COOKIE_SIZE + ' bytes');
  }

  if (!opts) throw new Error('opts is a required argument');
  opts.kexAlgorithms.forEach(_validateAlgorithmName);
  opts.serverKeyAlgorithms.forEach(_validateAlgorithmName);
  opts.clientEncryptionAlgorithms.forEach(_validateAlgorithmName);
  opts.serverEncryptionAlgorithms.forEach(_validateAlgorithmName);
  opts.clientMacAlgorithms.forEach(_validateAlgorithmName);
  opts.serverMacAlgorithms.forEach(_validateAlgorithmName);
  opts.clientCompressionAlgorithms.forEach(_validateAlgorithmName);
  opts.serverCompressionAlgorithms.forEach(_validateAlgorithmName);

  var nameLists = [
    _buildNameList(opts.kexAlgorithms),
    _buildNameList(opts.serverKeyAlgorithms),
    _buildNameList(opts.clientEncryptionAlgorithms),
    _buildNameList(opts.serverEncryptionAlgorithms),
    _buildNameList(opts.clientMacAlgorithms),
    _buildNameList(opts.serverMacAlgorithms),
    _buildNameList(opts.clientCompressionAlgorithms),
    _buildNameList(opts.serverCompressionAlgorithms),
    _buildNameList(opts.clientLanguages || []),
    _buildNameList(opts.serverLanguages || [])
  ];

  var nameListslength = nameLists.reduce(function(len, listBuf) {
    return len + listBuf.length;
  }, 0);

  // RFC 4253, Section 7.1 (Algorithm Negotiation)
  var kexinitSize = 1 + // Message number byte
    KEXINIT_COOKIE_SIZE + // cookie
    nameListslength +
    1 + // first_kex_packet_follows flag
    1; // reserved byte

  var buf = new Buffer(kexinitSize);
  buf.writeUInt8(SSH_MSG_KEXINIT, 0);
  cookie.copy(buf, 1);

  var offset = KEXINIT_COOKIE_SIZE + 1;
  nameLists.forEach(function(listBuf) {
    listBuf.copy(buf, offset);
    offset += listBuf.length;
  });

  buf.writeUInt8(!!opts.firstPacketFollows ? 1 : 0, offset);
  buf.writeUInt8(0, offset + 1);

  return buf;
}

function _parseKexInit(message) {
  var result = {
    kexAlgorithms: [],
    serverKeyAlgorithms: [],
    clientEncryptionAlgorithms: [],
    serverEncryptionAlgorithms: [],
    clientMacAlgorithms: [],
    serverMacAlgorithms: [],
    clientCompressionAlgorithms: [],
    serverCompressionAlgorithms: [],
    clientLanguages: [],
    serverLanguages: [],
    firstPacketFollows: false,
    reserved: 0
  };

  var offset = 1 + KEXINIT_COOKIE_SIZE; // SSH_MSG_KEXINIT + cookie
  [
    'kexAlgorithms', 'serverKeyAlgorithms', 'clientEncryptionAlgorithms',
    'serverEncryptionAlgorithms', 'clientMacAlgorithms', 'serverMacAlgorithms',
    'clientCompressionAlgorithms', 'serverCompressionAlgorithms',
    'clientLanguages', 'serverLanguages'
  ].forEach(function(item) {
    var nameList = _parseNameList(message, offset);
    offset += nameList.byteLength;
    delete nameList.byteLength;
    result[item] = nameList;
  });

  result.firstPacketFollows = message.readUInt8(offset) !== 0;
  result.reserved = message.readUInt8(offset + 1);

  return result;
}

function _createDisconnect() { return disconnectMessage; }
function _createNewKeys() { return newKeysMessage; }

function _validateAlgorithmName(algorithm, index) {
  if (algorithm.length > MAX_ALGORITHM_NAME_LENGTH) {
    throw new Error(util.format(
      'Algorithm name \'%s\' at index %d is longer than %d characters',
      algorithm,
      index,
      MAX_ALGORITHM_NAME_LENGTH
    ));
  }

  if (algorithm.trim().length < 1) {
    throw new Error(util.format('Algorithm at index %d is an empty string',
      index));
  }

  if (/[\x00-\x1F\x7F-\xFF]/.test(algorithm)) {
    throw new Error(util.format(
      'Algorithm name \'%s\' at index %d contains invalid characters',
      algorithm,
      index
    ));
  }
}

function _buildNameList(arr) {
  var str = arr.join(',');
  var len = Buffer.byteLength(str);

  var buf = new Buffer(4 + len);
  buf.writeUInt32BE(len, 0);
  buf.write(str, 4, len);

  return buf;
}

function _parseNameList(buffer, offset) {
  var length = buffer.readUInt32BE(offset);
  offset += 4;

  var nameList = length === 0 ? [] :
    buffer.slice(offset, offset + length).toString().split(',');

  nameList.byteLength = 4 + length;

  return nameList;
}
