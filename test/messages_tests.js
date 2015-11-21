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

var lib = require('../lib/messages.js');

exports.testInterface = function(t) {
  t.equals(typeof lib, 'object', 'library exports an object');

  // Message creation functions
  t.equal(typeof lib.createServerIdent, 'function',
    'should have a createServerIdent function');
  t.equal(typeof lib.createKexInit, 'function',
    'should have a createKexInit function');
  t.equal(typeof lib.parseKexInit, 'function',
    'should have a parseKexInit function');
  t.equal(typeof lib.createDisconnect, 'function',
    'should have a createDisconnect function');
  t.equal(typeof lib.createNewKeys, 'function',
    'should have a createNewKeys function');
  t.equal(typeof lib.parseKexdhInit, 'function',
    'should have a parseKexdhInit function');
  t.equal(typeof lib.createKexdhReply, 'function',
    'should have a createKexdhReply function');
  t.done();
};

exports.serverIdentCreation = {
  setUp: function(cb) {
    this.swVersion = 'SWVER';
    this.comment = 'COMMENT';
    cb();
  },

  throwsWithNoSwVersion: function(t) {
    t.throws(lib.createServerIdent);
    t.done();
  },

  testWithArguments: function(t) {
    t.equals(lib.createServerIdent(this.swVersion, this.comment).toString(),
      'SSH-2.0-SWVER COMMENT\r\n',
      'version string should be \'SSH-2.0-SWVER COMMENT\\r\\n\'');
    t.done();
  },

  testWithoutComment: function(t) {
    t.equals(lib.createServerIdent(this.swVersion).toString(),
      'SSH-2.0-SWVER\r\n',
      'version string should be \'SSH-2.0-SWVER\\r\\n\'');
    t.done();
  },

  testWithEmptyComment: function(t) {
    t.equals(lib.createServerIdent(this.swVersion, '').toString(),
      'SSH-2.0-SWVER\r\n',
      'version string should be \'SSH-2.0-SWVER\\r\\n\'');
    t.done();
  }
};

exports.kexInitCreation = {
  setUp: function(cb) {
    cb();
  },

  testArguments: function(t) {
    t.throws(lib.createKexInit, /cookie is a required argument/);
    t.throws(function() {
      lib.createKexInit("asdf");
    }, /cookie must be a Buffer/);

    t.throws(function() {
      lib.createKexInit(new Buffer(15));
    }, /cookie must be at least 16 bytes/);

    t.throws(function() {
      lib.createKexInit(new Buffer(16));
    }, /opts is a required argument/);

    testKexInitAlgorithms(t, 'kexAlgorithms');
    testKexInitAlgorithms(t, 'serverKeyAlgorithms');
    testKexInitAlgorithms(t, 'clientEncryptionAlgorithms');
    testKexInitAlgorithms(t, 'serverEncryptionAlgorithms');
    testKexInitAlgorithms(t, 'clientMacAlgorithms');
    testKexInitAlgorithms(t, 'serverMacAlgorithms');
    testKexInitAlgorithms(t, 'clientCompressionAlgorithms');
    testKexInitAlgorithms(t, 'serverCompressionAlgorithms');

    t.done();
  },

  testMessageNum: function(t) {
    var opts = defaultKexInitOpts();
    var actual = lib.createKexInit(new Buffer(16), opts);
    t.equal(actual[0], 20);
    t.done();
  },

  testCookie: function(t) {
    var opts = defaultKexInitOpts();
    var cookie = new Buffer([
      0x86, 0xa6, 0x94, 0x2a,
      0xf8, 0x3a, 0xe8, 0x7a,
      0x37, 0x45, 0x7e, 0x71,
      0xcc, 0xbd, 0xba, 0x6f
    ]);

    var actual = lib.createKexInit(cookie, opts);
    t.equal(actual.toString('binary', 1, 17), cookie.toString('binary'));
    t.done();
  },

  testKexAlgorithms: function(t) {
    var opts = defaultKexInitOpts();
    opts.kexAlgorithms = [
      'diffie-hellman-group1-sha1',
      'diffie-hellman-group14-sha1'
    ];
    var expected = new Buffer([
      0x00, 0x00, 0x00, 0x36, 0x64, 0x69, 0x66, 0x66,
      0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d,
      0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70,
      0x31, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x2c, 0x64,
      0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65,
      0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72,
      0x6f, 0x75, 0x70, 0x31, 0x34, 0x2d, 0x73, 0x68,
      0x61, 0x31
    ]);

    var actual = lib.createKexInit(new Buffer(16), opts);
    t.deepEqual(actual.slice(17, expected.length + 17), expected);
    t.done();
  },

  testFirstPacketFollows: function(t) {
    var opts = defaultKexInitOpts();
    var cookie = new Buffer(16);
    cookie.fill(1);

    opts.firstPacketFollows = undefined;
    var actual = lib.createKexInit(cookie, opts);
    t.equal(actual[57], 0);

    opts.firstPacketFollows = false;
    actual = lib.createKexInit(cookie, opts);
    t.equal(actual[57], 0);

    opts.firstPacketFollows = {};
    actual = lib.createKexInit(cookie, opts);
    t.equal(actual[57], 1);

    opts.firstPacketFollows = true;
    actual = lib.createKexInit(cookie, opts);
    t.equal(actual[57], 1);

    t.done();
  },

  testReservedBytes: function(t) {
    var opts = defaultKexInitOpts();
    var cookie = new Buffer(16);
    cookie.fill(8);

    var actual = lib.createKexInit(cookie, opts);
    t.equal(actual.readUInt32BE(58), 0);
    t.done();
  }
};

exports.kexInitParsing = {
  setUp: function(cb) {
    cb();
  },

  testKexAlgorithms: function(t) {
    var expected = [
      'diffie-hellman-group1-sha1',
      'diffie-hellman-group14-sha1'
    ];
    var zeroes = new Buffer(41);
    zeroes.fill(0);

    var message = Buffer.concat([
      zeroes.slice(0, 17),
      new Buffer([
        0x00, 0x00, 0x00, 0x36, 0x64, 0x69, 0x66, 0x66,
        0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d,
        0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70,
        0x31, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x2c, 0x64,
        0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65,
        0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72,
        0x6f, 0x75, 0x70, 0x31, 0x34, 0x2d, 0x73, 0x68,
        0x61, 0x31
      ]),
      zeroes
    ], 116);

    var kexinit = lib.parseKexInit(message);
    t.deepEqual(kexinit.kexAlgorithms, expected);
    t.done();
  },

  testFirstPacketFollows: function(t) {
    var message = new Buffer(62);
    message.fill(0);

    var kexinit = lib.parseKexInit(message);
    t.strictEqual(kexinit.firstPacketFollows, false);

    message[57] = 1;
    kexinit = lib.parseKexInit(message);
    t.strictEqual(kexinit.firstPacketFollows, true);
    t.done();
  },

  testReservedByte: function(t) {
    var message = new Buffer(62);
    message.fill(0);
    message[58] = 0x09;

    var kexinit = lib.parseKexInit(message);
    t.strictEqual(kexinit.reserved, 0x09000000);
    t.done();
  }
};

exports.disconnectCreation = {
  testCreateDisconnect: function(t) {
    var expected = new Buffer([1]).toString('binary');
    var actual = lib.createDisconnect();
    t.equal(actual.toString('binary'), expected);
    t.done();
  }
};

exports.newKeysCreation = {
  testCreateNewKeys: function(t) {
    var expected = new Buffer([21]).toString('binary');
    var actual = lib.createNewKeys();
    t.equal(actual.toString('binary'), expected);
    t.done();
  }
};

exports.kexdhInitParsing = {
  throwsWithBadMessageId: function(t) {
    t.throws(function() {
      lib.parseKexdhInit(new Buffer([0x0F, 0x00, 0x00, 0x00, 0x00]));
    }, /message id 15/);
    t.done();
  },

  parsesMSBValue: function(t) {
    var message = new Buffer([0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
    var expected = new Buffer([0x80]);
    var actual = lib.parseKexdhInit(message);
    t.deepEqual(actual, expected);
    t.done();
  },

  parsesNegativeValue: function(t) {
    var message = new Buffer([0x1e, 0x00, 0x00, 0x00, 0x02, 0xed, 0xcc]);
    var expected = new Buffer([0xed, 0xcc]);
    var actual = lib.parseKexdhInit(message);
    t.deepEqual(actual, expected);
    t.done();
  },

  parsesZeroValue: function(t) {
    var message = new Buffer([0x1e, 0x00, 0x00, 0x00, 0x00]);
    var expected = new Buffer(0);
    var actual = lib.parseKexdhInit(message);
    t.deepEqual(actual, expected);
    t.done();
  }
};

exports.kexdhReplyCreation = {
  setUp: function(cb) {
    this._hostKey = new Buffer('hostKey');
    this._exchangeValue = new Buffer([0x70]);
    this._signature = new Buffer('signature');
    this._keyLen = this._hostKey.length;
    this._valLen = this._exchangeValue.length;
    this._sigLen = this._signature.length;
    cb();
  },

  testArguments: function(t) {
    var self = this;
    t.throws(lib.createKexdhReply, /hostKey is a required argument/);

    t.throws(function() {
      lib.createKexdhReply(self._hostKey);
    }, /exchangeValue is a required argument/);

    t.throws(function() {
      lib.createKexdhReply(self._hostKey, self._exchangeValue);
    }, /signature is a required argument/);

    t.done();
  },

  testMessageNum: function(t) {
    var actual = lib.createKexdhReply(this._hostKey, this._exchangeValue,
      this._signature);
    t.equal(actual[0], 31);
    t.done();
  },

  testHostKey: function(t) {
    var actual = lib.createKexdhReply(this._hostKey, this._exchangeValue,
      this._signature);
    var expected = new Buffer(4 + this._keyLen);
    expected.writeUInt32BE(this._keyLen, 0);
    this._hostKey.copy(expected, 4);

    t.deepEqual(actual.slice(1, this._keyLen + 5), expected);
    t.done();
  },

  testExchangeValue: function(t) {
    var actual = lib.createKexdhReply(this._hostKey, this._exchangeValue,
      this._signature);
    var offset = 1 + 4 + this._keyLen;
    var expected = new Buffer(4 + this._valLen);
    expected.writeUInt32BE(this._valLen, 0);
    this._exchangeValue.copy(expected, 4);

    t.deepEqual(actual.slice(offset, offset + 4 + this._valLen), expected);
    t.done();
  },

  testSignature: function(t) {
    var actual = lib.createKexdhReply(this._hostKey, this._exchangeValue,
      this._signature);
    var offset = 1 + 4 + this._keyLen + 4 + this._valLen;
    var expected = new Buffer(4 + this._sigLen);
    expected.writeUInt32BE(this._sigLen, 0);
    this._signature.copy(expected, 4);

    t.deepEqual(actual.slice(offset, offset + 4 + this._sigLen), expected);
    t.done();
  }
};

function defaultKexInitOpts() {
  return {
    kexAlgorithms: [],
    serverKeyAlgorithms: [],
    clientEncryptionAlgorithms: [],
    serverEncryptionAlgorithms: [],
    clientMacAlgorithms: [],
    serverMacAlgorithms: [],
    clientCompressionAlgorithms: [],
    serverCompressionAlgorithms: [],
    clientLanguages: [],
    serverLanguages: []
  };
}

function testKexInitAlgorithms(t, nameList) {
  var opts = defaultKexInitOpts();

  var invalidCharsAlg = '\x00';
  var tooLongAlg = new Buffer(128);
  tooLongAlg.fill('a');
  tooLongAlg = tooLongAlg.toString();

  t.throws(function() {
    opts[nameList] = [tooLongAlg];
    lib.createKexInit(new Buffer(16), opts);
  }, /0 is longer than 64/);

  t.throws(function() {
    opts[nameList] = ['valid', invalidCharsAlg];
    lib.createKexInit(new Buffer(16), opts);
  }, /1 contains invalid/);

  t.throws(function() {
    opts[nameList] = ['valid', 'alsovalid', ''];
    lib.createKexInit(new Buffer(16), opts);
  }, /2 is an empty string/);
}
