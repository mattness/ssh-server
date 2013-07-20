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

var PassThrough = require('stream').PassThrough;
var crypto = require('crypto');
var SshOutputStream = require('../outputStream');

exports.testInterface = function(t) {
  var stream = new SshOutputStream();

  // Writeable Side Stream Methods
  t.equal(typeof stream.write, 'function', 'should have a write function');
  t.equal(typeof stream.end, 'function', 'should have an end function');

  // Readable Side Stream Methods
  t.equal(typeof stream.setEncoding, 'function', 'should have a setEncoding function');
  t.equal(typeof stream.read, 'function', 'should have a read function');
  t.equal(typeof stream.pipe, 'function', 'should have a pipe function');
  t.equal(typeof stream.unpipe, 'function', 'should have an unpipe function');

  // SSH Protocol Implementation
  t.equal(typeof stream.setMac, 'function', 'should have a setMac function');

  t.done();
};

exports.basicWriting = {
  setUp: function(cb) {
    this.stream = new SshOutputStream();
    this.payload = new Buffer(18);
    this.payload.fill(1);
    cb();
  },

  testPacketLength: function(t) {
    var self = this;

    t.expect(2);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.ok(packet.length >= self.payload.length + 5 + 4, // 5 header 4 padding
        'packet length should be at least 9 bytes longer than the payload');
      t.equal(packet.length % 8, 0, 'packet length should be a multiple of 8');
    });

    this.stream.end(this.payload);
  },

  testPadding: function(t) {
    var self = this;

    t.expect(1);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.equal(packet[4], 9, 'padding size should be 9');
    });

    this.stream.end(this.payload);
  },

  testSequenceTracking: function(t) {
    var self = this;

    t.expect(2);
    this.stream.once('readable', this.stream.read);
    this.stream.on('end', function() {
      t.equal(self.stream._sequence, 1, 'sequence number should be 1');
      t.done();
    });

    t.equal(this.stream._sequence, 0, 'sequence number should start at 0');
    this.stream.end(this.payload);
  },

  testSequenceWrapping: function(t) {
    var self = this;

    t.expect(1);
    this.stream.once('readable', this.stream.read);
    this.stream.on('end', function() {
      t.equal(self.stream._sequence, 0, 'sequence number should wrap around to 0');
      t.done();
    });

    this.stream._sequence = Math.pow(2, 32) - 1;
    this.stream.end(this.payload);
  }
};

exports.macWriting = {
  setUp: function(cb) {
    this.stream = new SshOutputStream();
    this.payload = new Buffer(18);
    this.payload.fill(1);
    this.macAlgorithm = 'sha1';
    this.macKey = new Buffer('my hmac secret key!!');
    cb();
  },

  testSettingMac: function(t) {
    this.stream._packetsRemaining = 1;
    this.stream.setMac(this.macAlgorithm, this.macKey);
    t.equal(this.stream._packetsRemaining, Math.pow(2, 31),
      'setting mac should reset packetsRemaining');

    this.stream.setMac();
    t.equal(this.stream._packetsRemaining, Math.pow(2, 31),
      'calling with no arguments should reset packetsRemaining');
    t.done();
  },

  testMac: function(t) {
    var self = this;

    t.expect(22);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      var actualMac = packet.slice(-20);
      t.equal(packet.length, self.payload.length + 5 + 9 + 20,
        // 18 payload + 5 header + 9 padding + 20 mac = 52
        'packet length should be 52');

      var hmac = require('crypto').createHmac(self.macAlgorithm, self.macKey);
      hmac.end(Buffer.concat([new Buffer([0,0,0,0]), packet.slice(0, -20)]));
      hmac.on('readable', function() {
        var expectedMac = new Buffer(hmac.read());

        t.equal(actualMac.length, expectedMac.length, 'lengths should match');
        for (var i = 0; i < expectedMac.length; i++) {
          t.equal(actualMac[i], expectedMac[i], 'byte ' + i + 'should match');
        }
      });
    });

    this.stream.setMac(this.macAlgorithm, this.macKey);
    this.stream.end(this.payload);
  }
};

exports.crypto = {
  setUp: function(cb) {
    this.stream = new SshOutputStream();
    this.payload = new Buffer(18);
    this.payload.fill(1);
    this.cryptoKey = new Buffer([
      0x51, 0xad, 0x46, 0x80, 0x8a, 0xad, 0x48, 0x18,
      0xd1, 0x36, 0x03, 0x0e, 0x32, 0xee, 0x16, 0x72,
      0xf1, 0x9a, 0xdc, 0x67, 0xf7, 0x77, 0x03, 0x8f,
      0x96, 0xf2, 0xca, 0x6d, 0x7b, 0x70, 0x35, 0x4b
    ]);
    this.cryptoIv = new Buffer([
      0x6b, 0xed, 0xeb, 0xb1,
      0x7f, 0xb5, 0x14, 0x96,
      0x6f, 0x06, 0x5e, 0x0b,
      0xb6, 0x02, 0x3c, 0x51
    ]);
    this.cipher = crypto.createCipheriv('aes-256-ctr', this.cryptoKey,
      this.cryptoIv);
    this.decipher = crypto.createDecipheriv('aes-256-ctr', this.cryptoKey,
      this.cryptoIv);
    this.cipherBlockSize = 16;
    cb();
  },

  testSettingCipher: function(t) {
    t.equal(this.stream._cipher, null, 'should start with no cipher');
    t.equal(this.stream._cipherBlockSize, 0, 'default blockSize should be 0');
    t.equal(this.stream._blocksRemaining, (Math.pow(1024, 3) / 8),
      'default blocks remaining should be 1 GiB / 8');

    this.stream.setCipher(this.cipher, this.cipherBlockSize);
    t.equal(this.stream._cipher, this.cipher,
      'sane arguments should be honored');
    t.equal(this.stream._cipherBlockSize, this.cipherBlockSize,
      'sane arguments should be honored');
    t.equal(this.stream._blocksRemaining,
      Math.pow(2, (this.cipherBlockSize * 2)),
      'sane arguments should set blocksRemaining to 2**(L/4)');

    this.stream.setCipher('garbage', 19);
    t.equal(this.stream._cipher, this.cipher,
      'insane arguments should be ignored');
    t.equal(this.stream._cipherBlockSize, this.cipherBlockSize,
      'insane arguments should be ignored');
    t.equal(this.stream._blocksRemaining,
      Math.pow(2, (this.cipherBlockSize * 2)),
      'insane arguments should not reset blocksRemaining');

    this.stream.setCipher();
    t.equal(this.stream._cipher, null,
      'calling with no arguments should clear cipher');
    t.equal(this.stream._cipherBlockSize, 0,
      'calling with no arguments should reset blockSize to 0');
    t.equal(this.stream._blocksRemaining, (Math.pow(1024, 3) / 8),
      'calling with no arguments should reset blocks remaining to 1 GiB / 8');
    t.done();
  },

  testPacketLength: function(t) {
    var self = this;

    t.expect(1);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.equal(packet.length % self.cipherBlockSize, 0,
        'packet length should be a multiple of cipherBlockSize');
    });

    this.stream.setCipher(this.cipher, this.cipherBlockSize);
    this.stream.end(this.payload);
  },

  testPadding: function(t) {
    var self = this;

    t.expect(1);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      packet = self.decipher.update(packet);
      t.equal(packet[4], 9, 'padding size should be 9');
    });

    this.stream.setCipher(this.cipher, this.cipherBlockSize);
    this.stream.end(this.payload);
  },

  testEncryption: function(t) {
    var self = this;

    t.expect(2);
    this.stream.on('end', t.done);
    this.stream.on('readable', function() {
      var packet = self.stream.read();
      t.notEqual(packet.slice(5, self.payload.length + 5).toString('binary'),
        self.payload.toString('binary'), 'payload should be incomprehensible');

      packet = self.decipher.update(packet);
      t.equal(packet.slice(5, self.payload.length + 5).toString('binary'),
        self.payload.toString('binary'),
        'deciphered packet should reveal payload');
    });

    this.stream.setCipher(this.cipher, this.cipherBlockSize);
    this.stream.end(this.payload);
  }
};

exports.rekeying = {
  setUp: function(cb) {
    this.stream = new SshOutputStream();
    this.payload = new Buffer(18);
    this.payload.fill(1);
    this.cryptoKey = new Buffer([
      0x51, 0xad, 0x46, 0x80, 0x8a, 0xad, 0x48, 0x18,
      0xd1, 0x36, 0x03, 0x0e, 0x32, 0xee, 0x16, 0x72,
      0xf1, 0x9a, 0xdc, 0x67, 0xf7, 0x77, 0x03, 0x8f,
      0x96, 0xf2, 0xca, 0x6d, 0x7b, 0x70, 0x35, 0x4b
    ]);
    this.cryptoIv = new Buffer([
      0x6b, 0xed, 0xeb, 0xb1,
      0x7f, 0xb5, 0x14, 0x96,
      0x6f, 0x06, 0x5e, 0x0b,
      0xb6, 0x02, 0x3c, 0x51
    ]);
    this.cipher = crypto.createCipheriv('aes-256-ctr', this.cryptoKey,
      this.cryptoIv);
    this.decipher = crypto.createDecipheriv('aes-256-ctr', this.cryptoKey,
      this.cryptoIv);
    this.cipherBlockSize = 16;
    this.macAlgorithm = 'sha1';
    this.macKey = new Buffer('my hmac secret key!!');
    cb();
  },

  testMaxPackets: function(t) {
    this.stream.on('rekey_needed', t.done);
    this.stream.on('readable', this.stream.read);

    this.stream.setMac(this.macAlgorithm, this.macKey);
    this.stream.setCipher(this.cipher, this.cipherBlockSize);
    this.stream._packetsRemaining = 1;

    this.stream.end(this.payload);
  },

  testMaxXferBytes: function(t) {
    this.stream.on('rekey_needed', t.done);
    this.stream.on('readable', this.stream.read);

    this.stream.setMac(this.macAlgorithm, this.macKey);
    this.stream.setCipher(this.cipher, this.cipherBlockSize);
    this.stream._blocksRemaining = 1;

    this.stream.end(this.payload);
  }
};
