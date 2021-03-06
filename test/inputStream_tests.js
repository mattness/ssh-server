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
var SshInputStream = require('../lib/inputStream');

exports.testInterface = function(t) {
  var stream = new SshInputStream();

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

exports.basicReading = {
  setUp: function(cb) {
    this.stream = new SshInputStream();
    this.payload = new Buffer(32);
    this.payload.writeUInt32BE(28, 0);  // Packet size
    this.payload.writeUInt8(9, 4);  // Padding Size
    this.payload.fill(1, 5, 23); // Payload bytes
    this.payload.fill(8, 23);  // Padding bytes
    cb();
  },

  testReading: function(t) {
    var self = this;

    t.expect(19);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.equal(packet.length, 18,
        'packet length should match original payload length');

      for (var i = 0; i < packet.length; i++) {
        t.equal(packet[i], 1, 'Packet byte ' + i + ' should be 1');
      }
    });

    this.stream.end(this.payload);
  },

  testReadingPartialPacket: function(t) {
    var self = this;

    t.expect(19);
    this.stream.on('end', t.done);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.equal(packet.length, 18,
        'packet length should match original payload length');

      for (var i = 0; i < packet.length; i++) {
        t.equal(packet[i], 1, 'Packet byte ' + i + ' should be 1');
      }
    });

    this.stream.write(this.payload.slice(0, 2));
    this.stream.write(this.payload.slice(2, 3));
    this.stream.write(this.payload.slice(3, 5));
    this.stream.end(this.payload.slice(5));
  },

  testReadingMultiplePackets: function(t) {
    var self = this;
    var count = 0;

    t.expect(39);
    this.stream.on('end', function A() {
      t.equal(count, 2, 'should read 2 total packets');
      t.done();
    });
    this.stream.on('readable', function B() {
      count++;
      var packet = self.stream.read();
      t.equal(packet.length, 18,
        'packet length should match original payload length');

      for (var i = 0; i < packet.length; i++) {
        t.equal(packet[i], 1, 'Packet byte ' + i + ' should be 1');
      }
    });

    this.stream.end(Buffer.concat([this.payload, this.payload]));
  }
};

exports.macReading = {
  setUp: function(cb) {
    this.stream = new SshInputStream();
    this.payload = new Buffer(52);
    this.payload.writeUInt32BE(28, 0);  // Packet size
    this.payload.writeUInt8(9, 4);  // Padding Size
    this.payload.fill(1, 5, 23); // Payload bytes
    this.payload.fill(8, 23);  // Padding bytes
    new Buffer([
      0xca, 0xfd, 0x0c, 0xb7, 0x2e,
      0x6a, 0xcb, 0x5a, 0xb9, 0x5d,
      0x94, 0xfe, 0xb9, 0x80, 0x07,
      0x30, 0x0e, 0x08, 0x7e, 0xe4
    ]).copy(this.payload, 32);
    this.macAlgorithm = 'sha1';
    this.macKey = new Buffer('my hmac secret key!!');
    this.stream.setMac(this.macAlgorithm, this.macKey);
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

    t.expect(19);
    this.stream.on('end', t.done);
    this.stream.on('error', t.ifError);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.equal(packet.length, 18,
        'packet length should match original payload length');

      for (var i = 0; i < packet.length; i++) {
        t.equal(packet[i], 1, 'Packet byte ' + i + ' should be 1');
      }
    });

    this.stream.end(this.payload);
  },

  testMacError: function(t) {
    t.expect(1);
    this.stream.on('end', t.done);
    this.stream.on('error', t.ok);
    this.stream.once('readable', this.stream.read);

    this.payload[this.payload.length - 1] += 1;
    this.stream.end(this.payload);
  },

  testReadingPartialPacket: function(t) {
    var self = this;

    t.expect(19);
    this.stream.on('end', t.done);
    this.stream.on('error', t.ifError);
    this.stream.once('readable', function() {
      var packet = self.stream.read();
      t.equal(packet.length, 18,
        'packet length should match original payload length');

      for (var i = 0; i < packet.length; i++) {
        t.equal(packet[i], 1, 'Packet byte ' + i + ' should be 1');
      }
    });

    this.stream.write(this.payload.slice(0, 2));
    this.stream.write(this.payload.slice(2, 3));
    this.stream.write(this.payload.slice(3, 5));
    this.stream.end(this.payload.slice(5));
  },

  testReadingMultiplePackets: function(t) {
    var self = this;
    var count = 0;

    t.expect(39);
    this.stream.on('end', function A() {
      t.equal(count, 2, 'should read 2 total packets');
      t.done();
    });
    this.stream.on('error', t.ifError);
    this.stream.on('readable', function B() {
      count++;
      var packet = self.stream.read();
      t.equal(packet.length, 18,
        'packet length should match original payload length');

      for (var i = 0; i < packet.length; i++) {
        t.equal(packet[i], 1, 'Packet byte ' + i + ' should be 1');
      }
    });

    var dblmsg = Buffer.concat([this.payload, this.payload]);
    new Buffer([
      0x29, 0x68, 0x2b, 0x2a, 0x4e,
      0x72, 0x13, 0x22, 0x1b, 0xbf,
      0xb4, 0x9c, 0xa2, 0x5a, 0xc0,
      0x6f, 0xaa, 0x30, 0x88, 0xb0
    ]).copy(dblmsg, 84);
    this.stream.end(dblmsg);
  }
};

exports.crypto = {
  setUp: function(cb) {
    this.stream = new SshInputStream();
    this.payload = new Buffer(32);
    this.payload.writeUInt32BE(28, 0);
    this.payload.writeUInt8(9, 4);
    this.payload.fill(1, 5, 23);
    this.payload.fill(8, 23);
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
    this.payload = this.cipher.update(this.payload);
    cb();
  },

  testSettingCipher: function(t) {
    t.equal(this.stream._cipher, null, 'should start with no cipher');
    t.equal(this.stream._blocksRemaining, (Math.pow(1024, 3) / 8),
      'default blocks remaining should be 1 GiB / 8');

    this.stream.setCipher(this.decipher, this.cipherBlockSize);
    t.equal(this.stream._cipher, this.decipher,
      'sane arguments should be honored');
    t.equal(this.stream._blocksRemaining,
      Math.pow(2, (this.cipherBlockSize * 2)),
      'sane arguments should set blocksRemaining to 2**(L/4)');

    this.stream.setCipher('garbage', 19);
    t.equal(this.stream._cipher, this.decipher,
      'insane arguments should be ignored');
    t.equal(this.stream._blocksRemaining,
      Math.pow(2, (this.cipherBlockSize * 2)),
      'insane arguments should not reset blocksRemaining');

    this.stream.setCipher();
    t.equal(this.stream._cipher, null,
      'calling with no arguments should clear cipher');
    t.equal(this.stream._blocksRemaining, (Math.pow(1024, 3) / 8),
      'calling with no arguments should reset blocks remaining to 1 GiB / 8');
    t.done();
  },

  testEncryption: function(t) {
    var self = this;

    t.expect(1);
    this.stream.on('end', t.done);
    this.stream.on('readable', function() {
      var expectedPayload = new Buffer(18);
      expectedPayload.fill(1);

      var packet = self.stream.read();
      t.equal(packet.toString('binary'), expectedPayload.toString('binary'),
        'deciphered packet should reveal payload');
    });

    this.stream.setCipher(this.decipher, this.cipherBlockSize);
    this.stream.end(this.payload);
  },

  testUnevenChunks: function(t) {
    var self = this;

    t.expect(1);
    this.stream.on('end', t.done);
    this.stream.on('readable', function() {
      var expectedPayload = new Buffer(18);
      expectedPayload.fill(1);

      t.equal(self.stream.read().toString('binary'),
        expectedPayload.toString('binary'),
        'deciphered packet should reveal payload');
    });

    this.stream.setCipher(this.decipher, this.cipherBlockSize);
    this.stream.write(this.payload.slice(0, 16));
    this.stream.write(this.payload.slice(16, 19));
    this.stream.write(this.payload.slice(19, 30));
    this.stream.end(this.payload.slice(30));
  }
};

exports.rekeying = {
  setUp: function(cb) {

    this.stream = new SshInputStream();
    this.payload = new Buffer(52);
    this.payload.writeUInt32BE(28, 0);
    this.payload.writeUInt8(9, 4);
    this.payload.fill(1, 5, 23);
    this.payload.fill(8, 23);
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
    this.payload = this.cipher.update(this.payload);
    this.macAlgorithm = 'sha1';
    this.macKey = new Buffer('my hmac secret key!!');
    new Buffer([
      0xca, 0xfd, 0x0c, 0xb7, 0x2e,
      0x6a, 0xcb, 0x5a, 0xb9, 0x5d,
      0x94, 0xfe, 0xb9, 0x80, 0x07,
      0x30, 0x0e, 0x08, 0x7e, 0xe4
    ]).copy(this.payload, 32);
    cb();
  },

  testMaxPackets: function(t) {
    this.stream.on('rekey_needed', t.done);
    this.stream.on('readable', this.stream.read);

    this.stream.setMac(this.macAlgorithm, this.macKey);
    this.stream.setCipher(this.decipher, this.cipherBlockSize);
    this.stream._packetsRemaining = 1;

    this.stream.end(this.payload);
  },

  testMaxXferBytes: function(t) {
    this.stream.on('rekey_needed', t.done);
    this.stream.on('readable', this.stream.read);

    this.stream.setMac(this.macAlgorithm, this.macKey);
    this.stream.setCipher(this.decipher, this.cipherBlockSize);
    this.stream._blocksRemaining = 1;

    this.stream.end(this.payload);
  }
};
