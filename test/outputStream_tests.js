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
