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
  }
};
