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
var Protocol = require('../protocol');

exports.setUp = function(cb) {
  this.proto = new Protocol();
  cb();
};

exports.publicApi = {

  exposesStartMethod: function(t) {
    t.equal(typeof this.proto.start, 'function', 'start is a function');
    t.done();
  }

};

exports.writeVersionMethod = {

  writesCorrectVersionString: function(t) {
    var swversion = 'MySSHServer_1.0.0';
    var stream = new PassThrough();

    stream.on('readable', function() {
      t.equal(stream.read().toString(), 'SSH-2.0-MySSHServer_1.0.0\r\n',
        'written version should be SSH-2.0-MySSHServer_1.0.0\r\n');
      stream.end();
      t.done();
    });

    this.proto.ostream = stream;
    this.proto.writeVersion(swversion);
  },

  writesCorrectVersionWithComment: function(t) {
    var swversion = 'MySSHServer_1.0.0';
    var comment = 'Stable';
    var stream = new PassThrough();

    stream.on('readable', function() {
      t.equal(stream.read().toString(), 'SSH-2.0-MySSHServer_1.0.0 Stable\r\n',
        'written version should be SSH-2.0-MySSHServer_1.0.0 Stable\r\n');
      stream.end();
      t.done();
    });

    this.proto.ostream = stream;
    this.proto.writeVersion(swversion, comment);
  },

  errorsOnNonPrintableCharacters: function(t) {
    this.proto.on('error', function(err) {
      t.ok(err, 'error event should be emitted');
    });
    this.proto.writeVersion('My\tSSHServer', function(err) {
      t.ok(err, 'err is truthy');
      t.done();
    });
  }

};
