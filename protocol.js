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

module.exports = Protocol;

var EventEmitter = require('events').EventEmitter;
var util = require('util');
var SshReadableStream = require('./inputStream');
var SshWritableStream = require('./outputStream');

util.inherits(Protocol, EventEmitter);
Protocol.prototype.write = _write;
Protocol.prototype.writeVersion = _writeVersion;

function _writeVersion(swversion, comment, cb) {
  if (typeof comment === 'function') {
    cb = comment;
    comment = undefined;
  }

  if (/[\x00-\x1F\x20\x2D\x7F-\xFF]/.test(swversion)) {
    var err = new Error(
      'Software Version must contain only printable US-ASCII characters ' +
      'and cannot include whitespace or minus sign (-)');
    this.emit('error', err);
    this.ostream.end();
    if (!!cb) cb(err);
    return;
  }

  var verbuf = new Buffer(255);
  // Write the string, but save room for the crlf, we enforce the 255 char
  // limit by simply truncating the comment (or swversion if there is no
  // comment)
  var offset = verbuf.write(
    util.format('SSH-2.0-%s%s', swversion, comment ? ' ' + comment : ''),
    0, verbuf.length - 2);
  offset += verbuf.write('\r\n', offset, 2);

  // Send everything up to and including the lf down the pipe.
  this.write(verbuf.slice(0, offset), cb);
}

function _write() {
  return this.ostream.write.apply(this.ostream, arguments);
}

function Protocol() {
  if (!(this instanceof Protocol))
    return new Protocol();

  this.istream = new SshReadableStream();
  this.ostream = new SshWritableStream();
}
