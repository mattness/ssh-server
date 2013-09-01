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
var crypto = require('crypto');
var SshReadableStream = require('./inputStream');
var SshWritableStream = require('./outputStream');
var KEXINIT_COOKIE_SIZE = 16;

util.inherits(Protocol, EventEmitter);
Protocol.prototype.start = _start;
Protocol.prototype.createKexInit = _createKexInit;

function _start(socket) {
  var self = this;
  this._socket = socket;

  _writeVersion.call(this);

  crypto.randomBytes(KEXINIT_COOKIE_SIZE, function(err, cookie) {
    if (err) return socket.destroy();
    // self._writeStream.write(_createKexInit(cookie));
  });

  this._socket.on('readable', function _handleClientIdent() {
    var ident = self._socket.read();
    for (var i = 0; i < ident.length; i++) {
      if (ident[i] === 0xa) break;
    }

    self._clientIdent = ident.slice(0, i + 1).toString();
    self._logger.log('rx: ', self._clientIdent);

    self._socket.removeListener('readable', _handleClientIdent);
    self._readStream.write(ident.slice(i + 1));
    self._socket.pipe(self._readStream);
  });

}

function _writeVersion() {
  var verbuf = new Buffer(255);
  // Write the string, but save room for the crlf, we enforce the 255 char
  // limit by simply truncating the comment (or swversion if there is no
  // comment)
  var offset = verbuf.write(
    util.format('SSH-2.0-%s%s', this._swversion,
      this._identComment ? ' ' + this._identComment : ''
    ), 0, verbuf.length - 2
  );
  offset += verbuf.write('\r\n', offset, 2);

  if (offset < verbuf.length)
    verbuf = verbuf.slice(0, offset);

  this._serverIdent = verbuf.toString();

  // Send everything up to and including the lf down the pipe.
  this._logger.log('tx: ', verbuf.toString());
  this._socket.write(verbuf);
  this._writeStream.pipe(this._socket);
}

function _createKexInit(cookie) {
  var msg = new Buffer();
}

function Protocol(opts) {
  if (!(this instanceof Protocol))
    return new Protocol(opts);

  this._swversion = opts.softwareVersion;
  this._identComment = opts.identComment;
  this._logger = opts.logger;
  this._readStream = new SshReadableStream();
  this._writeStream = new SshWritableStream();

  this._readStream.on('readable', function A() {
    this._logger.log('rx: ', this._readStream.read().toString());
  }.bind(this));

  this._serverIdent = '';
  this._clientIdent = '';
}
