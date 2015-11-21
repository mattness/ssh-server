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
var messages = require('./messages');

util.inherits(Protocol, EventEmitter);

function _run() {
  // First things first, identify ourselves
  var identMsg = messages.createServerIdent(this._swversion,
    this._identComment);
  this._serverIdent = identMsg.toString();
  this._logger.log('tx: ', this._serverIdent.trim());
  this._socket.write(identMsg);
  this._writeStream.pipe(this._socket);

  // Then wait for the client's identification to arrive
  this._socket.once('readable', _handleClientIdent.bind(this));

  // Generate the cookie needed to initialize key exchange
  crypto.randomBytes(messages.KEXINIT_COOKIE_SIZE, _cookieReady.bind(this));
}

function _handleClientIdent() {
  var ident = this._socket.read();
  // Get the index of the first carriage return
  for (var i = 0; i < ident.length; i++) {
    if (ident[i] === 0xa) break;
  }

  // Client ident is everything up to and including the first CRLF
  this._clientIdent = ident.slice(0, i + 1).toString();
  this._logger.log('rx: ', this._clientIdent.trim());

  // Any extra data that arrived in the same chunk as the ident
  // should be sliced off and sent along to the SshInputStream
  this._readStream.write(ident.slice(i + 1));

  // All future data that arrives on the socket should get piped through
  // the SshInputStream
  this._socket.pipe(this._readStream);
}

function _cookieReady(err, cookie) {
  if (err) return this._socket.destroy();

  // Use the cookie to build the key exchange init message
  var kexInit = messages.createKexInit(cookie, this._opts);

  // And send it to the client
  this._logger.log('tx: ', kexInit.readUInt8(0));
  this._writeStream.write(kexInit);
}

function Protocol(opts, socket) {
  if (!(this instanceof Protocol))
    return new Protocol(opts);

  this._opts = opts;
  this._swversion = opts.softwareVersion;
  this._identComment = opts.identComment;
  this._logger = opts.logger;
  this._socket = socket;
  this._readStream = new SshReadableStream();
  this._writeStream = new SshWritableStream();

  this._serverIdent = '';
  this._clientIdent = '';

  this._readStream.on('readable', function ProtocolA() {
    var msg = this._readStream.read();
    var id = msg.readUInt8(0);

    this._logger.log('rx: ', id);
  }.bind(this));

  process.nextTick(_run.bind(this));
}
