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
var fs = require('fs');
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
  this._serverKexInit = messages.createKexInit(cookie, this._opts);

  // And send it to the client
  this._logger.log('tx: ', this._serverKexInit.readUInt8(0));
  this._writeStream.write(this._serverKexInit);
  _negotiateAlgorithms.call(this);
  _doKeyExchange.call(this);
}

function _negotiateAlgorithms() {
  if (!this._serverKexInit || !this._clientKexInit) return;

  var kex = this._algorithms.kex = _findMatch(
    this._opts.kexAlgorithms,
    this._clientKexInit.kexAlgorithms);
  var hostKeyAlg = this._algorithms.hostKeyAlg = _findMatch(
    this._opts.serverKeyAlgorithms,
    this._clientKexInit.serverKeyAlgorithms);
  var inboundCrypto = this._algorithms.inboundCrypto = _findMatch(
    this._opts.clientEncryptionAlgorithms,
    this._clientKexInit.clientEncryptionAlgorithms);
  var outboundCrypto = this._algorithms.outboundCrypto = _findMatch(
    this._opts.serverEncryptionAlgorithms,
    this._clientKexInit.serverEncryptionAlgorithms);
  var inboundMac = this._algorithms.inboundMac = _findMatch(
    this._opts.clientMacAlgorithms,
    this._clientKexInit.clientMacAlgorithms);
  var outboundMac = this._algorithms.outboundMac = _findMatch(
    this._opts.serverMacAlgorithms,
    this._clientKexInit.serverMacAlgorithms);
  var inboundCompression = this._algorithms.inboundCompression = _findMatch(
    this._opts.clientCompressionAlgorithms,
    this._clientKexInit.clientCompressionAlgorithms);
  var outboundCompression = this._algorithms.outboundCompression = _findMatch(
    this._opts.serverCompressionAlgorithms,
    this._clientKexInit.serverCompressionAlgorithms);
  var inboundLanguage = this._algorithms.inboundLanguage = _findMatch(
    this._opts.clientLanguages,
    this._clientKexInit.clientLanguages);
  var outboundLanguage = this._algorithms.outboundLanguage = _findMatch(
    this._opts.serverLanguages,
    this._clientKexInit.serverLanguages);

  // TODO (mattness): Create Kex Protocol object and hook up events
  this._logger.log(':: Key Exchange Protocol: %s', kex);
  this._dh = new crypto.getDiffieHellman('modp2');
  this._dh.generateKeys();

  this._logger.log(':: Server Host Key Algorithm: %s', hostKeyAlg);
  this._hostKey = new Buffer(fs.readFileSync('rsa_host_key.pub').toString()
    .split(' ')[1], 'base64');
  this._hostPrivKey = fs.readFileSync('rsa_host_key').toString();

  this._logger.log(':: Crypto (Client -> Server) %s', inboundCrypto);
  this._logger.log(':: Crypto (Server -> Client) %s', outboundCrypto);
  this._logger.log(':: MAC (Client -> Server) %s', inboundMac);
  this._logger.log(':: MAC (Server -> Client) %s', outboundMac);
  this._logger.log(':: Compression (Client -> Server) %s', inboundCompression);
  this._logger.log(':: Compression (Server -> Client) %s', outboundCompression);
  this._logger.log(':: Language (Client -> Server) %s', inboundLanguage);
  this._logger.log(':: Language (Server -> Client) %s', outboundLanguage);
}

function _doKeyExchange() {
  if (!this._serverKexInit || !this._clientKexInit) return;
  if (!this._clientDhInit) return;

  // Get the exchange value
  var f = this._dh.getPublicKey();
  var K = this._secret = this._dh.computeSecret(this._clientDhInit);

  // Hash all the things
  var hashalg = crypto.createHash('sha1');
  var signalg = crypto.createSign('RSA-SHA1');

  hashalg
    .update(messages.buildString(this._clientIdent.trim()))
    .update(messages.buildString(this._serverIdent.trim()))
    .update(messages.buildString(this._clientKexInitRaw))
    .update(messages.buildString(this._serverKexInit))
    .update(messages.buildString(this._hostKey))
    .update(messages.buildMPInt(this._clientDhInit))
    .update(messages.buildMPInt(f))
    .update(messages.buildMPInt(K));

  var hash = this._exchangeHash = hashalg.digest();
  this._sessionId = this._sessionId || this._exchangeHash;

  signalg.write(hash);
  var signature = Buffer.concat([
    messages.buildString('ssh-rsa'),
    messages.buildString(signalg.sign(this._hostPrivKey))
  ]);

  // this._logger.log('dh V_C: ', messages.buildString(this._clientIdent.trim()).toString('hex'));
  // this._logger.log('dh V_S: ', messages.buildString(this._serverIdent.trim()).toString('hex'));
  // this._logger.log('dh I_C: ', messages.buildString(this._clientKexInitRaw).toString('hex'));
  // this._logger.log('dh I_S: ', messages.buildString(this._serverKexInit).toString('hex'));
  // this._logger.log('dh K_S: ', messages.buildString(this._hostKey).toString('hex'));
  // this._logger.log('dh e: ', messages.buildMPInt(this._clientDhInit).toString('hex'));
  // this._logger.log('dh f: ', messages.buildMPInt(f).toString('hex'));
  // this._logger.log('dh K: ', messages.buildMPInt(K).toString('hex'));
  // this._logger.log('dh H: ', hash.toString('hex'));
  // this._logger.log('dh s: ', signature.toString('hex'))

  // Create the DH_REPLY
  var msg = messages.createKexdhReply(this._hostKey, f, signature);
  this._logger.log('tx: ', msg.readUInt8(0));
  this._writeStream.write(msg);
}

function _findMatch(a, b) {
  for (var i = 0; i < a.length; i++) {
    if (b.indexOf(a[i]) > -1) {
      return a[i];
    }
  }
}

function _handleNewKeys() {
  var decipherKey = _generateKey.call(this, 'C');
  var decipherIV = _generateKey.call(this, 'A');
  var inboundMacKey = _generateKey.call(this, 'E');
  var cipherKey = _generateKey.call(this, 'D');
  var cipherIV = _generateKey.call(this, 'B');
  var outboundMacKey = _generateKey.call(this, 'F');

  var decipher = crypto.createDecipheriv('aes-128-ctr',
    decipherKey.slice(0,16), decipherIV.slice(0,16));
  this._readStream.setCipher(decipher, 16);
  this._readStream.setMac('sha1', inboundMacKey);

  this._writeStream.write(messages.createNewKeys());
  var cipher = crypto.createCipheriv('aes-128-ctr',
    cipherKey.slice(0,16), cipherIV.slice(0,16));
  this._writeStream.setCipher(cipher, 16);
  this._writeStream.setMac('sha1', outboundMacKey);
}

function _generateKey(salt) {
  var hashalg = crypto.createHash('sha1');
  hashalg.update(messages.buildMPInt(this._secret))
    .update(this._exchangeHash)
    .update(new Buffer(salt, 'ascii'))
    .update(this._exchangeHash);
  return hashalg.digest();
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
  this._serverKexInit = null;
  this._clientKexInit = null;
  this._secret = null;
  this._exchangeHash = null;
  this._algorithms = {};

  this._readStream.on('readable', function ProtocolA() {
    var msg = this._readStream.read();
    if (!msg) return;

    var id = msg.readUInt8(0);
    this._logger.log('rx: ', id);

    switch(id) {
      case 20:
        this._clientKexInitRaw = msg;
        this._clientKexInit = messages.parseKexInit(msg);
        _negotiateAlgorithms.call(this);
        break;

      case 21: // SSH_MSG_NEWKEYS
        _handleNewKeys.call(this);
        break;

      case 30:
        this._clientDhInit = messages.parseKexdhInit(msg);
        _doKeyExchange.call(this);
        break;
    }
  }.bind(this));

  process.nextTick(_run.bind(this));
}
