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

module.exports = SshOutputStream;

var Transform = require('stream').Transform;
var util = require('util');
var crypto = require('crypto');

util.inherits(SshOutputStream, Transform);
SshOutputStream.prototype._transform = _transform;
SshOutputStream.prototype.setMac = _setMac;
SshOutputStream.prototype.setCipher = _setCipher;

var MIN_PADDING_SIZE = 4;  // RFC 4253, Section 6 (random padding)
var MAX_PADDING_SIZE = 255; // RFC 4253, Section 6 (random padding)
var MAX_SEQUENCE_NUMBER = Math.pow(2, 32);
var HEADER_SIZE = 5;  // 4-byte packet_length + 1 byte padding length
var MAX_MAC_PACKETS = Math.pow(2, 31); // RFC 4344, Section 3.1 (First Rekeying)
var MAX_KEY_BLOCKS = (Math.pow(1024, 3) / 8); // RFC 4344, Section 3.2 (Second Rekeying)

function _transform(chunk, encoding, done) {
  var self = this;
  var macAlgorithm = this._macAlgorithm;
  var macKey = this._macKey;
  var cipher = this._cipher;

  // 1.  Figure out what the payload size is
  // TODO (mattness):  Support payload compression
  var payloadSize = chunk.length;

  // Figure out what the block size should be
  var blockSize = Math.max(this._cipherBlockSize, 8);

  // 2.  Figure out what the padding size should be
  var paddingSize = blockSize - ((HEADER_SIZE + payloadSize) % blockSize);

  // 3.  Make sure we have at least MIN_PADDING_SIZE bytes of padding
  while (paddingSize < MIN_PADDING_SIZE) {
    paddingSize += blockSize;
  }

  // 4.  Make sure we have no more than MAX_PADDING_SIZE bytes of padding
  if (paddingSize > MAX_PADDING_SIZE) {
    this.emit('error', new Error(
      util.format('Padding size (%d) exceeds RFC maximum (%d)', paddingSize,
        MAX_PADDING_SIZE)));
    done();
    return;
  }

  // Generate random bytes to use as padding
  crypto.randomBytes(paddingSize, function(err, padding) {
    if (err) {
      this.emit('error', err);
      done();
      return;
    }

    // Create a buffer big enough to hold everything
    // packet & padding lengths header + payloadSize + paddingSize
    var packet = new Buffer(HEADER_SIZE + payloadSize + paddingSize);

    // Write the packet length in the first 4 bytes
    // packet length is 1 byte for padding size value, plus size of
    // the payload plus size of the padding bytes
    packet.writeUInt32BE(1 + payloadSize + paddingSize, 0);

    // The next byte contains the size of the padding
    packet.writeUInt8(paddingSize, 4);

    // Then our payload
    chunk.copy(packet, HEADER_SIZE);

    // And our padding
    padding.copy(packet, HEADER_SIZE + payloadSize);

    // If we've negotiated a MAC algorithm, run it
    var mac;
    if (self._macAlgorithm) {
      var hmac = crypto.createHmac(macAlgorithm, macKey);
      var seqNumBuffer = new Buffer(4);
      seqNumBuffer.writeUInt32BE(self._sequence, 0);
      hmac.update(Buffer.concat([seqNumBuffer, packet]));
      mac = new Buffer(hmac.digest());
      hmac = null;  // unref so it can be gc'd asap
    }

    if (cipher) {
      self._blocksRemaining -= (packet.length / blockSize);
      packet = cipher.update(packet);
    }

    if (mac) {
      packet = Buffer.concat([packet, mac]);
      self._packetsRemaining -= 1;
    }

    // Finally, send the packet downstream
    self.push(packet);
    self._sequence = ++self._sequence % MAX_SEQUENCE_NUMBER;

    // If we've written enough data with these keys, let someone know that
    // it's time to rekey
    if (self._packetsRemaining === 0 || self._blocksRemaining <= 0) {
      // TODO (mattness): Probably need to buffer all writes while waiting
      self.emit('rekey_needed');
    }

    done();
  });
}

function _setMac(algorithm, key) {
  if (!algorithm) {
    this._macAlgorithm = null;
    this._macKey = null;
  } else {
    this._macAlgorithm = algorithm;
    this._macKey = key;
  }

  // RFC 4344, Section 3.1 (First Rekeying Recommendation)
  this._packetsRemaining = MAX_MAC_PACKETS;
}

function _setCipher(cipher, blockSize) {
  if (!cipher) {
    this._cipher = null;
    this._cipherBlockSize = 0;
    this._blocksRemaining = MAX_KEY_BLOCKS;
  }

  if (cipher instanceof crypto.Cipheriv) {
    this._cipher = cipher;
    this._cipherBlockSize = blockSize || 0;

    // RFC 4344, Section 3.2 (Second Rekeying Recommendation)
    var blockBits = blockSize * 8;
    this._blocksRemaining = blockBits < 128 ? MAX_KEY_BLOCKS :
      Math.pow(2, (blockBits / 4));
  }
}

function SshOutputStream() {
  if (!(this instanceof SshOutputStream))
    return new SshOutputStream();

  // Encryption
  this._cipher = null;
  this._cipherBlockSize = 0;

  // Message Authentication
  this._sequence = 0;
  this._macAlgorithm = null;
  this._macKey = null;

  // Rekey tracking
  this._packetsRemaining = MAX_MAC_PACKETS;
  this._blocksRemaining = MAX_KEY_BLOCKS;

  Transform.call(this);
}
