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

module.exports = SshInputStream;

var Transform = require('stream').Transform;
var util = require('util');
var crypto = require('crypto');

util.inherits(SshInputStream, Transform);
SshInputStream.prototype._transform = _transform;
SshInputStream.prototype.setMac = _setMac;
SshInputStream.prototype.setCipher = _setCipher;

var PACKET_LENGTH_FIELD_SIZE = 4;
var HEADER_SIZE = PACKET_LENGTH_FIELD_SIZE + 1;  // packet length + 1 byte padding length
var MAX_MAC_PACKETS = Math.pow(2, 31); // RFC 4344, Section 3.1 (First Rekeying)
var MAX_SEQUENCE_NUMBER = Math.pow(2, 32);
var MAX_KEY_BLOCKS = (Math.pow(1024, 3) / 8); // RFC 4344, Section 3.2 (Second Rekeying)

function _transform(chunk, encoding, done) {
  if (this._packetInProgress && !this._bytesPending) {
    // If we don't have enough data yet to read the packet length, combine
    // the pendingChunks with this one
    chunk = Buffer.concat(this._pendingChunks.concat(chunk));

    // Clear the pending list, we'll re-push the combined chunk if needed
    clearPending.call(this);
  }

  while (chunk.length > 0) {
    // If we're waiting for more data, and this chunk has it, combine all the
    // pending chunks and continue.  Otherwise, add it to the pending list
    if (this._packetInProgress) {
      if(this._bytesPending - chunk.length <= 0) {
        chunk = Buffer.concat(this._pendingChunks.concat(chunk));
        clearPending.call(this);
      } else {
        this._bytesPending -= chunk.length;
        this._pendingChunks.push(chunk);
        break;
      }
    }

    // If we don't have enough data to get the packet length, queue the chunk
    if (chunk.length < PACKET_LENGTH_FIELD_SIZE) {
      this._packetInProgress = true;
      this._bytesPending = 0;  // Not enough data to get the packet length
      this._pendingChunks.push(chunk);
      break;
    }

    if(this._cipher && this._bytesDecrypted === 0) {
      // Decrypt the packet length part of the buffer, and replace those
      // bytes in the buffer with the plaintext bytes
      this._cipher.update(chunk.slice(0, PACKET_LENGTH_FIELD_SIZE)).copy(
        chunk, 0);
      this._bytesDecrypted = PACKET_LENGTH_FIELD_SIZE;
    }

    var packetLength = chunk.readUInt32BE(0);
    var expectedLength = packetLength + this._macLength;
    var encryptedLength = PACKET_LENGTH_FIELD_SIZE + packetLength;

    // If the packet length is greater than what's left in the chunk, queue it
    if (expectedLength > (chunk.length - PACKET_LENGTH_FIELD_SIZE)) {
      this._packetInProgress = true;
      this._bytesPending = expectedLength - chunk.length -
        PACKET_LENGTH_FIELD_SIZE;
      this._pendingChunks.push(chunk);
      break;
    }

    // We've got the whole packet now, decrypt the rest of it
    if (this._cipher) {
      if (this._bytesDecrypted < encryptedLength) {
        chunk = Buffer.concat([
          chunk.slice(0, this._bytesDecrypted),
          this._cipher.update(chunk.slice(this._bytesDecrypted,
            encryptedLength)),
          // Don't forget to save the MAC if it's there
          chunk.slice(encryptedLength)
        ]);
      }

      // Reset _bytesDecrypted for the next packet
      this._bytesDecrypted = 0;
      this._blocksRemaining -= (encryptedLength / this._cipherBlockSize);
    }

    // Parse it and push it down the pipe.
    if (this._macAlgorithm) {
      var macIdx = encryptedLength; // MAC starts where crypto ends, macIdx is
                                    // just to help readability
      var mac = chunk.slice(macIdx, macIdx + this._macLength);
      var packet = chunk.slice(0, macIdx);
      var seqNumBuffer = new Buffer(4);
      seqNumBuffer.writeUInt32BE(this._sequence, 0);
      var hmac = crypto.createHmac(this._macAlgorithm, this._macKey);
      hmac.update(Buffer.concat([seqNumBuffer, packet]));
      this._packetsRemaining -= 1;

      if (mac.toString('binary') != hmac.digest().toString('binary')) {
        this.emit('error', new Error('Message Integrity Failure'));
        done();
        return;
      }

      chunk = Buffer.concat([
        packet, // current packet
        chunk.slice(macIdx + this._macLength) // whatever's after the MAC
      ]);
    }

    var paddingLength = chunk.readUInt8(PACKET_LENGTH_FIELD_SIZE);
    var endOffset = chunk.length - packetLength - PACKET_LENGTH_FIELD_SIZE;
    var payloadEnd = chunk.length - (endOffset + paddingLength);
    var payload = chunk.slice(HEADER_SIZE, payloadEnd);

    this.push(payload);
    this._sequence = ++this._sequence % MAX_SEQUENCE_NUMBER;

    if (this._packetsRemaining === 0 || this._blocksRemaining <= 0) {
      this.emit('rekey_needed');
    }

    // slice of what's left of the chunk, and make another pass
    chunk = chunk.slice(PACKET_LENGTH_FIELD_SIZE + packetLength);
  }

  done();
}

function clearPending() {
  this._packetInProgress = false;
  this._pendingChunks.length = 0;
  this._bytesPending = 0;
}

function _setMac(algorithm, key, digestLength) {
  if (!algorithm) {
    this._macAlgorithm = null;
    this._macKey = null;
    this._macLength = 0;
  } else {
    this._macAlgorithm = algorithm;
    this._macKey = key;
    if (!!digestLength) {
      this._macLength = digestLength;
    } else {
      this._macLength = crypto.createHmac(algorithm, key).digest().length;
    }
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

  if (cipher instanceof crypto.Decipheriv) {
    this._cipher = cipher;
    this._cipherBlockSize = blockSize;

    // RFC 4344, Section 3.2 (Second Rekeying Recommendation)
    var blockBits = blockSize * 8;
    this._blocksRemaining = blockBits < 128 ? MAX_KEY_BLOCKS :
      Math.pow(2, (blockBits / 4));
  }
}

function SshInputStream() {
  if (!(this instanceof SshInputStream))
    return new SshInputStream();

  // Encryption
  this._cipher = null;
  this._cipherBlockSize = 0;
  this._bytesDecrypted = 0;

  // Message Authentication
  this._sequence = 0;
  this._macAlgorithm = null;
  this._macKey = null;
  this._macLength = 0;

  // Rekey Tracking
  this._packetsRemaining = MAX_MAC_PACKETS;
  this._blocksRemaining = MAX_KEY_BLOCKS;

  this._packetInProgress = false;
  this._bytesPending = 0;
  this._pendingChunks = [];

  Transform.call(this);
}
