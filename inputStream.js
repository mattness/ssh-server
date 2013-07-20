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

util.inherits(SshInputStream, Transform);
SshInputStream.prototype._transform = _transform;

var PACKET_LENGTH_FIELD_SIZE = 4;
var HEADER_SIZE = PACKET_LENGTH_FIELD_SIZE + 1;  // packet length + 1 byte padding length

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

    var packetLength = chunk.readUInt32BE(0);

    // If the packet length is greater than what's left in the chunk, queue it
    if (packetLength > (chunk.length - PACKET_LENGTH_FIELD_SIZE)) {
      this._packetInProgress = true;
      this._bytesPending = packetLength - chunk.length -
        PACKET_LENGTH_FIELD_SIZE;
      this._pendingChunks.push(chunk);
      break;
    }

    // Otherwise, parse it and push it down the pipe.
    var paddingLength = chunk.readUInt8(PACKET_LENGTH_FIELD_SIZE);
    var endOffset = chunk.length - packetLength - PACKET_LENGTH_FIELD_SIZE;
    var payloadEnd = chunk.length - (endOffset + paddingLength);
    var payload = chunk.slice(HEADER_SIZE, payloadEnd);

    this.push(payload);

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

function SshInputStream() {
  if (!(this instanceof SshInputStream))
    return new SshInputStream();

  this._packetInProgress = false;
  this._bytesPending = 0;
  this._pendingChunks = [];
  Transform.call(this);
}
