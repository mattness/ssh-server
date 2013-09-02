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

module.exports = {
  createServerIdent: _createServerIdent
};

var util = require('util');

function _createServerIdent(swVersion, comment) {
  var buf = new Buffer(255);

  // Write the string, but save room for the crlf, we enforce the 255 char
  // limit by simply truncating the comment (or swversion if there is no
  // comment)
  var offset = buf.write(
    util.format('SSH-2.0-%s%s', swVersion, comment ? ' ' + comment : ''),
    0, buf.length - 2
  );
  offset += buf.write('\r\n', offset, 2);

  if (offset < buf.length)
    buf = buf.slice(0, offset);

  return buf;
}
