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

exports = module.exports = createServer;

var util = require('util');
var pkginfo = require('./package.json');
var Protocol = require('./protocol');
var defaults = {
  softwareVersion: 'SshServerJS_' + pkginfo.version,
  logger: console
};

function createServer(options) {
  var opts = options || defaults;

  if (/[\x00-\x1F\x20\x2D\x7F-\xFF]/.test(opts.softwareVersion)) {
    throw new Error(
      'Software Version must contain only printable US-ASCII characters ' +
      'and cannot include whitespace or minus sign (-)');
  }

  function connectionHandler(socket) {
    new Protocol(opts).start(socket);
  }

  return connectionHandler;
}
