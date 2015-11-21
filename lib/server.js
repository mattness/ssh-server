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

module.exports = createServer;

var Session = require('./transportProtocol');
var pkginfo = require('../package.json');
var defaults = {
  softwareVersion: 'SshServerJS_' + pkginfo.version,
  kexAlgorithms: [
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group-exchange-sha1',
    'diffie-hellman-group1-sha1',
    'diffie-hellman-group14-sha1'
  ],
  serverKeyAlgorithms: ['ssh-dss'],
  clientEncryptionAlgorithms: ['3des-cbc'],
  serverEncryptionAlgorithms: ['3des-cbc'],
  clientMacAlgorithms: ['hmac-sha1'],
  serverMacAlgorithms: ['hmac-sha1'],
  clientCompressionAlgorithms: ['zlib','none'],
  serverCompressionAlgorithms: ['zlib','none'],
  clientLanguages: [],
  serverLanguages: [],
  logger: console
};

function createServer(options) {
  var opts = options || defaults;
  function connectionHandler(socket) {
    var session = new Session(opts, socket);
  }

  return connectionHandler;
}
