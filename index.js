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
  softwareVersion: 'ssh_server_' + pkginfo.version
};

function createServer(options) {
  var opts = options || defaults;

  function connectionHandler(socket) {
    var self = this;
    this.protocol = new Protocol();

    socket.on('readable', function B() {
      var ident = socket.read();
      for (var i = 0; i < ident.length; i++) {
        if (ident[i] === 0xa) break;
      }
      console.log('socket: ', ident.slice(0, i + 1).toString());
      self.protocol.istream.write(ident.slice(i + 1));
      socket.pipe(self.protocol.istream);
    });

    this.protocol.istream.on('readable', function A() {
      console.log('read: ', self.protocol.istream.read().toString());
    });

    var o = this.protocol.ostream;
    this.protocol.ostream = socket;
    this.protocol.writeVersion(opts.softwareVersion, opts.identComment);

    this.protocol.ostream = o;
    this.protocol.ostream.pipe(socket);
  }

  return connectionHandler;
}
