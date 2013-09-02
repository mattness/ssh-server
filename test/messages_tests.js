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

var lib = require('../lib/messages.js');

exports.testInterface = function(t) {
  t.equals(typeof lib, 'object', 'library exports an object');

  // Message creation functions
  t.equal(typeof lib.createServerIdent, 'function',
    'should have a createServerIdent function');
  t.equal(typeof lib.createKexInit, 'function',
    'should have a createKexInit function');
  t.done();
};

exports.serverIdentCreation = {
  setUp: function(cb) {
    this.swVersion = 'SWVER';
    this.comment = 'COMMENT';
    cb();
  },

  throwsWithNoSwVersion: function(t) {
    t.throws(lib.createServerIdent);
    t.done();
  },

  testWithArguments: function(t) {
    t.equals(lib.createServerIdent(this.swVersion, this.comment).toString(),
      'SSH-2.0-SWVER COMMENT\r\n',
      'version string should be \'SSH-2.0-SWVER COMMENT\\r\\n\'');
    t.done();
  },

  testWithoutComment: function(t) {
    t.equals(lib.createServerIdent(this.swVersion).toString(),
      'SSH-2.0-SWVER\r\n',
      'version string should be \'SSH-2.0-SWVER\\r\\n\'');
    t.done();
  },

  testWithEmptyComment: function(t) {
    t.equals(lib.createServerIdent(this.swVersion, '').toString(),
      'SSH-2.0-SWVER\r\n',
      'version string should be \'SSH-2.0-SWVER\\r\\n\'');
    t.done();
  }
};

exports.kexInitCreation = {
  setUp: function(cb) {
    cb();
  },

  testArguments: function(t) {
    t.throws(lib.createKexInit, 'cookie is a required argument');
    t.done();
  }
};
