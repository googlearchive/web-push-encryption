/**
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

require('chai').should();
const expect = require('chai').expect;
const proxyquire = require('proxyquire');
const sinon = require('sinon');

const EXAMPLE_SERVER_KEYS = {
  public: 'BOg5KfYiBdDDRF12Ri17y3v+POPr8X0nVP2jDjowPVI/DMKU1aQ3OLdPH1iaakvR9/PHq6tNCzJH35v/JUz2crY=',
  private: 'uDNsfsz91y2ywQeOHljVoiUg3j5RGrDVAswRqjP3v90='
};
const EXAMPLE_SALT = 'AAAAAAAAAAAAAAAAAAAAAA==';

const EXAMPLE_INPUT = 'Hello, World.';
const EXAMPLE_OUTPUT = 'CE2OS6BxfXsC2YbTdfkeWLlt4AKWbHZ3Fe53n5/4Yg==';

const VALID_SUBSCRIPTION = {
  endpoint: 'https://example-endpoint.com/example/1234',
  keys: {
    auth: '8eDyX_uCN0XRhSbY5hs7Hg==',
    p256dh: 'BCIWgsnyXDv1VkhqL2P7YRBvdeuDnlwAPT2guNhdIoW3IP7GmHh1SMKPLxRf7x8vJy6ZFK3ol2ohgn_-0yP7QQA='
  }
};

const INVALID_AUTH_SUBSCRIPTION = {
  endpoint: 'https://example-endpoint.com/example/1234',
  keys: {
    auth: 'uCN0XRhSbY5hs7Hg==',
    p256dh: 'BCIWgsnyXDv1VkhqL2P7YRBvdeuDnlwAPT2guNhdIoW3IP7GmHh1SMKPLxRf7x8vJy6ZFK3ol2ohgn_-0yP7QQA='
  }
};

const INVALID_P256DH_SUBSCRIPTION = {
  endpoint: 'https://example-endpoint.com/example/1234',
  keys: {
    auth: '8eDyX_uCN0XRhSbY5hs7Hg==',
    p256dh: '6ZFK3ol2ohgn_-0yP7QQA='
  }
};

const SUBSCRIPTION_NO_KEYS = {
  endpoint: 'https://example-endpoint.com/example/1234'
};

const GCM_SUBSCRIPTION_EXAMPLE = {
  original: 'https://android.googleapis.com/gcm/send/AAAAAAAAAAA:AAA91AAAA2_A7AAAAAAAAAAAAAAAAAAAAAAAAAAA9AAAAA9AAA_AAAA8AAAAAA5-AAAAAA2AAAA_AAAAA4A51A_A3AAA1AAAAAAAAAAAAAAA3AAAAAAAAA6AA2AAAAAAAA80AAAAAA',
  webpush: 'https://gcm-http.googleapis.com/gcm/AAAAAAAAAAA:AAA91AAAA2_A7AAAAAAAAAAAAAAAAAAAAAAAAAAA9AAAAA9AAA_AAAA8AAAAAA5-AAAAAA2AAAA_AAAAA4A51A_A3AAA1AAAAAAAAAAAAAAA3AAAAAAAAA6AA2AAAAAAAA80AAAAAA'
};

const SALT_LENGTH = 16;
const SERVER_PUBLIC_KEY_LENGTH = 65;

let testStubs = [];

describe('Test the Libraries Top Level API', function() {
  const restoreStubs = () => {
    testStubs.forEach(stub => {
      stub.restore();
    });
    testStubs = [];
  };

  beforeEach(() => restoreStubs());

  after(() => restoreStubs());

  describe('Test encrypt() method', function() {
    it('should encrypt the message with a valid subscription', function() {
      const library = require('../src/index.js');
      const response = library.encrypt('Hello, World', VALID_SUBSCRIPTION);
      Buffer.isBuffer(response.ciphertext).should.equal(true);
      Buffer.isBuffer(response.salt).should.equal(true);
      response.salt.should.have.length(SALT_LENGTH);
      Buffer.isBuffer(response.serverPublicKey).should.equal(true);
      response.serverPublicKey.should.have.length(SERVER_PUBLIC_KEY_LENGTH);
    });

    it('should throw an error due to subscription with no keys being passed in', function() {
      const library = require('../src/index.js');
      expect(
        () => library.encrypt('Hello, World', SUBSCRIPTION_NO_KEYS)
      ).to.throw('Subscription has no encryption details');
    });

    it('should not throw an error when no endpoint is passed in', function() {
      const library = require('../src/index.js');
      let subscription = {
        keys: VALID_SUBSCRIPTION.keys
      };
      const response = library.encrypt('Hello, World', subscription);
      Buffer.isBuffer(response.ciphertext).should.equal(true);
      Buffer.isBuffer(response.salt).should.equal(true);
      response.salt.should.have.length(SALT_LENGTH);
      Buffer.isBuffer(response.serverPublicKey).should.equal(true);
      response.serverPublicKey.should.have.length(SERVER_PUBLIC_KEY_LENGTH);
    });

    it('should throw an error due to an invalid auth token', function() {
      const library = require('../src/index.js');
      expect(
        () => library.encrypt('Hello, World', INVALID_AUTH_SUBSCRIPTION)
      ).to.throw('Subscription\'s Auth token is not 16 bytes.');
    });

    it('should not throw an error when no auth token is passed in', function() {
      const library = require('../src/index.js');
      let subscription = {
        endpoint: VALID_SUBSCRIPTION.endpoint,
        keys: {
          p256dh: VALID_SUBSCRIPTION.keys.p256dh
        }
      };

      expect(
        () => library.encrypt('Hello, World', subscription)
      ).to.throw('Subscription is missing some encryption details');
    });

    it('should throw an error due to an invalid client public key', function() {
      const library = require('../src/index.js');
      expect(
        () => library.encrypt('Hello, World', INVALID_P256DH_SUBSCRIPTION)
      ).to.throw('Subscription\'s client key (p256dh) is invalid.');
    });

    it('should throw an error when no p256dh key is passed in', function() {
      const library = require('../src/index.js');
      let subscription = {
        endpoint: VALID_SUBSCRIPTION.endpoint,
        keys: {
          auth: VALID_SUBSCRIPTION.keys.auth
        }
      };

      expect(
        () => library.encrypt('Hello, World', subscription)
      ).to.throw('Subscription is missing some encryption details');
    });

    it('should return the correct encryption values', function() {
      let crypto = require('crypto');

      // This is for the salt
      let saltStub = sinon.stub(crypto, 'randomBytes');
      saltStub.withArgs(16).returns(new Buffer(EXAMPLE_SALT, 'base64'));
      testStubs.push(saltStub);

      // Server key generation
      const exampleECDH = crypto.createECDH('prime256v1');
      exampleECDH.generateKeys();
      exampleECDH.setPrivateKey(EXAMPLE_SERVER_KEYS.private, 'base64');
      exampleECDH.setPublicKey(EXAMPLE_SERVER_KEYS.public, 'base64');
      // Make this a NOOP
      exampleECDH.generateKeys = () => {
        return exampleECDH.getPublicKey();
      };
      let ecdhStub = sinon.stub(crypto, 'createECDH');
      ecdhStub.withArgs('prime256v1').returns(exampleECDH);
      testStubs.push(ecdhStub);

      const library = proxyquire('../src/index.js', {
        'crypto': crypto
      });

      const response = library.encrypt(EXAMPLE_INPUT, VALID_SUBSCRIPTION);
      Buffer.isBuffer(response.salt).should.equal(true);
      response.salt.should.have.length(SALT_LENGTH);
      response.salt.toString('base64').should.equal(EXAMPLE_SALT);

      Buffer.isBuffer(response.serverPublicKey).should.equal(true);
      response.serverPublicKey.should.have.length(SERVER_PUBLIC_KEY_LENGTH);
      response.serverPublicKey.toString('base64').should.equal(EXAMPLE_SERVER_KEYS.public);

      response.ciphertext.toString('base64').should.equal(EXAMPLE_OUTPUT);
    });

    it('should throw an error when the input is too large', function() {
      const library = require('../src/index.js');

      let largeInput = new Buffer(4081);
      largeInput.fill(0);

      expect(
        () => library.encrypt(largeInput.toString('utf8'), VALID_SUBSCRIPTION)
      ).to.throw('Payload is too large. The max number of bytes is 4078, input is 4081 bytes plus 0 bytes of padding.');

      largeInput = new Buffer(5000);
      largeInput.fill(0);

      expect(
        () => library.encrypt(largeInput.toString('utf8'), VALID_SUBSCRIPTION)
      ).to.throw('Payload is too large. The max number of bytes is 4078, input is 5000 bytes plus 0 bytes of padding.');

      expect(() => library.encrypt(EXAMPLE_INPUT, VALID_SUBSCRIPTION, 4080))
        .to.throw('Payload is too large. The max number of bytes is 4078, input is 13 bytes plus 4080 bytes of padding.')
    });
  });

  describe('Test sendWebPush() method', function() {
    it('should throw an error when no input provided', function() {
      const library = require('../src/index.js');

      expect(
        () => library.sendWebPush()
      ).to.throw('sendWebPush() expects a subscription endpoint with ' +
        'an endpoint parameter and a string send with the push message.');
    });

    it('should throw an error when the subscription object has no endpoint', function() {
      const library = require('../src/index.js');

      expect(
        () => library.sendWebPush({})
      ).to.throw('sendWebPush() expects a subscription endpoint with ' +
        'an endpoint parameter and a string send with the push message.');
    });

    it('should throw an error when a subscription is passed in with no payload data', function() {
      const library = require('../src/index.js');

      expect(
        () => library.sendWebPush({
          endpoint: 'http://fakendpoint'
        })
      ).to.throw('sendWebPush() expects a subscription endpoint with ' +
        'an endpoint parameter and a string send with the push message.');
    });

    it('should throw an error when a subscription is passed in with array as payload data', function() {
      const library = require('../src/index.js');

      expect(
        () => library.sendWebPush({
          endpoint: 'http://fakendpoint'
        }, [
          {
            hello: 'world'
          },
          'This is a test',
          Promise.resolve('Promise Resolve'),
          Promise.reject('Promise Reject')
        ])
      ).to.throw('sendWebPush() expects a subscription endpoint with ' +
        'an endpoint parameter and a string send with the push message.');
    });

    it('should throw an error when a subscription with no encryption details is passed in with string as payload data', function() {
      const library = require('../src/index.js');

      expect(
        () => library.sendWebPush({
          endpoint: 'http://fakendpoint'
        }, 'Hello, World!')
      ).to.throw('Subscription has no encryption details.');
    });

    it('should attempt a web push protocol request', function() {
      const requestReplacement = {
        post: (endpoint, data, cb) => {
          endpoint.should.equal(VALID_SUBSCRIPTION.endpoint);

          Buffer.isBuffer(data.body).should.equal(true);
          data.headers.Encryption.should.have.length(27);
          data.headers['Crypto-Key'].should.have.length(90);

          cb(
            null,
            {
              statusCode: 200,
              statusMessage: 'Status message'
            },
            'Response body'
          );
        }
      };
      const pushProxy = proxyquire('../src/push.js', {
        'request': requestReplacement
      });
      const library = proxyquire('../src/index.js', {
        './push': pushProxy
      });
      return library.sendWebPush(VALID_SUBSCRIPTION, 'Hello, World!')
      .then(response => {
        response.statusCode.should.equal(200);
        response.statusMessage.should.equal('Status message');
        response.body.should.equal('Response body');
      });
    });

    it('should attempt a web push protocol request for GCM', function() {
      const API_KEY = 'AAAA';
      const gcmSubscription = {
        endpoint: GCM_SUBSCRIPTION_EXAMPLE.original,
        keys: VALID_SUBSCRIPTION.keys
      };
      const requestReplacement = {
        post: (endpoint, data, cb) => {
          endpoint.should.equal(GCM_SUBSCRIPTION_EXAMPLE.webpush);

          Buffer.isBuffer(data.body).should.equal(true);
          data.headers.Encryption.should.have.length(27);
          data.headers['Crypto-Key'].should.have.length(90);
          data.headers.Authorization.should.equal('key=' + API_KEY);

          cb(
            null,
            {
              statusCode: 200,
              statusMessage: 'Status message'
            },
            'Response body'
          );
        }
      };

      const pushProxy = proxyquire('../src/push.js', {
        'request': requestReplacement
      });
      const library = proxyquire('../src/index.js', {
        './push': pushProxy
      });
      library.addAuthToken('https://android.googleapis.com/gcm/send', API_KEY);
      return library.sendWebPush(gcmSubscription, 'Hello, World!')
      .then(response => {
        response.statusCode.should.equal(200);
        response.statusMessage.should.equal('Status message');
        response.body.should.equal('Response body');
      });
    });

    it('should throw an error when not providing an AuthToken for a GCM subscription', function() {
      const gcmSubscription = {
        endpoint: GCM_SUBSCRIPTION_EXAMPLE.original,
        keys: VALID_SUBSCRIPTION.keys
      };

      const library = require('../src/index.js');
      expect(
        () => library.sendWebPush(gcmSubscription, 'Hello, World!')
      ).to.throw('GCM requires an Auth Token. Please add one using theaddAuthToken() method.');
    });

    it('should handle errors from request', function() {
      const EXAMPLE_ERROR = 'Example Error';

      const requestReplacement = {
        post: (endpoint, data, cb) => {
          endpoint.should.equal(VALID_SUBSCRIPTION.endpoint);

          Buffer.isBuffer(data.body).should.equal(true);
          data.headers.Encryption.should.have.length(27);
          data.headers['Crypto-Key'].should.have.length(90);

          cb(EXAMPLE_ERROR);
        }
      };
      const pushProxy = proxyquire('../src/push.js', {
        'request': requestReplacement
      });
      const library = proxyquire('../src/index.js', {
        './push': pushProxy
      });
      return library.sendWebPush(VALID_SUBSCRIPTION, 'Hello, World!')
      .then(() => {
        throw new Error('The promise was expected to reject.');
      })
      .catch(err => {
        err.should.equal(EXAMPLE_ERROR);
      });
    });
  });
});
