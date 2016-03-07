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

const request = require('request');
const encrypt = require('./encrypt').encrypt;

const GCM_URL = 'https://android.googleapis.com/gcm/send';
const TEMP_GCM_URL = 'https://gcm-http.googleapis.com/gcm';

/**
 * URL safe Base64 encoder
 * @param  {Buffer} buffer The data to encode
 * @return {String} URL safe base 64 encoded string
 */
function ub64(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/\=/g, '');
}

/**
 * A helper for creating the value part of the HTTP encryption headers
 * @param  {String} name  The name of the header field
 * @param  {Buffer} value The value of the field
 * @return {String} String representation of the header
 */
function createHeaderField(name, value) {
  return `${name}=${ub64(value)}`;
}

const authTokens = [];

/**
 * Returns the appropriate authentication token, if any, for the endpoint we are
 * trying to send to.
 * @param  {String} endpoint URL of the endpoint
 * @return {String}          The authentication token
 */
function getAuthToken(endpoint) {
  for (let i = 0; i < authTokens.length; i++) {
    if (endpoint.indexOf(authTokens[i].pattern) !== -1) {
      return authTokens[i].token;
    }
  }
}

/**
 * Adds a new authentication token. The pattern is a simple string. An endpoint
 * will use the given authentication token if the pattern is a substring of the
 * endpoint.
 * @param {String} pattern The pattern to match on
 * @param {String} token   The authentication token
 */
function addAuthToken(pattern, token) {
  authTokens.push({pattern, token});
}

/**
 * Sends a message using the Web Push protocol
 * @param  {Object}   subscription The subscription details for the client we
 *                                 are sending to
 * @param  {String}   message      The message to send
 * @return {Promise} A promise that resolves if the push was sent successfully
 *                   with status and body.
 */
function sendWebPush(subscription, message) {
  if (
    !subscription || !subscription.endpoint ||
    !message || typeof message !== 'string') {
    throw new Error('sendWebPush() expects a subscription endpoint with ' +
      'an endpoint parameter and a string send with the push message.');
  }

  let endpoint = subscription.endpoint;
  const authToken = getAuthToken(endpoint);

  const payload = encrypt(message, subscription);
  const headers = {
    'Encryption': createHeaderField('salt', payload.salt),
    'Crypto-Key': createHeaderField('dh', payload.serverPublicKey)
  };

  if (authToken) {
    headers.Authorization = 'key=' + authToken;
  } else if (endpoint.indexOf(GCM_URL) !== -1) {
    throw new Error('GCM requires an Auth Token. Please add one using the' +
      'addAuthToken() method.');
  }

  // If the endpoint is GCM then we temporarily need to rewrite it, as not all
  // GCM servers support the Web Push protocol. This should go away in the
  // future.
  endpoint = endpoint.replace(GCM_URL, TEMP_GCM_URL);

  return new Promise(function(resolve, reject) {
    request.post(endpoint, {
      body: payload.ciphertext,
      headers: headers
    }, function(error, response, body) {
      if (error) {
        reject(error);
      } else {
        resolve({
          statusCode: response.statusCode,
          statusMessage: response.statusMessage,
          body: body
        });
      }
    });
  });
}

module.exports = {
  sendWebPush,
  addAuthToken,
  ub64,
  createHeaderField,
  getAuthToken
};
