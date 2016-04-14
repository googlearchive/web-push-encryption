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
const encrypt = require('./encrypt');

const GCM_URL = 'https://android.googleapis.com/gcm/send';
const TEMP_GCM_URL = 'https://gcm-http.googleapis.com/gcm';

/**
 * URL safe Base64 encoder
 *
 * @private
 * @param  {Buffer} buffer The data to encode
 * @return {String} URL safe base 64 encoded string
 */
function ub64(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/\=/g, '');
}

/**
 * Sends a message using the Web Push protocol
 *
 * @memberof web-push-encryption
 * @param  {String}   message      The message to send
 * @param  {Object}   subscription The subscription details for the client we
 *                                 are sending to
 * @param  {String}   authToken    Optional token to be used in the
 *                                 `Authentication` header if the endpoint
 *                                 requires it.
 * @return {Promise} A promise that resolves if the push was sent successfully
 *                   with status and body.
 */
function sendWebPush(message, subscription, authToken) {
  if (!subscription || !subscription.endpoint) {
    throw new Error('sendWebPush() expects a subscription endpoint with ' +
      'an endpoint parameter.');
  }

  // If the endpoint is GCM then we temporarily need to rewrite it, as not all
  // GCM servers support the Web Push protocol. This should go away in the
  // future.
  const endpoint = subscription.endpoint.replace(GCM_URL, TEMP_GCM_URL);

  const payload = encrypt(message, subscription);
  const headers = {
    'Content-Encoding': 'aesgcm',
    'Encryption': `salt=${ub64(payload.salt)}`,
    'Crypto-Key': `dh=${ub64(payload.serverPublicKey)}`
  };

  if (authToken) {
    headers.Authorization = `key=${authToken}`;
  } else if (endpoint.indexOf(TEMP_GCM_URL) !== -1) {
    throw new Error('GCM requires an Auth Token parameter');
  }

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

module.exports = sendWebPush;
