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

let gcmAuthToken;

/**
 * Set the key to use in the Authentication header for GCM requests
 * @param {String} key The API key to use
 * @throws {Error} If the key is invalid
 */
function setGCMAPIKey(key) {
  if (!key.startsWith('AIza') || key.length !== 40) {
    throw new Error('expected Server API Key in the form AIza..., 40 characters long');
  }
  gcmAuthToken = key;
}

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
 * @param {Number}    paddingLength The number of bytes of padding to add to the
 *                                  message before encrypting it.
 * @return {Promise} A promise that resolves if the push was sent successfully
 *                   with status and body.
 */
function sendWebPush(message, subscription, paddingLength) {
  if (!subscription || !subscription.endpoint) {
    throw new Error('sendWebPush() expects a subscription endpoint with ' +
      'an endpoint parameter.');
  }

  // If the endpoint is GCM then we temporarily need to rewrite it, as not all
  // GCM servers support the Web Push protocol. This should go away in the
  // future.
  const endpoint = subscription.endpoint.replace(GCM_URL, TEMP_GCM_URL);
  const headers = {
    // TODO: Make TTL variable
    TTL: '0'
  };
  let body;

  if (message && message.length > 0) {
    const payload = encrypt(message, subscription, paddingLength);
    headers['Content-Encoding'] = 'aesgcm';
    headers.Encryption = `salt=${ub64(payload.salt)}`;
    headers['Crypto-Key'] = `dh=${ub64(payload.serverPublicKey)}`;
    body = payload.ciphertext;
  }

  if (endpoint.indexOf(TEMP_GCM_URL) !== -1) {
    if (gcmAuthToken) {
      headers.Authorization = `key=${gcmAuthToken}`;
    } else {
      throw new Error('GCM requires an Auth Token parameter');
    }
  }

  return new Promise(function(resolve, reject) {
    request.post(endpoint, {
      body: body,
      headers: headers
    }, function(error, response, body) {
      if (error) {
        reject(error);
      } else {
        if (response.statusCode >= 400 && response.statusCode < 500) {
          // Subscription is invalid:
          // https://tools.ietf.org/html/draft-ietf-webpush-protocol-04#section-8.3
          return reject({
            code: 'expired-subscription',
            statusCode: response.statusCode,
            statusMessage: response.statusMessage,
            body: body
          });
        }

        resolve({
          statusCode: response.statusCode,
          statusMessage: response.statusMessage,
          body: body
        });
      }
    });
  });
}

module.exports = {sendWebPush, setGCMAPIKey};
