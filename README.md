Push Encryption (node)
----------------------

[![Travis Build Status](https://travis-ci.org/GoogleChrome/push-encryption-node.svg?branch=master)](https://travis-ci.org/GoogleChrome/push-encryption-node)

[![Dependency Badge from David](https://david-dm.org/GoogleChrome/push-encryption-node.svg)](https://david-dm.org/GoogleChrome/push-encryption-node)

This library provides the functions necessary to encrypt a payload for sending
with the Web Push protocol. It also includes a helper function for actually
send the message to the Web Push endpoint.

What is this for?
-----------------

The [Push API](http://w3c.github.io/push-api/) allow users to subscribe for
notifications from a web site, which can be delivered to them even if the
browser has been closed. This was first shipped as part of Chrome 42, but the
push message could not contain any payload data.

As of Chrome 50 and Firefox 44 (desktop-only) payloads are supported, but the
server must encrypt the payload or the receiving browser will reject it.

This library implements the necessary encryption as a Node module.

Overview
--------

Install the module using npm:

`npm install web-push-encryption`

Require the module:

`const webpush = require('web-push-encryption');`

Send a message:

`webpush.sendWebPush('Yay! Web Push!', subscription);`

API
---

**sendWebPush**
`webpush.sendWebPush(message, subscription);`

Encrypts a message and sends it the the subscribed client using the Web Push
protocol. The subscription parameter is the serialised PushSubscription object
obtained from the client when susbscribing. One way to get this object in the
correct format is by calling `JSON.stringify(subscription)` and then
transmitting the resulting string to the server.

The message is a String, and will be the value of the `data` property of the
PushEvent that the client receives.

**addAuthToken**
`.addAuthToken(pattern, token)`

Some push providers (notably Google Cloud Messaging (GCM), used by Chrome's push
implementation) require an `Authentication:` token to be sent with push
requests. You can specify which tokens to send for which push providers. Both
`pattern` and `token` are Strings. When sending the message to the endpoint, the
endpoint is matched against each pattern that has been set. If any pattern is a
substring of the endpoint then the associated token will be sent in the request.

For example, to set the token for GCM you could use a pattern of
`https://android.googleapis.com/gcm`.

**encrypt**
`.encrypt(message, subscription)`

This method performs the neccessary encryption but does not actually send the
Web Push request. This allows you to use an alternative implementation of the
Web Push protocol. The output is an Object:

```javascript
{
  ciphertext: Buffer,
  salt: Buffer,
  serverPublicKey: Buffer
}
```

These are the raw values needed to construct the body (`ciphertext`),
`Encryption` header (`salt`) and `Crypto-Key` header (`serverPublicKey`). For
more details of the Web Push protocol, see
https://webpush-wg.github.io/webpush-encryption/

Support
-------

If you've found an error in this library, please file an issue:
https://github.com/GoogleChrome/push-encryption-node/issues

Patches are encouraged, and may be submitted by forking this project and
submitting a pull request through GitHub.

License
-------

Copyright 2016 Google, Inc.

Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements.  See the NOTICE file distributed with this work for
additional information regarding copyright ownership.  The ASF licenses this
file to you under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License.  You may obtain a copy of
the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
License for the specific language governing permissions and limitations under
the License.
