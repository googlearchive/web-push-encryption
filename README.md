# DEPRECATION NOTICE

This library is now <strong>deprecated</strong> in favor of:
[web-push](https://github.com/web-push-libs/web-push)

### Migration from `web-push-encryption` to `web-push`

To move from this library to `web-push` perform the following steps:

Install the new module and delete `web-push-encryption` from your dependencies.

    npm install --save web-push

Swap the required module from `web-push-encryption` to `web-push` in your code.

    var webpush = require('web-push');

Replace the `sendWebPush(<Payload String or Buffer>, <PushSubscription Object>)` call with
the following:

    const params = {
      payload: <Payload String or Buffer>
    };
    if (subscription.keys) {
      params.userPublicKey = subscription.keys.p256dh;
      params.userAuth = subscription.keys.auth;
    }
    webpush.sendNotification(subscription.endpoint, params);

`setGCMAPIKey` is the same for both libraries, just make sure it's called
 before `sendNotificaiton`.

    webpush.setGCMAPIKey(MY_GCM_KEY);

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
