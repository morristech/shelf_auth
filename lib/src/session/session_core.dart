// Copyright (c) 2015, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.session;

import 'package:uuid/uuid.dart';

String defaultCreateSessionIdentifier() => new Uuid().v1();

///// encodes the session token in the response somewhere
//typedef Response SessionTokenResponseEncoder(Response response, String sessionToken);
//
//Response headerSessionTokenResponseEncoder(Response response, String sessionToken) {
//
//}
//
//Response metaTagSessionTokenResponseEncoder(Response response, String sessionToken) {
//
//}
