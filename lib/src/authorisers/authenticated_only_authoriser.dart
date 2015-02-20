// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.authenticatedonly;

import 'package:shelf/shelf.dart';
import 'dart:async';
import '../authorisation.dart';
import 'package:option/option.dart';
import 'package:logging/logging.dart';
import '../authentication.dart';

Logger _log = new Logger('shelf_auth.authorisation.authenticatedonly');

/// An [Authoriser] that denies access to unauthenticated requests
class AuthenticatedOnlyAuthoriser implements Authoriser {
  Future<bool> isAuthorised(Request request) =>
      new Future.value(_isAuthorised(request));

  bool _isAuthorised(Request request) =>
      getAuthenticatedContext(request) is Some;
}
