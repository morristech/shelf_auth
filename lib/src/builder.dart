// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.builder;

import 'package:shelf/shelf.dart';
import 'package:logging/logging.dart';
import 'authentication.dart';
import 'core.dart';
import 'authenticators/basic_auth.dart';
import 'principal/user_lookup.dart';

export 'core.dart';


final Logger _log = new Logger('shelf_auth.builder');

/// A builder to help with the creation of shelf_auth middleware
class AuthenticationBuilder {
  List <Authenticator> _authenticators = [];
  SessionHandler _sessionHandler;
  bool allowHttp = false;
  bool allowAnonymousAccess = true;

  AuthenticationBuilder basic(UserLookupByUsernamePassword userLookup) =>
      authenticator(new BasicAuthenticator(userLookup));

  AuthenticationBuilder authenticator(Authenticator authenticator) {
    _authenticators.add(authenticator);
    return this;
  }

  AuthenticationBuilder sessionHandler(SessionHandler sessionHandler) {
    _sessionHandler = sessionHandler;
    return this;
  }

  Middleware build() => authenticate(_authenticators,
      sessionHandler: _sessionHandler, allowHttp: allowHttp,
      allowAnonymousAccess: allowAnonymousAccess);

}
